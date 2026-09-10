/**
 * correlationService.js — Automated Real-Time Incident Correlation Engine.
 *
 * Correlates streaming security findings by entity (IP, process name)
 * and MITRE ATT&CK techniques within a rolling time window.
 *
 * When related threats cluster (2+ findings or critical severity),
 * an Incident is automatically opened or updated, linking constituent Threat IDs.
 */
import Incident, { SEVERITY_ORDER } from '../models/Incident.js';
import Threat from '../models/Threat.js';
import User from '../models/User.js';

const DEFAULT_WINDOW_MS  = 15 * 60 * 1000; // 15 minutes
const DEFAULT_MIN_THRESHOLD = 2;

const SEVERITY_WEIGHT = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Returns whichever severity is higher according to SOC hierarchy.
 */
function getHigherSeverity(sevA, sevB) {
  const weightA = SEVERITY_WEIGHT[sevA] || 1;
  const weightB = SEVERITY_WEIGHT[sevB] || 1;
  return weightA >= weightB ? sevA : sevB;
}

/**
 * Heuristic mapping from threat type / description to MITRE ATT&CK technique IDs.
 */
export function inferMitreTechniques(type = '', description = '') {
  const combined = `${type} ${description}`.toLowerCase();
  const techniques = new Set();

  if (combined.includes('port scan') || combined.includes('port_scan') || combined.includes('reconnaissance')) {
    techniques.add('T1046'); // Network Service Discovery
  }
  if (combined.includes('brute') || combined.includes('login') || combined.includes('credential_stuffing')) {
    techniques.add('T1110'); // Brute Force
  }
  if (combined.includes('command') || combined.includes('powershell') || combined.includes('bash') || combined.includes('sh_spawn')) {
    techniques.add('T1059'); // Command and Scripting Interpreter
  }
  if (combined.includes('sql') || combined.includes('sqli') || combined.includes('xss') || combined.includes('exploit') || combined.includes('traversal')) {
    techniques.add('T1190'); // Exploit Public-Facing Application
  }
  if (combined.includes('ransom') || combined.includes('crypt') || combined.includes('encrypt')) {
    techniques.add('T1486'); // Data Encrypted for Impact
  }
  if (combined.includes('c2') || combined.includes('malware') || combined.includes('beacon') || combined.includes('trojan')) {
    techniques.add('T1071'); // Application Layer Protocol
  }
  if (combined.includes('privilege') || combined.includes('root') || combined.includes('sudo')) {
    techniques.add('T1068'); // Exploitation for Privilege Escalation
  }
  if (combined.includes('ddos') || combined.includes('dos') || combined.includes('flood')) {
    techniques.add('T1498'); // Network Denial of Service
  }

  return Array.from(techniques);
}

/**
 * Correlates a newly saved Threat document in real time.
 *
 * @param {Object} threat - Mongoose Threat document
 * @param {string} userId - ID of the analyst user
 * @param {Object} [clientNamespace] - Socket.IO namespace for browser clients
 * @param {string} [clientRoom] - User room string, e.g. `user:${userId}`
 */
export async function correlateFinding(threat, userId, clientNamespace = null, clientRoom = null) {
  try {
    const ip = threat.source?.ip;
    const processName = threat.source?.processName;

    // Load user preferences (non-blocking — fall back to defaults if not found)
    let windowMs  = DEFAULT_WINDOW_MS;
    let minThreshold = DEFAULT_MIN_THRESHOLD;
    try {
      const user = await User.findById(userId).select('preferences').lean();
      if (user?.preferences?.correlationWindowMs)  windowMs      = user.preferences.correlationWindowMs;
      if (user?.preferences?.minFindingsThreshold) minThreshold  = user.preferences.minFindingsThreshold;
    } catch (_) { /* use defaults */ }

    const windowStart = new Date(Date.now() - windowMs);
    const inferredMitre = inferMitreTechniques(threat.type, threat.description);

    // 1. Look for an existing open / investigating incident in the current correlation window
    const recentIncidents = await Incident.find({
      userId,
      status: { $in: ['open', 'investigating'] },
      updatedAt: { $gte: windowStart },
    }).populate('threatIds', 'source severity type description');

    let matchingIncident = null;

    for (const incident of recentIncidents) {
      // Check if any threat already in this incident shares the same IP or process
      const hasMatchingEntity = incident.threatIds.some((t) => {
        if (!t) return false;
        const sameIp = ip && t.source?.ip && t.source.ip === ip;
        const sameProc = processName && t.source?.processName && t.source.processName === processName;
        return sameIp || sameProc;
      });

      if (hasMatchingEntity) {
        matchingIncident = incident;
        break;
      }
    }

    if (matchingIncident) {
      // Add threat to existing incident
      const threatIdStr = threat._id.toString();
      const existingIds = matchingIncident.threatIds.map((t) => (t._id || t).toString());

      if (!existingIds.includes(threatIdStr)) {
        matchingIncident.threatIds.push(threat._id);
      }

      // Upgrade severity if this threat is more severe
      matchingIncident.severity = getHigherSeverity(matchingIncident.severity, threat.severity);

      // Merge new MITRE techniques
      const mitreSet = new Set(matchingIncident.mitreTechniques || []);
      inferredMitre.forEach((t) => mitreSet.add(t));
      matchingIncident.mitreTechniques = Array.from(mitreSet);

      // Update summary to reflect total constituent count
      const count = matchingIncident.threatIds.length;
      const entityLabel = ip || processName || 'endpoint';
      matchingIncident.summary = `Correlated ${count} security findings linked to ${entityLabel} (highest: ${matchingIncident.severity.toUpperCase()}).`;

      await matchingIncident.save();

      // Link incident to threat
      threat.incidentId = matchingIncident._id;
      await threat.save();

      if (clientNamespace && clientRoom) {
        clientNamespace.to(clientRoom).emit('incident:updated', matchingIncident.toObject());
      }

      return { incident: matchingIncident, isNew: false };
    }

    // 2. If no existing incident, check recent un-correlated threats from same entity
    const query = {
      userId,
      incidentId: null,
      createdAt: { $gte: windowStart },
      _id: { $ne: threat._id },
    };

    if (ip) {
      query['source.ip'] = ip;
    } else if (processName) {
      query['source.processName'] = processName;
    } else {
      // Without an entity to correlate on, only critical threats auto-open an incident
      if (threat.severity !== 'critical') {
        return null;
      }
    }

    const unassignedThreats = await Threat.find(query);

    // Form an incident when enough threats cluster (user-configurable) or on any critical finding
    const shouldCluster = unassignedThreats.length >= (minThreshold - 1) || threat.severity === 'critical';

    if (shouldCluster) {
      const allThreats = [...unassignedThreats, threat];
      const allIds = allThreats.map((t) => t._id);

      // Derive worst severity
      const worstSeverity = allThreats.reduce(
        (acc, t) => getHigherSeverity(acc, t.severity),
        threat.severity
      );

      // Aggregate MITRE techniques
      const techniqueSet = new Set(inferredMitre);
      for (const t of unassignedThreats) {
        inferMitreTechniques(t.type, t.description).forEach((m) => techniqueSet.add(m));
      }

      const entityLabel = ip || processName || 'Endpoint Activity';
      const distinctTypes = [...new Set(allThreats.map((t) => t.type))].join(', ');

      const newIncident = new Incident({
        userId,
        title: `Correlated Alert: ${entityLabel} (${distinctTypes})`,
        severity: worstSeverity,
        status: 'open',
        threatIds: allIds,
        summary: `Automated correlation detected ${allThreats.length} correlated events from ${entityLabel}. Patterns identified: ${distinctTypes}.`,
        mitreTechniques: Array.from(techniqueSet),
        notes: `System generated correlation at ${new Date().toISOString()}`,
      });

      await newIncident.save();

      // Associate all constituent threats with the new incident
      await Threat.updateMany(
        { _id: { $in: allIds } },
        { $set: { incidentId: newIncident._id } }
      );

      threat.incidentId = newIncident._id;

      if (clientNamespace && clientRoom) {
        clientNamespace.to(clientRoom).emit('incident:new', newIncident.toObject());
      }

      return { incident: newIncident, isNew: true };
    }

    return null;
  } catch (err) {
    console.error('[CorrelationService] Error in correlateFinding:', err);
    return null;
  }
}

/**
 * Handles agent-generated incident objects (kind: 'incident').
 */
export async function handleAgentIncident(agentIncident, userId, clientNamespace = null, clientRoom = null) {
  try {
    const title = agentIncident.title || `Agent Correlated Incident: ${agentIncident.severity || 'Medium'}`;
    const severity = (agentIncident.severity || 'medium').toLowerCase();
    const entities = agentIncident.entities || {};
    const ip = entities.ips?.[0] || null;

    // Check for recent matching threats to link
    const windowStart = new Date(Date.now() - CORRELATION_WINDOW_MS);
    const relatedThreats = await Threat.find({
      userId,
      createdAt: { $gte: windowStart },
      ...(ip ? { 'source.ip': ip } : {}),
    }).limit(20);

    const threatIds = relatedThreats.map((t) => t._id);

    const incident = new Incident({
      userId,
      title,
      severity: ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'medium',
      status: 'open',
      threatIds,
      summary: agentIncident.explanation || `Agent telemetry correlated multiple events on host.`,
      mitreTechniques: inferMitreTechniques(title, agentIncident.explanation || ''),
      notes: `Ingested from local agent sensor at ${new Date().toISOString()}`,
    });

    await incident.save();

    if (threatIds.length > 0) {
      await Threat.updateMany(
        { _id: { $in: threatIds } },
        { $set: { incidentId: incident._id } }
      );
    }

    if (clientNamespace && clientRoom) {
      clientNamespace.to(clientRoom).emit('incident:new', incident.toObject());
    }

    return incident;
  } catch (err) {
    console.error('[CorrelationService] Error in handleAgentIncident:', err);
    return null;
  }
}
