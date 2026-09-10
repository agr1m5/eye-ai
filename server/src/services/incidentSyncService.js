/**
 * incidentSyncService.js — Bidirectional synchronization between Incidents and Threats.
 *
 * Ensures analysts NEVER need to perform redundant operations on both:
 *
 * 1. Incident -> Threats:
 *    - Incident marked 'resolved' or 'closed' => Automatically marks all constituent threats as 'dismissed'.
 *    - Incident marked 'investigating' => Automatically marks all 'new' constituent threats as 'acknowledged'.
 *    - Incident deleted => Automatically deletes or unlinks constituent threats.
 *
 * 2. Threats -> Incident:
 *    - When all constituent threats are 'dismissed' => Automatically marks parent incident as 'resolved'.
 *    - When all constituent threats are 'acknowledged' (or dismissed, none 'new') => Automatically marks parent incident as 'investigating'.
 *    - When constituent threats are deleted => Updates parent incident's threatIds, recalculates severity. If 0 remain, auto-closes the incident.
 */
import Incident from '../models/Incident.js';
import Threat from '../models/Threat.js';

const SEVERITY_WEIGHT = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function getHighestSeverity(severities = []) {
  let highest = 'info';
  let maxWeight = 1;
  for (const sev of severities) {
    const w = SEVERITY_WEIGHT[sev] || 1;
    if (w > maxWeight) {
      maxWeight = w;
      highest = sev;
    }
  }
  return highest;
}

/**
 * When an Incident status changes, sync its constituent threats.
 *
 * - resolved / closed: All threats marked 'dismissed'
 * - investigating: All 'new' threats marked 'acknowledged'
 */
export async function syncThreatsFromIncident(incidentId, newStatus, userId) {
  if (!incidentId || !newStatus) return { modifiedCount: 0 };

  if (newStatus === 'resolved' || newStatus === 'closed') {
    const res = await Threat.updateMany(
      {
        userId,
        $or: [{ incidentId }, { _id: { $in: [incidentId] } }],
        status: { $ne: 'dismissed' },
      },
      { $set: { status: 'dismissed' } }
    );
    return { modifiedCount: res.modifiedCount, newThreatStatus: 'dismissed' };
  }

  if (newStatus === 'investigating') {
    const res = await Threat.updateMany(
      {
        userId,
        $or: [{ incidentId }, { _id: { $in: [incidentId] } }],
        status: 'new',
      },
      { $set: { status: 'acknowledged' } }
    );
    return { modifiedCount: res.modifiedCount, newThreatStatus: 'acknowledged' };
  }

  return { modifiedCount: 0 };
}

/**
 * When one or more Threats change status or are removed, sync their parent Incident(s).
 *
 * - If all constituent threats are 'dismissed' => Incident status becomes 'resolved'
 * - If all constituent threats are 'acknowledged' or 'dismissed' (none 'new') & incident was 'open' => Incident status becomes 'investigating'
 * - Recalculates highest severity among remaining threats
 * - If 0 threats remain => marks Incident 'closed'
 */
export async function syncIncidentFromThreats(incidentId, userId) {
  if (!incidentId) return null;

  const incident = await Incident.findOne({ _id: incidentId, userId });
  if (!incident) return null;

  const threats = await Threat.find({
    userId,
    $or: [{ incidentId: incident._id }, { _id: { $in: incident.threatIds || [] } }],
  }).lean();

  if (threats.length === 0) {
    // All threats for this incident have been deleted
    incident.threatIds = [];
    if (incident.status !== 'closed' && incident.status !== 'resolved') {
      incident.status = 'closed';
      incident.summary = `${incident.summary || ''} (All constituent findings cleared)`.trim();
    }
    await incident.save();
    return { incident, autoResolved: true, remainingCount: 0 };
  }

  // Update threatIds array to strictly match existing threats
  incident.threatIds = threats.map((t) => t._id);

  // Recalculate severity based on active threats
  incident.severity = getHighestSeverity(threats.map((t) => t.severity));

  const total = threats.length;
  const dismissedCount = threats.filter((t) => t.status === 'dismissed').length;
  const ackCount = threats.filter((t) => t.status === 'acknowledged').length;
  const newCount = threats.filter((t) => t.status === 'new').length;

  let statusUpdated = false;

  // If all constituent threats are dismissed/closed, automatically resolve the incident!
  if (dismissedCount === total && incident.status !== 'resolved' && incident.status !== 'closed') {
    incident.status = 'resolved';
    statusUpdated = true;
  } else if (newCount === 0 && incident.status === 'open' && (ackCount > 0 || dismissedCount > 0)) {
    // If all threats are acknowledged (or dismissed) and none are new, move to investigating
    incident.status = 'investigating';
    statusUpdated = true;
  }

  await incident.save();
  return { incident, statusUpdated, total, dismissedCount, ackCount, newCount };
}

/**
 * Helper to sync multiple incidents by threat IDs.
 */
export async function syncIncidentsForThreats(threatIds = [], userId) {
  if (!threatIds || threatIds.length === 0) return;

  const threats = await Threat.find({
    _id: { $in: threatIds },
    userId,
    incidentId: { $ne: null },
  }).select('incidentId').lean();

  const incidentIds = Array.from(new Set(threats.map((t) => t.incidentId.toString())));
  await Promise.all(incidentIds.map((id) => syncIncidentFromThreats(id, userId)));
}
