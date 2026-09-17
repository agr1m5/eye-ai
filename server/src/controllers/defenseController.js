/**
 * defenseController.js — Active Defense & SOAR Containment.
 *
 * Dispatches active countermeasures to endpoint agents:
 *  - kill_process: kills malicious process tree
 *  - isolate_host: toggles network isolation
 *  - quarantine_file: vaults suspicious binaries
 */
import DefenseAction from '../models/DefenseAction.js';
import Incident from '../models/Incident.js';
import Threat from '../models/Threat.js';
import { syncThreatsFromIncident } from '../services/incidentSyncService.js';
import { createAuditEntry } from '../services/auditService.js';
import { getIO } from '../config/socket.js';

// Map of in-flight containment dispatch timeouts: actionId -> NodeJS.Timeout
export const dispatchTimeouts = new Map();

export function cancelDispatchTimeout(actionId) {
  const idStr = String(actionId);
  const t = dispatchTimeouts.get(idStr);
  if (t) {
    clearTimeout(t);
    dispatchTimeouts.delete(idStr);
  }
}

/* ── POST /api/defense/contain ───────────────────────────────── */
export async function executeContainment(req, res, next) {
  try {
    const { actionType, target, reason, threatId, incidentId, executedBy = 'analyst' } = req.body;

    if (!actionType || !target || String(target).trim() === 'undefined' || String(target).trim() === 'null') {
      return res.status(400).json({
        status:  'error',
        message: 'A valid target IP, PID, or hostname is required for containment.',
      });
    }

    const validActions = ['kill_process', 'isolate_host', 'quarantine_file'];
    if (!validActions.includes(actionType)) {
      return res.status(400).json({
        status:  'error',
        message: `Invalid actionType. Allowed: ${validActions.join(', ')}`,
      });
    }

    let numericPid = null;
    let expectedProcessName = req.body.expectedProcessName || null;

    if (actionType === 'kill_process') {
      const candidatePid = req.body.pid !== undefined ? req.body.pid : target;
      // Allow exact numeric PID or "PID: <number>" formatting
      const cleanedPid = typeof candidatePid === 'string' && candidatePid.trim().startsWith('PID:')
        ? candidatePid.trim().replace(/^PID:\s*/i, '')
        : candidatePid;

      numericPid = Number(cleanedPid);
      if (!Number.isInteger(numericPid) || numericPid <= 0) {
        return res.status(400).json({
          status:  'error',
          message: `Invalid PID: "${candidatePid}". Target must be a positive integer PID for kill_process.`,
        });
      }
    }

    // Correlate to an active or relevant Incident
    let incident = null;
    let threatDoc = null;
    if (incidentId) {
      incident = await Incident.findOne({ _id: incidentId, userId: req.user._id });
    }
    if (threatId) {
      threatDoc = await Threat.findOne({ _id: threatId, userId: req.user._id });
      if (!incident && threatDoc?.incidentId) {
        incident = await Incident.findOne({ _id: threatDoc.incidentId, userId: req.user._id });
      }
      if (!expectedProcessName && threatDoc?.source?.processName) {
        expectedProcessName = threatDoc.source.processName;
      }
    }
    if (!incident) {
      const rawTarget = String(target).trim();
      const cleanNum = numericPid || Number(rawTarget.replace(/[^\d]/g, ''));
      const ipPattern = rawTarget.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];

      const queryConditions = [];
      if (ipPattern) queryConditions.push({ 'source.ip': ipPattern });
      if (cleanNum && !isNaN(cleanNum)) queryConditions.push({ 'source.pid': cleanNum });
      queryConditions.push({ 'source.processName': new RegExp(rawTarget.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') });

      const matchingThreat = await Threat.findOne({
        userId: req.user._id,
        $or: queryConditions,
        incidentId: { $ne: null },
      }).sort({ createdAt: -1 });

      if (matchingThreat?.incidentId) {
        incident = await Incident.findOne({ _id: matchingThreat.incidentId, userId: req.user._id });
      }
      if (!expectedProcessName && matchingThreat?.source?.processName) {
        expectedProcessName = matchingThreat.source.processName;
      }
    }
    if (!incident) {
      // Find the most recent open or investigating incident
      incident = await Incident.findOne({
        userId: req.user._id,
        status: { $in: ['open', 'investigating'] },
      }).sort({ createdAt: -1 });
    }

    if (!expectedProcessName && incident) {
      const incidentThreat = await Threat.findOne({
        userId: req.user._id,
        incidentId: incident._id,
        $or: [
          ...(numericPid ? [{ 'source.pid': numericPid }] : []),
          { 'source.processName': { $ne: null } },
        ],
      }).sort({ createdAt: -1 });
      if (incidentThreat?.source?.processName) {
        expectedProcessName = incidentThreat.source.processName;
      }
    }

    // Save defense record with status 'active' (in-flight until verified by agent receipt)
    const defenseAction = new DefenseAction({
      userId: req.user._id,
      actionType,
      target: String(target).trim(),
      pid: numericPid,
      expectedProcessName,
      filePath: req.body.filePath || null,
      reason: reason || 'SOC containment countermeasure',
      threatId: threatId || null,
      incidentId: incident?._id || incidentId || null,
      executedBy: executedBy || 'analyst',
      status: 'active',
      receipt: {
        dispatchedAt: new Date(),
        initiator: req.user.email,
        ip: req.ip,
      },
    });
    await defenseAction.save();

    // 30-second dispatch timeout: if agent does not return a verification receipt within 30s, mark failed
    const timeoutHandle = setTimeout(async () => {
      try {
        dispatchTimeouts.delete(defenseAction._id.toString());
        const freshAction = await DefenseAction.findById(defenseAction._id);
        if (freshAction && !freshAction.receipt?.agentExecution && freshAction.status === 'active') {
          freshAction.status = 'failed';
          freshAction.receipt = {
            ...freshAction.receipt,
            error: 'Dispatch timeout: Agent did not acknowledge receipt within 30s',
            timedOutAt: new Date(),
          };
          await freshAction.save();

          const io = getIO();
          if (io) {
            const clientRoom = `user:${req.user._id}`;
            const failPayload = {
              actionId: freshAction._id.toString(),
              actionType: freshAction.actionType,
              target: freshAction.target,
              success: false,
              output: 'Containment failed: Endpoint agent timed out (30s elapsed without receipt).',
            };
            io.of('/').to(clientRoom).emit('defense:action:failed', failPayload);
            io.of('/client').to(clientRoom).emit('defense:action:failed', failPayload);
          }
        }
      } catch (timeoutErr) {
        console.error('[DefenseController] Timeout handler error:', timeoutErr.message);
      }
    }, 30000);

    dispatchTimeouts.set(defenseAction._id.toString(), timeoutHandle);

    // Dispatch command to agent namespace over Socket.IO (incident is NOT marked resolved yet)
    try {
      const io = getIO();
      if (io) {
        io.of('/agent').emit('agent:command:contain', {
          actionId: defenseAction._id,
          actionType,
          target: defenseAction.target,
          pid: numericPid,
          expectedProcessName,
          filePath: req.body.filePath || null,
          reason: defenseAction.reason,
          userId: req.user._id.toString(),
        });

        const clientRoom = `user:${req.user._id}`;
        // Broadcast dispatch event to client dashboard room
        io.of('/').to(clientRoom).emit('defense:action:executed', defenseAction.toObject());
        try {
          io.of('/client').to(clientRoom).emit('defense:action:executed', defenseAction.toObject());
        } catch (_) {}
      }
    } catch (socketErr) {
      console.warn('[DefenseController] Socket dispatch warning:', socketErr.message);
    }

    // Log compliance audit entry
    createAuditEntry({
      userId: req.user._id,
      action: `defense.${actionType}`,
      targetType: 'system',
      targetId: defenseAction._id,
      metadata: {
        target: defenseAction.target,
        reason: defenseAction.reason,
        executedBy: defenseAction.executedBy,
      },
      ip: req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: `Containment action '${actionType}' dispatched for target ${target}`,
      data:    defenseAction,
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/defense/actions ────────────────────────────────── */
export async function listDefenseActions(req, res, next) {
  try {
    const { status, limit = 50 } = req.query;
    const filter = { userId: req.user._id };
    if (status) filter.status = status;

    const actions = await DefenseAction.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit, 10))
      .lean();

    const activeCounts = {
      total: actions.length,
      active: actions.filter((a) => a.status === 'active').length,
      isolatedHosts: actions.filter((a) => a.status === 'active' && a.actionType === 'isolate_host').length,
      quarantinedFiles: actions.filter((a) => a.status === 'active' && a.actionType === 'quarantine_file').length,
      killedProcesses: actions.filter((a) => a.actionType === 'kill_process').length,
    };

    return res.status(200).json({
      status: 'success',
      data: {
        actions,
        stats: activeCounts,
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/defense/:id/release ───────────────────────────── */
export async function releaseDefenseAction(req, res, next) {
  try {
    const action = await DefenseAction.findOne({
      _id: req.params.id,
      userId: req.user._id,
    });

    if (!action) {
      return res.status(404).json({ status: 'error', message: 'Defense action not found.' });
    }

    action.status = 'released';
    action.receipt = {
      ...action.receipt,
      releasedAt: new Date(),
      releasedBy: req.user.email,
    };
    await action.save();

    // Notify agent to unblock/restore
    try {
      const io = getIO();
      if (io) {
        io.of('/agent').emit('agent:command:release', {
          actionId: action._id,
          actionType: action.actionType,
          target: action.target,
          userId: req.user._id.toString(),
        });
        io.of('/client').to(`user:${req.user._id}`).emit('defense:action:released', action.toObject());
      }
    } catch {}

    createAuditEntry({
      userId: req.user._id,
      action: `defense.released_${action.actionType}`,
      targetType: 'system',
      targetId: action._id,
      metadata: { target: action.target },
      ip: req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: `Containment for ${action.target} successfully released.`,
      data:    action,
    });
  } catch (err) {
    next(err);
  }
}
