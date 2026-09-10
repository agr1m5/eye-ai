/**
 * defenseController.js — Active Defense & SOAR Containment.
 *
 * Dispatches active countermeasures to endpoint agents:
 *  - kill_process: kills malicious process tree
 *  - block_ip: blocks attacker IP in firewall
 *  - isolate_host: toggles network isolation
 *  - quarantine_file: vaults suspicious binaries
 */
import DefenseAction from '../models/DefenseAction.js';
import { createAuditEntry } from '../services/auditService.js';
import { getIO } from '../config/socket.js';

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

    const validActions = ['kill_process', 'block_ip', 'isolate_host', 'quarantine_file'];
    if (!validActions.includes(actionType)) {
      return res.status(400).json({
        status:  'error',
        message: `Invalid actionType. Allowed: ${validActions.join(', ')}`,
      });
    }

    // Save defense record
    const defenseAction = new DefenseAction({
      userId: req.user._id,
      actionType,
      target: String(target).trim(),
      reason: reason || 'SOC containment countermeasure',
      threatId: threatId || null,
      incidentId: incidentId || null,
      executedBy: executedBy || 'analyst',
      status: 'active',
      receipt: {
        dispatchedAt: new Date(),
        initiator: req.user.email,
        ip: req.ip,
      },
    });
    await defenseAction.save();

    // Dispatch command to agent namespace over Socket.IO
    try {
      const io = getIO();
      if (io) {
        io.of('/agent').emit('agent:command:contain', {
          actionId: defenseAction._id,
          actionType,
          target: defenseAction.target,
          reason: defenseAction.reason,
          userId: req.user._id.toString(),
        });

        // Broadcast to client dashboard room on default namespace
        io.of('/').to(`user:${req.user._id}`).emit('defense:action:executed', defenseAction.toObject());
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
      blockedIps: actions.filter((a) => a.status === 'active' && a.actionType === 'block_ip').length,
      isolatedHosts: actions.filter((a) => a.status === 'active' && a.actionType === 'isolate_host').length,
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
