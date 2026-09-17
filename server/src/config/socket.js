/**
 * Socket.IO Server Configuration — Eye Live SOC
 *
 * Namespaces:
 *   /        — Browser clients authenticated via JWT
 *   /agent   — Local agent clients authenticated via agent pairing token
 */
import mongoose from 'mongoose';
import { Server } from 'socket.io';
import { config } from './env.js';
import { verifyToken } from '../utils/jwt.js';
import User from '../models/User.js';
import Threat from '../models/Threat.js';
import Incident from '../models/Incident.js';
import HostActivity from '../models/HostActivity.js';
import DefenseAction from '../models/DefenseAction.js';
import { correlateFinding, handleAgentIncident } from '../services/correlationService.js';
import { dispatchCriticalAlert } from '../services/alertService.js';
import { enrichThreat } from '../services/geoService.js';
import { syncThreatsFromIncident } from '../services/incidentSyncService.js';
import { cancelDispatchTimeout } from '../controllers/defenseController.js';

let io = null;
const activeAgents = new Map(); // userId -> { socketId, label, lastSeen, metrics }

export function initSocketServer(httpServer) {
  io = new Server(httpServer, {
    cors: {
      origin: [config.clientOrigin, 'http://localhost:5180'],
      methods: ['GET', 'POST'],
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  /* ─────────────────────────────────────────────────────────────
     1. Default Namespace (/) — Browser Dashboards (JWT Auth)
  ───────────────────────────────────────────────────────────── */
  const clientNamespace = io.of('/');

  clientNamespace.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
      if (!token) {
        return next(new Error('Authentication token required'));
      }

      const payload = verifyToken(token);
      if (!payload?.sub) {
        return next(new Error('Invalid token payload'));
      }

      socket.userId = payload.sub.toString();
      next();
    } catch (err) {
      return next(new Error(`Authentication failed: ${err.message}`));
    }
  });

  clientNamespace.on('connection', (socket) => {
    const userRoom = `user:${socket.userId}`;
    socket.join(userRoom);
    console.log(`[Socket.IO:Client] User connected: ${socket.userId} (socket ${socket.id}) joined room ${userRoom}`);

    // If an agent is already active for this user, inform client immediately
    const active = activeAgents.get(socket.userId);
    if (active) {
      socket.emit('agent:status', {
        connected: true,
        label: active.label,
        lastSeen: active.lastSeen,
        metrics: active.metrics || null,
      });
    }

    socket.on('disconnect', (reason) => {
      console.log(`[Socket.IO:Client] User disconnected: ${socket.userId} (${reason})`);
    });
  });

  /* ─────────────────────────────────────────────────────────────
     2. Agent Namespace (/agent) — Local Security Agent
  ───────────────────────────────────────────────────────────── */
  const agentNamespace = io.of('/agent');

  agentNamespace.use(async (socket, next) => {
    try {
      const auth = socket.handshake.auth || {};
      const agentToken = auth.agentToken || auth.token;
      let userId = auth.userId;

      if (!agentToken) {
        return next(new Error('Agent pairing token required in auth'));
      }

      let user = null;
      if (userId) {
        user = await User.findById(userId).select('+agentTokenHash');
      } else {
        // Fallback: match against all users with an active pairing token
        const users = await User.find({ agentTokenHash: { $ne: null } }).select('+agentTokenHash');
        for (const u of users) {
          if (await u.compareAgentToken(agentToken)) {
            user = u;
            break;
          }
        }
      }

      if (!user) {
        return next(new Error('User account not found or invalid pairing token'));
      }

      const isValid = await user.compareAgentToken(agentToken);
      if (!isValid) {
        return next(new Error('Invalid or expired agent pairing token'));
      }

      socket.userId = user._id.toString();
      socket.agentLabel = user.agentLabel || 'Local Agent';
      next();
    } catch (err) {
      return next(new Error(`Agent auth failed: ${err.message}`));
    }
  });

  agentNamespace.on('connection', (socket) => {
    const userId = socket.userId;
    const clientRoom = `user:${userId}`;
    console.log(`[Socket.IO:Agent] Agent connected for user ${userId} (socket ${socket.id})`);

    const agentInfo = {
      connected: true,
      label: socket.agentLabel,
      lastSeen: new Date(),
    };

    activeAgents.set(userId, {
      socketId: socket.id,
      label: socket.agentLabel,
      lastSeen: agentInfo.lastSeen,
    });

    // Notify user's dashboard that agent is online
    clientNamespace.to(clientRoom).emit('agent:status', agentInfo);

    // Ingest single finding from agent
    socket.on('finding:submit', async (findingData, ack) => {
      try {
        if (!findingData || !findingData.severity || !findingData.type) {
          if (typeof ack === 'function') ack({ status: 'error', message: 'Invalid finding format' });
          return;
        }

        const threat = new Threat({
          userId: socket.userId,
          severity: findingData.severity,
          type: findingData.type,
          source: findingData.source || {},
          description: findingData.description || '',
          rawData: findingData.rawData || null,
          agentSessionId: findingData.agentSessionId || socket.id,
          status: 'new',
          fromImport: false,
        });

        await threat.save();

        // Enrich with GeoIP data (non-blocking, silent on RFC-1918 / error)
        await enrichThreat(threat);

        // Broadcast to user dashboard
        clientNamespace.to(clientRoom).emit('finding:new', threat.toObject());

        // Real-time correlation into an Incident
        await correlateFinding(threat, socket.userId, clientNamespace, clientRoom);

        // Fire webhook alert for critical / high findings
        if (threat.severity === 'critical' || threat.severity === 'high') {
          dispatchCriticalAlert(threat.toObject()).catch(() => {});
        }

        if (typeof ack === 'function') {
          ack({ status: 'success', threatId: threat._id });
        }
      } catch (err) {
        console.error(`[Socket.IO:Agent] Error saving finding:`, err.message);
        if (typeof ack === 'function') {
          ack({ status: 'error', message: err.message });
        }
      }
    });

    // Ingest batch findings from agent
    socket.on('findings:batch', async (data, ack) => {
      try {
        const findings = data?.findings || [];
        let count = 0;
        for (const f of findings) {
          if (!f) continue;

          // If agent emitted an already correlated incident cluster
          if (f.kind === 'incident') {
            await handleAgentIncident(f, socket.userId, clientNamespace, clientRoom);
            count++;
            continue;
          }

          if (!f.severity || !f.type) continue;
          const threat = new Threat({
            userId: socket.userId,
            severity: f.severity,
            type: f.type,
            source: f.source || {
              ip: f.sourceIp || null,
              processName: f.processName || null,
              pid: f.pid || null,
              port: f.port || null,
            },
            description: f.description || '',
            rawData: f.raw || f.rawData || null,
            agentSessionId: f.agentSessionId || socket.id,
            status: 'new',
            fromImport: false,
          });
          await threat.save();
          await enrichThreat(threat);
          count++;
          clientNamespace.to(clientRoom).emit('finding:new', threat.toObject());

          // Real-time entity & MITRE correlation
          await correlateFinding(threat, socket.userId, clientNamespace, clientRoom);

          // Fire webhook alert for critical / high findings
          if (threat.severity === 'critical' || threat.severity === 'high') {
            dispatchCriticalAlert(threat.toObject()).catch(() => {});
          }
        }
        if (typeof ack === 'function') {
          ack({ success: true, count });
        }
      } catch (err) {
        console.error('[Socket.IO:Agent] Batch save error:', err.message);
        if (typeof ack === 'function') ack({ success: false, error: err.message });
      }
    });

    // Ingest single host & user activity from agent (one-by-one real-time stream)
    socket.on('activity:single', async (act) => {
      try {
        if (!act) return;

        // Skip root user telemetry
        const actor = act.actor || act.user || 'system';
        if (actor === 'root' || actor.startsWith('_')) return;

        const doc = await HostActivity.create({
          userId: socket.userId,
          source: act.source || 'process',
          action: act.action || `${act.source || 'process'}.event`,
          description: act.description || act.message || 'Host activity recorded',
          actor,
          entity: act.entity || act.command || act.remoteIp || '',
          ip: act.ip || act.remoteIp || null,
          isThreat: Boolean(act.isThreat),
          severity: act.severity || 'none',
          threatType: act.threatType || null,
          metadata: act.metadata || act.raw ? { raw: act.raw, ...act } : act,
          timestamp: act.timestamp ? new Date(act.timestamp) : new Date(),
        });

        // Broadcast single activity to user's dashboard in real-time
        clientNamespace.to(clientRoom).emit('activity:single', doc.toObject());
      } catch (err) {
        console.error('[Socket.IO:Agent] Error saving single activity:', err.message);
      }
    });

    // Ingest batch host & user activities from agent
    socket.on('activities:batch', async (data, ack) => {
      try {
        const rawActivities = data?.activities || [];
        if (!Array.isArray(rawActivities) || rawActivities.length === 0) {
          if (typeof ack === 'function') ack({ success: true, count: 0 });
          return;
        }

        const docs = rawActivities.map((act) => ({
          userId: socket.userId,
          source: act.source || 'process',
          action: act.action || `${act.source || 'process'}.event`,
          description: act.description || act.message || 'Host activity recorded',
          actor: act.actor || act.user || 'system',
          entity: act.entity || act.command || act.remoteIp || '',
          ip: act.ip || act.remoteIp || null,
          isThreat: Boolean(act.isThreat),
          severity: act.severity || 'none',
          threatType: act.threatType || null,
          metadata: act.metadata || act.raw ? { raw: act.raw, ...act } : act,
          timestamp: act.timestamp ? new Date(act.timestamp) : new Date(),
        }));

        const inserted = await HostActivity.insertMany(docs, { ordered: false });

        // Real-time broadcast to user's dashboard
        clientNamespace.to(clientRoom).emit('activity:batch', inserted);

        if (typeof ack === 'function') {
          ack({ success: true, count: inserted.length });
        }
      } catch (err) {
        console.error('[Socket.IO:Agent] Error saving activity batch:', err.message);
        if (typeof ack === 'function') {
          ack({ success: false, error: err.message });
        }
      }
    });

    // Heartbeat from agent (handles both 'agent:heartbeat' and 'heartbeat')
    const handleHeartbeat = (data) => {
      const lastSeen = new Date();
      const metrics = data?.metrics || null;
      activeAgents.set(userId, {
        socketId: socket.id,
        label: socket.agentLabel,
        lastSeen,
        metrics,
      });

      clientNamespace.to(clientRoom).emit('agent:status', {
        connected: true,
        label: socket.agentLabel,
        lastSeen,
        metrics,
      });
    };

    socket.on('agent:heartbeat', handleHeartbeat);
    socket.on('heartbeat', handleHeartbeat);

    // Containment command receipt from agent
    socket.on('agent:contain:receipt', async (receipt) => {
      try {
        if (!receipt) return;

        // Clear in-flight dispatch timeout if present
        if (receipt.actionId) {
          cancelDispatchTimeout(receipt.actionId);
        }

        let action = null;
        if (receipt.actionId && mongoose.Types.ObjectId.isValid(receipt.actionId)) {
          action = await DefenseAction.findByIdAndUpdate(
            receipt.actionId,
            {
              status: receipt.success ? 'active' : 'failed',
              $set: { 'receipt.agentExecution': receipt },
            },
            { new: true }
          );
        }

        // Honest verification check: ONLY resolve incident if receipt.success is TRUE
        if (receipt.success) {
          if (action?.incidentId) {
            const inc = await Incident.findById(action.incidentId);
            if (inc && inc.status !== 'closed') {
              inc.status = 'resolved';
              inc.resolvedAt = inc.resolvedAt || new Date();

              const actionName = (receipt.actionType || action.actionType || 'containment').replace(/_/g, ' ').toUpperCase();
              const confirmMsg = `[Host Daemon Verification — ${new Date().toLocaleTimeString()}] Takedown verified on endpoint (${actionName} on target ${receipt.target || action.target}). Output: ${receipt.output || 'Enforced'}`;

              if (!inc.notes?.includes('Host Daemon Verification')) {
                inc.notes = inc.notes ? `${inc.notes}\n\n${confirmMsg}` : confirmMsg;
              }

              if (!inc.summary?.includes('Attack Taken Down')) {
                inc.summary = `${inc.summary} (Attack Taken Down via SOAR: ${actionName})`;
              }

              await inc.save();
              await syncThreatsFromIncident(inc._id, 'resolved', socket.userId);

              clientNamespace.to(clientRoom).emit('incident:updated', inc.toObject());
              clientNamespace.to(clientRoom).emit('incident:resolved', {
                incidentId: inc._id.toString(),
                actionType: receipt.actionType || action.actionType,
                target: receipt.target || action.target,
                resolvedAt: inc.resolvedAt,
                message: `Attack taken down: ${actionName} verified on target ${receipt.target || action.target}`,
                incident: inc.toObject(),
              });

              io.of('/').to(clientRoom).emit('incident:updated', inc.toObject());
              io.of('/').to(clientRoom).emit('incident:resolved', {
                incidentId: inc._id.toString(),
                actionType: receipt.actionType || action.actionType,
                target: receipt.target || action.target,
                resolvedAt: inc.resolvedAt,
                message: `Attack taken down: ${actionName} verified on target ${receipt.target || action.target}`,
                incident: inc.toObject(),
              });
            }
          }

          clientNamespace.to(clientRoom).emit('defense:action:confirmed', receipt);
          io.of('/').to(clientRoom).emit('defense:action:confirmed', receipt);
        } else {
          // Failure on endpoint (e.g. non-root, invalid syntax, verification mismatch)
          // Do NOT resolve the incident. Notify client dashboard of real failure.
          console.warn(`[Socket.IO:Agent] Containment failed on agent: ${receipt.output}`);
          clientNamespace.to(clientRoom).emit('defense:action:failed', receipt);
          io.of('/').to(clientRoom).emit('defense:action:failed', receipt);
        }
      } catch (err) {
        console.error('[Socket.IO:Agent] Error updating defense action receipt:', err.message);
      }
    });

    socket.on('disconnect', (reason) => {
      console.log(`[Socket.IO:Agent] Agent disconnected for user ${userId}: ${reason}`);
      activeAgents.delete(userId);
      const lastSeen = new Date();
      clientNamespace.to(clientRoom).emit('agent:status', {
        connected: false,
        label: socket.agentLabel,
        lastSeen,
      });
    });
  });

  return io;
}

export function getIO() {
  if (!io) {
    throw new Error('[Socket.IO] Server not initialized!');
  }
  return io;
}

export function isAgentConnected(userId) {
  if (!userId) return false;
  return activeAgents.has(userId.toString());
}

export function disconnectAgent(userId) {
  if (!userId) return;
  const uId = userId.toString();
  const active = activeAgents.get(uId);
  if (active && io) {
    const agentSocket = io.of('/agent').sockets.get(active.socketId);
    if (agentSocket) {
      agentSocket.disconnect(true);
    }
    activeAgents.delete(uId);
    const clientRoom = `user:${uId}`;
    io.of('/').to(clientRoom).emit('agent:status', {
      connected: false,
      label: active.label,
      lastSeen: new Date(),
    });
  }
}

