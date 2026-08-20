/**
 * Socket.IO Server Configuration — Rakshak Live SOC
 *
 * Namespaces:
 *   /        — Browser clients authenticated via JWT
 *   /agent   — Local agent clients authenticated via agent pairing token
 */
import { Server } from 'socket.io';
import { config } from './env.js';
import { verifyToken } from '../utils/jwt.js';
import User from '../models/User.js';
import Threat from '../models/Threat.js';

let io = null;

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
      const { agentToken, userId } = socket.handshake.auth || {};
      if (!agentToken || !userId) {
        return next(new Error('Agent pairing token and userId required in auth'));
      }

      const user = await User.findById(userId).select('+agentTokenHash');
      if (!user) {
        return next(new Error('User account not found'));
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

    // Notify user's dashboard that agent is online
    clientNamespace.to(clientRoom).emit('agent:status', {
      connected: true,
      label: socket.agentLabel,
      lastSeen: new Date(),
    });

    // Ingest finding from agent
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

        // Broadcast to user dashboard
        clientNamespace.to(clientRoom).emit('finding:new', threat.toObject());

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

    // Heartbeat from agent
    socket.on('agent:heartbeat', (data) => {
      clientNamespace.to(clientRoom).emit('agent:status', {
        connected: true,
        label: socket.agentLabel,
        lastSeen: new Date(),
        metrics: data?.metrics || null,
      });
    });

    socket.on('disconnect', (reason) => {
      console.log(`[Socket.IO:Agent] Agent disconnected for user ${userId}: ${reason}`);
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
