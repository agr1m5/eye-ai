/**
 * socketHelpers.js — Utilities for emitting Socket.IO events to user rooms.
 */
import { getIO } from '../config/socket.js';

/**
 * Emit an event to all connected dashboard sockets for a specific user.
 * @param {string} userId - Target user ID (ObjectId or string)
 * @param {string} event - Event name (e.g. 'finding:new', 'incident:updated')
 * @param {any} data - Event payload
 */
export function emitToUser(userId, event, data) {
  try {
    const io = getIO();
    const room = `user:${userId.toString()}`;
    io.of('/').to(room).emit(event, data);
  } catch (error) {
    console.error(`[SocketHelper] Failed to emit ${event} to user ${userId}:`, error.message);
  }
}
