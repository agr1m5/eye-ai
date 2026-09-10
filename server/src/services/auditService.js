/**
 * auditService.js — Analyst Audit Log Helper.
 *
 * Provides a single `createAuditEntry()` function that controllers call
 * to record significant analyst actions without blocking the response.
 *
 * All writes are fire-and-forget — audit failures are logged but
 * never propagated to the caller.
 */
import AuditLog from '../models/AuditLog.js';

/**
 * Record an analyst action in the audit log.
 * Non-blocking — returns immediately; database write is async.
 *
 * @param {string}  userId     — authenticated user's ObjectId string
 * @param {string}  action     — dot-namespaced action, e.g. 'threat.dismissed'
 * @param {string}  targetType — 'threat' | 'incident' | 'report' | 'agent' | 'preferences' | 'system'
 * @param {string}  [targetId] — ObjectId of the affected document
 * @param {Object}  [metadata] — extra context (old status, new status, title, etc.)
 */
export function createAuditEntry(arg1, action, targetType, targetId = null, metadata = {}, ip = null) {
  let entry;
  if (typeof arg1 === 'object' && arg1 !== null) {
    entry = {
      userId: arg1.userId,
      action: arg1.action,
      targetType: (arg1.targetType || 'system').toLowerCase(),
      targetId: arg1.targetId?.toString() || null,
      metadata: arg1.metadata || {},
      ip: arg1.ip || null,
    };
  } else {
    entry = {
      userId: arg1,
      action,
      targetType: (targetType || 'system').toLowerCase(),
      targetId: targetId?.toString() || null,
      metadata,
      ip,
    };
  }

  // Fire-and-forget — never awaited by callers
  AuditLog.create(entry)
    .catch((err) => {
      console.error('[AuditService] Failed to write audit entry:', entry.action, err.message);
    });
}
