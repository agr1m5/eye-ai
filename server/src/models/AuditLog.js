/**
 * AuditLog Model — Eye Live SOC
 *
 * Immutable record of significant analyst actions for compliance,
 * forensics, and SOC-2 audit trail requirements.
 *
 * Recorded actions:
 *   threat.acknowledged    — analyst acknowledged a finding
 *   threat.dismissed       — analyst dismissed a finding
 *   incident.status_changed — incident workflow transition
 *   incident.notes_saved   — analyst updated incident notes
 *   report.generated       — PDF report triggered
 *   agent.token_issued     — new agent pairing token created
 *   agent.token_revoked    — agent token revoked
 *   preferences.updated    — correlation rule settings changed
 */
import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    // Dot-namespaced action identifier, e.g. 'threat.dismissed'
    action: {
      type:     String,
      required: true,
      index:    true,
    },

    // Type of the primary object affected
    targetType: {
      type: String,
      enum: ['threat', 'incident', 'report', 'agent', 'preferences', 'system', 'user'],
      default: 'system',
      set: (v) => (v ? v.toLowerCase() : 'system'),
    },

    // MongoDB ObjectId string of the affected document (if applicable)
    targetId: {
      type:    String,
      default: null,
    },

    // Extra context — varies by action (old/new status, report title, etc.)
    metadata: {
      type:    mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    // Audit logs are append-only — disable update operations at the schema level
    strict: true,
  }
);

// Compound index for per-user paginated queries
auditLogSchema.index({ userId: 1, createdAt: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);
export default AuditLog;
