/**
 * Incident Model — Eye Live SOC
 *
 * Represents a correlated cluster of related Threat findings.
 * The backend (or AI agent) groups threats that appear related
 * (same source IP, same time window, related MITRE techniques, etc.)
 * into a single Incident for easier analyst triage.
 *
 * Severity reflects the highest-severity member threat and is
 * recalculated whenever the Incident is updated.
 *
 * Steps that use this model:
 *   Step 6  — Socket.IO  'incident:updated' events
 *   Step 11 — IncidentsPage + incidentController CRUD
 *   Step 13 — Report generation (incident scoped)
 */
import mongoose from 'mongoose';

/* ── Severity order helper (not stored) ─────────────────────── */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/* ── Main Schema ─────────────────────────────────────────────── */
const incidentSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    title: {
      type:    String,
      required: true,
      trim:    true,
    },

    // Highest severity among member threats
    severity: {
      type:    String,
      enum:    ['critical', 'high', 'medium', 'low', 'info'],
      default: 'info',
      index:   true,
    },

    status: {
      type:    String,
      enum:    ['open', 'investigating', 'resolved', 'closed'],
      default: 'open',
      index:   true,
    },

    // References to constituent Threat documents
    threatIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref:  'Threat',
      },
    ],

    // AI-generated or analyst-written narrative
    summary: {
      type:    String,
      default: '',
    },

    // MITRE ATT&CK technique IDs observed, e.g. ['T1059', 'T1071.001']
    mitreTechniques: {
      type:    [String],
      default: [],
    },

    // Analyst notes
    notes: {
      type:    String,
      default: '',
    },

    resolvedAt: {
      type:    Date,
      default: null,
    },
  },
  { timestamps: true }
);

/* ── Pre-save hook: set resolvedAt timestamp automatically ───── */
incidentSchema.pre('save', function (next) {
  if (
    this.isModified('status') &&
    (this.status === 'resolved' || this.status === 'closed') &&
    !this.resolvedAt
  ) {
    this.resolvedAt = new Date();
  }
  next();
});

/* ── Compound indexes ────────────────────────────────────────── */
incidentSchema.index({ userId: 1, status: 1 });
incidentSchema.index({ userId: 1, severity: 1 });
incidentSchema.index({ userId: 1, createdAt: -1 });

const Incident = mongoose.model('Incident', incidentSchema);
export default Incident;
