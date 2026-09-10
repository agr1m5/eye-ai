/**
 * Threat Model — Rakshak Live SOC
 *
 * Represents a single security finding emitted by the local agent
 * or extracted from a manually imported log file.
 *
 * Lifecycle:
 *   new  →  acknowledged  →  dismissed
 *              ↓
 *         (correlated into an Incident, incidentId set)
 *
 * Steps that use this model:
 *   Step 6  — Socket.IO agent finding ingestion  (agent emits 'finding:new')
 *   Step 11 — ThreatsPage + threatController CRUD
 *   Step 14 — Log import analysis
 */
import mongoose from 'mongoose';

/* ── Sub-schema: source info ─────────────────────────────────── */
const sourceSchema = new mongoose.Schema(
  {
    ip:          { type: String, default: null },
    hostname:    { type: String, default: null },
    processName: { type: String, default: null },
    pid:         { type: Number, default: null },
    port:        { type: Number, default: null },
    protocol:    { type: String, default: null },
  },
  { _id: false }
);

/* ── Sub-schema: GeoIP enrichment (optional) ─────────────────── */
const geoSchema = new mongoose.Schema(
  {
    country:     { type: String, default: null },
    countryCode: { type: String, default: null },  // ISO 3166-1 alpha-2, e.g. 'CN'
    city:        { type: String, default: null },
    isp:         { type: String, default: null },
    lat:         { type: Number, default: null },
    lon:         { type: Number, default: null },
  },
  { _id: false }
);

/* ── Main Schema ─────────────────────────────────────────────── */
const threatSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    severity: {
      type:     String,
      enum:     ['critical', 'high', 'medium', 'low', 'info'],
      required: true,
      index:    true,
    },

    // Human-readable category, e.g. 'Port Scan', 'Brute Force', 'Malware C2'
    type: {
      type:     String,
      required: true,
      trim:     true,
    },

    // Where the threat originated
    source: {
      type:    sourceSchema,
      default: () => ({}),
    },

    description: {
      type:    String,
      default: '',
    },

    // Raw JSON payload from the agent — flexible for any sensor
    rawData: {
      type:    mongoose.Schema.Types.Mixed,
      default: null,
    },

    status: {
      type:    String,
      enum:    ['new', 'acknowledged', 'dismissed'],
      default: 'new',
      index:   true,
    },

    // Set when this threat is correlated into an incident
    incidentId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'Incident',
      default: null,
      index:   true,
    },

    // Which agent session produced this finding
    agentSessionId: {
      type:    String,
      default: null,
    },

    // True if this came from a manual log import rather than live agent
    fromImport: {
      type:    Boolean,
      default: false,
    },
    importedLogId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'ImportedLog',
      default: null,
    },

    // GeoIP enrichment — auto-populated from ip-api.com for public source IPs
    geo: {
      type:    geoSchema,
      default: null,
    },
  },
  { timestamps: true }
);

/* ── Compound indexes for common query patterns ──────────────── */
threatSchema.index({ userId: 1, severity: 1 });
threatSchema.index({ userId: 1, status: 1 });
threatSchema.index({ userId: 1, createdAt: -1 });
threatSchema.index({ userId: 1, incidentId: 1 });

const Threat = mongoose.model('Threat', threatSchema);
export default Threat;
