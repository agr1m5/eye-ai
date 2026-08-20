/**
 * ImportedLog Model — Rakshak Live SOC
 *
 * Tracks a log file that was manually uploaded by an analyst
 * (the secondary ingestion path, complementing the live agent).
 *
 * After upload the backend queues an analysis job that parses
 * the file and creates Threat documents linked back to this record
 * via Threat.importedLogId.
 *
 * Supported file types (enforced at controller level in Step 14):
 *   text/plain, application/json, text/csv, application/gzip
 *
 * Steps that use this model:
 *   Step 14 — logImportController upload + analysis + results
 */
import mongoose from 'mongoose';

const importedLogSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    // Original filename as uploaded by the browser
    originalName: {
      type:     String,
      required: true,
      trim:     true,
    },

    // Server-side absolute path where the file is stored
    filePath: {
      type:     String,
      required: true,
    },

    // File size in bytes
    fileSize: {
      type:    Number,
      default: 0,
    },

    // MIME type detected on upload
    mimeType: {
      type:    String,
      default: 'application/octet-stream',
    },

    status: {
      type:    String,
      enum:    ['uploaded', 'processing', 'done', 'failed'],
      default: 'uploaded',
      index:   true,
    },

    // How many Threat documents were extracted from this log
    threatCount: {
      type:    Number,
      default: 0,
    },

    // Stores error message if status === 'failed'
    error: {
      type:    String,
      default: null,
    },

    // Timestamp when analysis completed (success or failure)
    processedAt: {
      type:    Date,
      default: null,
    },
  },
  { timestamps: true }
);

/* ── Pre-save hook: stamp processedAt on terminal states ──────── */
importedLogSchema.pre('save', function (next) {
  if (
    this.isModified('status') &&
    (this.status === 'done' || this.status === 'failed') &&
    !this.processedAt
  ) {
    this.processedAt = new Date();
  }
  next();
});

/* ── Indexes ─────────────────────────────────────────────────── */
importedLogSchema.index({ userId: 1, createdAt: -1 });
importedLogSchema.index({ userId: 1, status: 1 });

const ImportedLog = mongoose.model('ImportedLog', importedLogSchema);
export default ImportedLog;
