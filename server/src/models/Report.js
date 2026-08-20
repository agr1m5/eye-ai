/**
 * Report Model — Rakshak Live SOC
 *
 * Tracks a PDF incident report that was requested by an analyst.
 * Report generation is async (the PDF is built server-side by a worker
 * using puppeteer/pdfkit in Step 13). This document acts as the
 * job record + metadata pointer to the finished file.
 *
 * Two generation modes:
 *   1. Incident-scoped  — incidentId is set; PDF covers one incident
 *   2. Time-range       — timeRange is set; PDF covers all activity
 *                         in a date window
 *
 * Steps that use this model:
 *   Step 13 — reportController CRUD + PDF generation worker
 */
import mongoose from 'mongoose';

/* ── Sub-schema: time range ──────────────────────────────────── */
const timeRangeSchema = new mongoose.Schema(
  {
    from: { type: Date, required: true },
    to:   { type: Date, required: true },
  },
  { _id: false }
);

/* ── Main Schema ─────────────────────────────────────────────── */
const reportSchema = new mongoose.Schema(
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

    // Scoping — at least one of incidentId or timeRange must be provided
    incidentId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'Incident',
      default: null,
    },
    timeRange: {
      type:    timeRangeSchema,
      default: null,
    },

    // Server-side path to the generated PDF file
    filePath: {
      type:    String,
      default: null,
    },

    // Size in bytes of the generated PDF
    fileSize: {
      type:    Number,
      default: null,
    },

    status: {
      type:    String,
      enum:    ['pending', 'generating', 'done', 'failed'],
      default: 'pending',
      index:   true,
    },

    // Stores error message if status === 'failed'
    error: {
      type:    String,
      default: null,
    },

    // Timestamp when generation completed (success or failure)
    generatedAt: {
      type:    Date,
      default: null,
    },
  },
  { timestamps: true }
);

/* ── Pre-save hook: stamp generatedAt on terminal states ─────── */
reportSchema.pre('save', function (next) {
  if (
    this.isModified('status') &&
    (this.status === 'done' || this.status === 'failed') &&
    !this.generatedAt
  ) {
    this.generatedAt = new Date();
  }
  next();
});

/* ── Indexes ─────────────────────────────────────────────────── */
reportSchema.index({ userId: 1, createdAt: -1 });
reportSchema.index({ userId: 1, status: 1 });

const Report = mongoose.model('Report', reportSchema);
export default Report;
