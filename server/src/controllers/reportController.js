/**
 * reportController.js — PDF incident report generation.
 *
 * Uses the `pdfkit` library (already installed) to generate PDF reports
 * server-side. Supports two modes:
 *   1. Incident-scoped  — covers a single correlated incident
 *   2. Time-range       — covers all threats in a date window
 *
 * Routes:
 *   GET    /api/reports               — list reports
 *   POST   /api/reports               — generate a new PDF report
 *   GET    /api/reports/:id/download  — stream the PDF file
 *   DELETE /api/reports/:id           — delete report + file
 */
import path    from 'path';
import fs      from 'fs';
import { fileURLToPath } from 'url';
import PDFDocument from 'pdfkit';

import Report   from '../models/Report.js';
import Incident from '../models/Incident.js';
import Threat   from '../models/Threat.js';

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.resolve(__dirname, '../../reports');

// Ensure reports directory exists
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

/* ── GET /api/reports ────────────────────────────────────────── */
export async function listReports(req, res, next) {
  try {
    const reports = await Report.find({ userId: req.user._id })
      .sort('-createdAt')
      .lean();

    return res.status(200).json({ status: 'success', data: reports });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/reports ───────────────────────────────────────── */
export async function generateReport(req, res, next) {
  try {
    const { title, incidentId, timeRange } = req.body;

    if (!title) {
      return res.status(400).json({ status: 'error', message: 'Report title is required.' });
    }
    if (!incidentId && !timeRange) {
      return res.status(400).json({
        status:  'error',
        message: 'Either incidentId or timeRange (from/to) must be provided.',
      });
    }

    // Create report document
    const report = new Report({
      userId:     req.user._id,
      title,
      incidentId: incidentId || null,
      timeRange:  timeRange  || null,
      status:     'generating',
    });
    await report.save();

    // Return immediately; PDF generation is async
    res.status(202).json({ status: 'success', data: report });

    // ── Async PDF generation ────────────────────────────────────
    generatePDF(report, req.user).catch((err) => {
      console.error('[ReportController] PDF generation failed:', err.message);
    });
  } catch (err) {
    next(err);
  }
}

/* ── PDF Generation Worker ───────────────────────────────────── */
async function generatePDF(report, user) {
  const filePath = path.join(REPORTS_DIR, `${report._id}.pdf`);

  try {
    // Gather data
    let threats   = [];
    let incident  = null;

    if (report.incidentId) {
      incident = await Incident.findById(report.incidentId).lean();
      if (incident) {
        threats = await Threat.find({ _id: { $in: incident.threatIds } }).lean();
      }
    } else if (report.timeRange) {
      threats = await Threat.find({
        userId:    user._id,
        createdAt: { $gte: report.timeRange.from, $lte: report.timeRange.to },
      }).sort('-createdAt').lean();
    }

    // Build PDF
    await new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50, size: 'A4' });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // ── Header ──────────────────────────────────────────────
      doc.fontSize(20).fillColor('#0ea5e9').text('🛡️  RAKSHAK LIVE SOC', { align: 'center' });
      doc.moveDown(0.3);
      doc.fontSize(14).fillColor('#1e293b').text(report.title, { align: 'center' });
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor('#64748b')
         .text(`Generated: ${new Date().toUTCString()}  |  Analyst: ${user.email}`, { align: 'center' });

      doc.moveDown(1);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e2e8f0').lineWidth(1).stroke();
      doc.moveDown(1);

      // ── Executive Summary ────────────────────────────────────
      doc.fontSize(13).fillColor('#0f172a').text('Executive Summary');
      doc.moveDown(0.4);
      doc.fontSize(9).fillColor('#334155');

      if (incident) {
        doc.text(`Incident: ${incident.title}`);
        doc.text(`Severity: ${incident.severity.toUpperCase()}`);
        doc.text(`Status: ${incident.status}`);
        if (incident.summary) doc.moveDown(0.3).text(incident.summary);
      } else {
        const from = new Date(report.timeRange.from).toLocaleDateString();
        const to   = new Date(report.timeRange.to).toLocaleDateString();
        doc.text(`Time Range: ${from} → ${to}`);
        doc.text(`Total Threats: ${threats.length}`);

        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const t of threats) bySeverity[t.severity] = (bySeverity[t.severity] || 0) + 1;
        doc.text(`Severity Breakdown: Critical(${bySeverity.critical}) High(${bySeverity.high}) Medium(${bySeverity.medium}) Low(${bySeverity.low}) Info(${bySeverity.info})`);
      }

      doc.moveDown(1.5);

      // ── Threat Findings ──────────────────────────────────────
      if (threats.length > 0) {
        doc.fontSize(13).fillColor('#0f172a').text('Threat Findings');
        doc.moveDown(0.5);

        for (const [i, threat] of threats.entries()) {
          if (doc.y > 700) doc.addPage();

          const severityColor = {
            critical: '#ef4444',
            high:     '#f97316',
            medium:   '#eab308',
            low:      '#22c55e',
            info:     '#3b82f6',
          }[threat.severity] || '#64748b';

          doc.fontSize(10).fillColor(severityColor)
             .text(`[${threat.severity.toUpperCase()}] ${threat.type}`, { continued: false });

          doc.fontSize(8).fillColor('#475569');
          if (threat.source?.ip)       doc.text(`  Source IP: ${threat.source.ip}`);
          if (threat.source?.hostname) doc.text(`  Hostname:  ${threat.source.hostname}`);
          if (threat.description)      doc.text(`  ${threat.description}`);
          doc.text(`  Detected: ${new Date(threat.createdAt).toUTCString()}`);

          if (i < threats.length - 1) {
            doc.moveDown(0.3);
            doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#f1f5f9').lineWidth(0.5).stroke();
            doc.moveDown(0.3);
          }
        }
      } else {
        doc.fontSize(9).fillColor('#94a3b8').text('No threat findings in this scope.');
      }

      // ── MITRE Techniques ─────────────────────────────────────
      if (incident?.mitreTechniques?.length > 0) {
        doc.moveDown(1.5);
        doc.fontSize(13).fillColor('#0f172a').text('MITRE ATT&CK Techniques Observed');
        doc.moveDown(0.4);
        doc.fontSize(9).fillColor('#334155')
           .text(incident.mitreTechniques.join(', '));
      }

      // ── Footer ───────────────────────────────────────────────
      doc.moveDown(3);
      doc.fontSize(7).fillColor('#94a3b8')
         .text('This report was generated automatically by Eye Live SOC. Handle as CONFIDENTIAL.',
               { align: 'center' });

      doc.end();
      stream.on('finish', resolve);
      stream.on('error', reject);
    });

    const stat = fs.statSync(filePath);
    await Report.findByIdAndUpdate(report._id, {
      status:   'done',
      filePath,
      fileSize: stat.size,
    });

    console.log(`[ReportController] PDF generated: ${filePath} (${stat.size} bytes)`);
  } catch (err) {
    await Report.findByIdAndUpdate(report._id, {
      status: 'failed',
      error:  err.message,
    });
    throw err;
  }
}

/* ── GET /api/reports/:id/download ──────────────────────────── */
export async function downloadReport(req, res, next) {
  try {
    const report = await Report.findOne({
      _id:    req.params.id,
      userId: req.user._id,
    });

    if (!report) {
      return res.status(404).json({ status: 'error', message: 'Report not found.' });
    }
    if (report.status !== 'done' || !report.filePath) {
      return res.status(409).json({
        status:  'error',
        message: `Report is not ready (status: ${report.status}).`,
      });
    }
    if (!fs.existsSync(report.filePath)) {
      return res.status(410).json({ status: 'error', message: 'Report file no longer exists.' });
    }

    const fileName = `${report.title.replace(/[^a-z0-9]/gi, '_')}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    fs.createReadStream(report.filePath).pipe(res);
  } catch (err) {
    next(err);
  }
}

/* ── DELETE /api/reports/:id ─────────────────────────────────── */
export async function deleteReport(req, res, next) {
  try {
    const report = await Report.findOneAndDelete({
      _id:    req.params.id,
      userId: req.user._id,
    });

    if (!report) {
      return res.status(404).json({ status: 'error', message: 'Report not found.' });
    }

    // Clean up file if it exists
    if (report.filePath && fs.existsSync(report.filePath)) {
      fs.unlinkSync(report.filePath);
    }

    return res.status(200).json({ status: 'success', message: 'Report deleted.' });
  } catch (err) {
    next(err);
  }
}
