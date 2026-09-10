/**
 * incidentController.js — Correlated incident management.
 *
 * Routes:
 *   GET    /api/incidents          — paginated list with filters
 *   GET    /api/incidents/:id      — single incident with populated threats
 *   PATCH  /api/incidents/:id/status — update status
 *   POST   /api/incidents          — manually create an incident
 */
import Incident from '../models/Incident.js';
import Threat   from '../models/Threat.js';
import { createAuditEntry } from '../services/auditService.js';

const PAGE_SIZE = 20;

/* ── GET /api/incidents ───────────────────────────────────────── */
export async function listIncidents(req, res, next) {
  try {
    const {
      page     = 1,
      limit    = PAGE_SIZE,
      status,
      severity,
      sort     = '-createdAt',
    } = req.query;

    const filter = { userId: req.user._id };
    if (status)   filter.status   = status;
    if (severity) filter.severity = severity;

    const pageNum  = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const skip     = (pageNum - 1) * limitNum;

    const [incidents, total] = await Promise.all([
      Incident.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Incident.countDocuments(filter),
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        incidents,
        pagination: {
          page:       pageNum,
          limit:      limitNum,
          total,
          totalPages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/incidents/:id ───────────────────────────────────── */
export async function getIncident(req, res, next) {
  try {
    const incident = await Incident.findOne({
      _id:    req.params.id,
      userId: req.user._id,
    }).lean();

    if (!incident) {
      return res.status(404).json({ status: 'error', message: 'Incident not found.' });
    }

    // Populate threats
    const threats = await Threat.find({
      _id: { $in: incident.threatIds },
    }).lean();

    return res.status(200).json({
      status: 'success',
      data:   { ...incident, threats },
    });
  } catch (err) {
    next(err);
  }
}

/* ── PATCH /api/incidents/:id/status ─────────────────────────── */
export async function updateIncidentStatus(req, res, next) {
  try {
    const { status } = req.body;
    const allowed = ['open', 'investigating', 'resolved', 'closed'];
    if (!allowed.includes(status)) {
      return res.status(400).json({
        status:  'error',
        message: `Status must be one of: ${allowed.join(', ')}.`,
      });
    }

    const incident = await Incident.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { status },
      { new: true, runValidators: true }
    );

    if (!incident) {
      return res.status(404).json({ status: 'error', message: 'Incident not found.' });
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     'incident.status_changed',
      targetType: 'Incident',
      targetId:   incident._id,
      metadata:   { newStatus: status, title: incident.title, severity: incident.severity },
      ip:         req.ip,
    });

    return res.status(200).json({ status: 'success', data: incident });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/incidents — manual creation ────────────────────── */
export async function createIncident(req, res, next) {
  try {
    const { title, severity, threatIds = [], summary, notes, mitreTechniques = [] } = req.body;

    if (!title) {
      return res.status(400).json({ status: 'error', message: 'Title is required.' });
    }

    const incident = new Incident({
      userId: req.user._id,
      title,
      severity:        severity || 'info',
      threatIds,
      summary:         summary  || '',
      notes:           notes    || '',
      mitreTechniques,
    });

    await incident.save();

    // Link threats back to this incident
    if (threatIds.length > 0) {
      await Threat.updateMany(
        { _id: { $in: threatIds }, userId: req.user._id },
        { incidentId: incident._id }
      );
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     'incident.created',
      targetType: 'Incident',
      targetId:   incident._id,
      metadata:   { title: incident.title, severity: incident.severity },
      ip:         req.ip,
    });

    return res.status(201).json({ status: 'success', data: incident });
  } catch (err) {
    next(err);
  }
}

/* ── PATCH /api/incidents/:id/notes ─────────────────────────── */
export async function updateIncidentNotes(req, res, next) {
  try {
    const { notes } = req.body;

    const incident = await Incident.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { notes },
      { new: true }
    );

    if (!incident) {
      return res.status(404).json({ status: 'error', message: 'Incident not found.' });
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     'incident.notes_updated',
      targetType: 'Incident',
      targetId:   incident._id,
      metadata:   { title: incident.title },
      ip:         req.ip,
    });

    return res.status(200).json({ status: 'success', data: incident });
  } catch (err) {
    next(err);
  }
}
