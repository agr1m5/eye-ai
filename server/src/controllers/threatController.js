/**
 * threatController.js — Threat CRUD for Rakshak Live SOC.
 *
 * Routes:
 *   GET    /api/threats           — paginated list with filters
 *   GET    /api/threats/:id       — single threat detail
 *   PATCH  /api/threats/:id/status — acknowledge or dismiss
 *   DELETE /api/threats/:id       — dismiss (soft: set status='dismissed')
 */
import Threat from '../models/Threat.js';
import { createAuditEntry } from '../services/auditService.js';
import { getIO } from '../config/socket.js';
import { correlateFinding } from '../services/correlationService.js';

const PAGE_SIZE = 25;

/* ── GET /api/threats ─────────────────────────────────────────── */
export async function listThreats(req, res, next) {
  try {
    const {
      page     = 1,
      limit    = PAGE_SIZE,
      severity,
      status,
      sort     = '-createdAt',
      q,
      dateFrom,
      dateTo,
    } = req.query;

    const filter = { userId: req.user._id };
    if (severity) filter.severity = severity;
    if (status)   filter.status   = status;

    // Full-text search across type, description, source fields
    if (q && q.trim()) {
      const regex = new RegExp(q.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [
        { type:                   regex },
        { description:            regex },
        { 'source.ip':            regex },
        { 'source.hostname':      regex },
        { 'source.processName':   regex },
      ];
    }

    // Date range filter
    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo)   filter.createdAt.$lte = new Date(dateTo);
    }

    const pageNum  = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10)));
    const skip     = (pageNum - 1) * limitNum;

    const [threats, total] = await Promise.all([
      Threat.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Threat.countDocuments(filter),
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        threats,
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

/* ── GET /api/threats/:id ─────────────────────────────────────── */
export async function getThreat(req, res, next) {
  try {
    const threat = await Threat.findOne({
      _id:    req.params.id,
      userId: req.user._id,
    }).lean();

    if (!threat) {
      return res.status(404).json({ status: 'error', message: 'Threat not found.' });
    }

    return res.status(200).json({ status: 'success', data: threat });
  } catch (err) {
    next(err);
  }
}

/* ── PATCH /api/threats/:id/status ───────────────────────────── */
export async function updateThreatStatus(req, res, next) {
  try {
    const { status } = req.body;
    const allowed = ['new', 'acknowledged', 'dismissed'];
    if (!allowed.includes(status)) {
      return res.status(400).json({
        status:  'error',
        message: `Status must be one of: ${allowed.join(', ')}.`,
      });
    }

    const threat = await Threat.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { status },
      { new: true }
    );

    if (!threat) {
      return res.status(404).json({ status: 'error', message: 'Threat not found.' });
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     status === 'acknowledged' ? 'threat.acknowledged' : 'threat.dismissed',
      targetType: 'Threat',
      targetId:   threat._id,
      metadata:   { newStatus: status, type: threat.type, severity: threat.severity },
      ip:         req.ip,
    });

    return res.status(200).json({ status: 'success', data: threat });
  } catch (err) {
    next(err);
  }
}

/* ── DELETE /api/threats/:id — dismiss ───────────────────────── */
export async function dismissThreat(req, res, next) {
  try {
    const threat = await Threat.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { status: 'dismissed' },
      { new: true }
    );

    if (!threat) {
      return res.status(404).json({ status: 'error', message: 'Threat not found.' });
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     'threat.dismissed',
      targetType: 'Threat',
      targetId:   threat._id,
      metadata:   { newStatus: 'dismissed', type: threat.type },
      ip:         req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: 'Threat dismissed.',
      data:    threat,
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/threats/stats — severity distribution ──────────── */
export async function getThreatStats(req, res, next) {
  try {
    const stats = await Threat.aggregate([
      { $match: { userId: req.user._id } },
      {
        $group: {
          _id:   '$severity',
          count: { $sum: 1 },
        },
      },
    ]);

    const result = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const s of stats) {
      result[s._id] = s.count;
    }

    return res.status(200).json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/threats/timeline — per-minute event rate ───────── */
export async function getThreatTimeline(req, res, next) {
  try {
    const windowMins = Math.min(120, Math.max(5, parseInt(req.query.window || '60', 10)));
    const since = new Date(Date.now() - windowMins * 60 * 1000);

    const buckets = await Threat.aggregate([
      {
        $match: {
          userId:    req.user._id,
          createdAt: { $gte: since },
        },
      },
      {
        $group: {
          _id: {
            // Truncate to the minute
            year:   { $year:   '$createdAt' },
            month:  { $month:  '$createdAt' },
            day:    { $dayOfMonth: '$createdAt' },
            hour:   { $hour:   '$createdAt' },
            minute: { $minute: '$createdAt' },
          },
          count:    { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          high:     { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1, '_id.minute': 1 } },
    ]);

    // Normalise into a flat array of { timestamp, count, critical, high }
    const timeline = buckets.map((b) => ({
      timestamp: new Date(
        b._id.year,
        b._id.month - 1,
        b._id.day,
        b._id.hour,
        b._id.minute,
      ).toISOString(),
      count:    b.count,
      critical: b.critical,
      high:     b.high,
    }));

    return res.status(200).json({ status: 'success', data: { timeline, windowMins } });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/threats/simulate — Red Team Drill Simulator ─────── */
export async function simulateThreat(req, res, next) {
  try {
    const {
      type = 'simulated_attack',
      severity = 'critical',
      description = 'Simulated Red Team Drill',
      ip = '185.193.65.19',
      country = 'Russia',
      city = 'Moscow',
      isp = 'Rostelecom AS12389',
      lat = 55.7558,
      lon = 37.6173,
      process = 'drill_payload.exe',
      pid = 8821,
    } = req.body;

    const threat = new Threat({
      userId: req.user._id,
      severity,
      type,
      source: {
        ip,
        processName: process,
        pid,
      },
      geo: {
        country,
        city,
        isp,
        lat: Number(lat) || 0,
        lon: Number(lon) || 0,
      },
      description,
      rawData: { drill: true, simulatedAt: new Date() },
      status: 'new',
      fromImport: false,
    });

    await threat.save();

    createAuditEntry({
      userId: req.user._id,
      action: 'defense.drill_simulated',
      targetType: 'Threat',
      targetId: threat._id,
      metadata: { type, severity, ip, process, pid },
      ip: req.ip,
    });

    try {
      const io = getIO();
      const clientRoom = `user:${req.user._id}`;
      io.of('/').to(clientRoom).emit('finding:new', threat.toObject());
      await correlateFinding(threat, req.user._id, io.of('/'), clientRoom);
    } catch (socketErr) {
      console.warn('[simulateThreat] Socket broadcast warning:', socketErr.message);
    }

    return res.status(201).json({ status: 'success', data: threat });
  } catch (err) {
    next(err);
  }
}

