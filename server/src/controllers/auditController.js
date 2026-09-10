/**
 * auditController.js — GET /api/audit
 *
 * Returns a paginated, filtered audit log for the authenticated analyst.
 * Read-only — audit entries are never modified or deleted via API.
 */
import AuditLog from '../models/AuditLog.js';

const PAGE_SIZE = 50;

/* ── GET /api/audit ──────────────────────────────────────────── */
export async function listAuditLog(req, res, next) {
  try {
    const {
      page       = 1,
      limit      = PAGE_SIZE,
      action,
      targetType,
      category,
      search,
      dateFrom,
      dateTo,
    } = req.query;

    const filter = { userId: req.user._id };

    // Action filter: exact match or prefix if ending with '.'
    if (action) {
      if (action.endsWith('.')) {
        filter.action = new RegExp(`^${action.slice(0, -1)}\\.`, 'i');
      } else {
        filter.action = action;
      }
    }

    // Category / TargetType mapping (case-insensitive & cross-mapped)
    const cat = (category || targetType || '').toLowerCase();
    if (cat) {
      if (cat === 'settings' || cat === 'user' || cat === 'preferences') {
        filter.$or = [
          { targetType: { $in: ['user', 'preferences', 'settings'] } },
          { action: /^settings\./i },
          { action: /^preferences\./i },
        ];
      } else if (cat === 'incident') {
        filter.$or = [
          { targetType: 'incident' },
          { action: /^incident\./i },
        ];
      } else if (cat === 'threat') {
        filter.$or = [
          { targetType: 'threat' },
          { action: /^threat\./i },
        ];
      } else if (cat === 'agent') {
        filter.$or = [
          { targetType: 'agent' },
          { action: /^agent\./i },
        ];
      } else if (cat === 'report') {
        filter.$or = [
          { targetType: 'report' },
          { action: /^report\./i },
        ];
      } else {
        filter.targetType = new RegExp(`^${cat}$`, 'i');
      }
    }

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      const searchOr = [
        { action: searchRegex },
        { targetType: searchRegex },
        { ip: searchRegex },
      ];
      if (filter.$or) {
        filter.$and = [{ $or: filter.$or }, { $or: searchOr }];
        delete filter.$or;
      } else {
        filter.$or = searchOr;
      }
    }

    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo)   filter.createdAt.$lte = new Date(dateTo);
    }

    const pageNum  = Math.max(1, parseInt(page,  10));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10)));
    const skip     = (pageNum - 1) * limitNum;

    const [entries, total] = await Promise.all([
      AuditLog.find(filter)
        .populate('userId', 'email role name')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      AuditLog.countDocuments(filter),
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        entries,
        logs: entries,
        pagination: {
          page:       pageNum,
          limit:      limitNum,
          total,
          totalPages: Math.ceil(total / limitNum) || 1,
        },
      },
    });
  } catch (err) {
    next(err);
  }
}
