/**
 * activityController.js — Host and User Activity Telemetry Controller
 *
 * Exposes endpoints to query, filter, and inspect continuous host activity.
 */
import HostActivity from '../models/HostActivity.js';
import { generateActivitySuggestions, generateSecurityResponse } from '../services/aiService.js';

const PAGE_SIZE = 50;

/**
 * GET /api/activities
 * Query parameters:
 *   - page: integer (default: 1)
 *   - limit: integer (default: 50, max: 200)
 *   - source: 'process' | 'network' | 'log' | 'shell'
 *   - isThreat: 'true' | 'false'
 *   - search: text search in description, entity, actor
 *   - dateFrom, dateTo: ISO date strings
 */
export async function listActivities(req, res, next) {
  try {
    const {
      page = 1,
      limit = PAGE_SIZE,
      source,
      isThreat,
      search,
      dateFrom,
      dateTo,
    } = req.query;

    const filter = { userId: req.user._id };

    if (source) {
      filter.source = source;
    }

    if (isThreat !== undefined) {
      filter.isThreat = isThreat === 'true';
    }

    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo)   filter.createdAt.$lte = new Date(dateTo);
    }

    if (search && search.trim()) {
      const term = search.trim();
      const regex = new RegExp(term, 'i');
      filter.$or = [
        { description: regex },
        { entity: regex },
        { actor: regex },
        { ip: regex },
      ];
    }

    const pageNum  = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10)));
    const skip     = (pageNum - 1) * limitNum;

    const [activities, total] = await Promise.all([
      HostActivity.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      HostActivity.countDocuments(filter),
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        activities,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          totalPages: Math.ceil(total / limitNum),
        },
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/activities/stats
 * Returns activity breakdown for the user's host.
 */
export async function getActivityStats(req, res, next) {
  try {
    const userId = req.user._id;
    const past24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [total24h, processCount, networkCount, logCount, threatCount] = await Promise.all([
      HostActivity.countDocuments({ userId, createdAt: { $gte: past24Hours } }),
      HostActivity.countDocuments({ userId, source: 'process', createdAt: { $gte: past24Hours } }),
      HostActivity.countDocuments({ userId, source: 'network', createdAt: { $gte: past24Hours } }),
      HostActivity.countDocuments({ userId, source: 'log', createdAt: { $gte: past24Hours } }),
      HostActivity.countDocuments({ userId, isThreat: true, createdAt: { $gte: past24Hours } }),
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        total24h,
        processCount,
        networkCount,
        logCount,
        threatCount,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * DELETE /api/activities
 * Purges activity log for the current user.
 */
export async function clearActivities(req, res, next) {
  try {
    const result = await HostActivity.deleteMany({ userId: req.user._id });
    return res.status(200).json({
      status: 'success',
      message: `Cleared ${result.deletedCount} activity records.`,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/activities/suggestions (or /api/activities/:id/suggestions)
 * Generates security assessment, suggestions, and 1-click commands.
 */
export async function getActivitySuggestions(req, res, next) {
  try {
    let activity = req.body?.activity;

    if (req.params?.id) {
      activity = await HostActivity.findOne({ _id: req.params.id, userId: req.user._id }).lean();
      if (!activity) {
        return res.status(404).json({ status: 'error', message: 'Activity not found' });
      }
    }

    if (!activity) {
      return res.status(400).json({ status: 'error', message: 'Activity payload required' });
    }

    const suggestions = await generateActivitySuggestions({ activity });

    // Optional follow-up question
    let aiAnswer = null;
    if (req.body?.question && req.body.question.trim()) {
      const prompt = `Context: The user is asking about this host activity on their machine:
Source: ${activity.source}
Action: ${activity.action}
Description: ${activity.description}
Actor: ${activity.actor || 'system'}
Remote IP: ${activity.ip || 'none'}
Metadata: ${JSON.stringify(activity.metadata || {})}

User Question: ${req.body.question.trim()}
Provide concise, actionable, and technical security guidance.`;

      const aiRes = await generateSecurityResponse({
        messages: [{ role: 'user', content: prompt }],
      });
      aiAnswer = aiRes.content;
    }

    return res.status(200).json({
      status: 'success',
      data: {
        ...suggestions,
        aiAnswer,
      },
    });
  } catch (err) {
    next(err);
  }
}
