/**
 * Threat Routes
 *
 * GET    /api/threats             — paginated list with filters
 * GET    /api/threats/stats       — severity distribution counts
 * GET    /api/threats/timeline    — per-minute event rate for last N minutes
 * GET    /api/threats/:id         — single threat detail
 * PATCH  /api/threats/:id/status  — update status (acknowledged/dismissed/new)
 * DELETE /api/threats/:id         — dismiss threat
 *
 * All routes require a valid analyst JWT.
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  listThreats,
  getThreat,
  updateThreatStatus,
  dismissThreat,
  getThreatStats,
  getThreatTimeline,
  simulateThreat,
} from '../controllers/threatController.js';

const router = Router();

// All threat routes require authentication
router.use(protect);

router.get('/',           listThreats);
router.post('/simulate',  simulateThreat);
router.get('/stats',      getThreatStats);
router.get('/timeline',   getThreatTimeline);
router.get('/:id',        getThreat);
router.patch('/:id/status', updateThreatStatus);
router.delete('/:id',     dismissThreat);

export default router;
