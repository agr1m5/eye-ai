/**
 * activityRoutes.js — Endpoints for Host Activity Telemetry
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  listActivities,
  getActivityStats,
  clearActivities,
  getActivitySuggestions,
} from '../controllers/activityController.js';

const router = Router();

router.use(protect); // All activity endpoints require authentication

router.get('/', listActivities);
router.get('/stats', getActivityStats);
router.post('/suggestions', getActivitySuggestions);
router.post('/:id/suggestions', getActivitySuggestions);
router.delete('/', clearActivities);

export default router;
