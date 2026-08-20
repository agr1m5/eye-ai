/**
 * Agent Routes — Step 5
 *
 * POST   /api/agent/pair    — generate a one-time pairing token
 * DELETE /api/agent/pair    — revoke the current pairing token
 * GET    /api/agent/status  — return current pairing status
 *
 * All routes require a valid analyst JWT (protect middleware).
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  pairAgent,
  revokeAgent,
  getAgentStatus,
  pairValidation,
} from '../controllers/agentController.js';

const router = Router();

// All agent routes require authentication
router.use(protect);

router.post(  '/pair',   pairValidation, pairAgent);
router.delete('/pair',                   revokeAgent);
router.get(   '/status',                 getAgentStatus);

export default router;
