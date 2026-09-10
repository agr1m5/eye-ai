/**
 * defenseRoutes.js — SOAR Active Defense routes.
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  executeContainment,
  listDefenseActions,
  releaseDefenseAction,
} from '../controllers/defenseController.js';

const router = Router();

router.use(protect);

router.post('/contain',      executeContainment);
router.get('/actions',       listDefenseActions);
router.post('/:id/release',  releaseDefenseAction);

export default router;
