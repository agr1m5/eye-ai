/**
 * Audit Routes
 *
 * GET  /api/audit — paginated analyst audit log (protected)
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import { listAuditLog } from '../controllers/auditController.js';

const router = Router();

router.use(protect);
router.get('/', listAuditLog);

export default router;
