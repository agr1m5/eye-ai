/**
 * Report Routes
 *
 * GET    /api/reports               — list all reports
 * POST   /api/reports               — generate a new PDF report (async)
 * GET    /api/reports/:id/download  — stream the finished PDF
 * DELETE /api/reports/:id           — delete report + PDF file
 *
 * All routes require a valid analyst JWT.
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  listReports,
  generateReport,
  downloadReport,
  deleteReport,
} from '../controllers/reportController.js';

const router = Router();

router.use(protect);

router.get('/',                listReports);
router.post('/',               generateReport);
router.get('/:id/download',    downloadReport);
router.delete('/:id',          deleteReport);

export default router;
