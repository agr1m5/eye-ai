/**
 * Threat Intelligence Routes
 *
 * GET /api/ti/ip/:ip               — IP reputation lookup (VirusTotal / heuristic)
 * GET /api/ti/cve/:cveId           — CVE detail from NVD
 * GET /api/ti/mitre/:techniqueId   — MITRE ATT&CK technique detail
 * GET /api/ti/owasp/:category      — OWASP Top 10 category info
 *
 * All routes require a valid analyst JWT.
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  lookupIP,
  lookupCVE,
  lookupMITRE,
  lookupOWASP,
} from '../controllers/tiController.js';

const router = Router();

router.use(protect);

router.get('/ip/:ip',                 lookupIP);
router.get('/cve/:cveId',             lookupCVE);
router.get('/mitre/:techniqueId',     lookupMITRE);
router.get('/owasp/:category',        lookupOWASP);

export default router;
