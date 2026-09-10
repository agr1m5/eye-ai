/**
 * Log Import Routes
 *
 * POST /api/logs/upload    — upload log file (multipart/form-data, field: 'logfile')
 * GET  /api/logs           — list all imported logs for the user
 * GET  /api/logs/:id/threats — threats extracted from a specific log
 *
 * All routes require a valid analyst JWT.
 */
import { Router }  from 'express';
import multer      from 'multer';
import path        from 'path';
import { fileURLToPath } from 'url';
import { protect } from '../middleware/auth.js';
import {
  uploadLog,
  listLogs,
  getLogThreats,
} from '../controllers/logImportController.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const UPLOADS_DIR = path.resolve(__dirname, '../../uploads');

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename:    (_req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${unique}-${file.originalname}`);
  },
});

const ALLOWED_MIMES = [
  'text/plain',
  'application/json',
  'text/csv',
  'application/gzip',
  'application/x-gzip',
  'application/octet-stream',
];

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExt = ['.log', '.txt', '.json', '.csv', '.gz'];
    if (allowedExt.includes(ext) || ALLOWED_MIMES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only .log, .txt, .json, .csv, and .gz files are allowed.'));
    }
  },
});

const router = Router();

router.use(protect);

router.post('/upload',        upload.single('logfile'), uploadLog);
router.get('/',               listLogs);
router.get('/:id/threats',    getLogThreats);

export default router;
