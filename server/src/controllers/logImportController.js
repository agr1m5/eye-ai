/**
 * logImportController.js — Manual log file import & analysis.
 *
 * Upload pipeline:
 *   1. Analyst uploads a .log / .txt / .json / .csv file via multipart form.
 *   2. Multer saves it to server/uploads/.
 *   3. An ImportedLog document is created with status = 'uploaded'.
 *   4. Background analysis runs: parses lines, detects patterns, creates Threats.
 *   5. ImportedLog status updated to 'done' with threatCount.
 *
 * Routes:
 *   POST /api/logs/upload    — upload + trigger analysis
 *   GET  /api/logs           — list uploaded logs
 *   GET  /api/logs/:id/threats — threats extracted from a log
 */
import path   from 'path';
import fs     from 'fs';
import { fileURLToPath } from 'url';

import ImportedLog from '../models/ImportedLog.js';
import Threat      from '../models/Threat.js';
import { resolveGeo } from '../services/geoService.js';

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const UPLOADS_DIR = path.resolve(__dirname, '../../uploads');

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

/* ── POST /api/logs/upload ───────────────────────────────────── */
export async function uploadLog(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({ status: 'error', message: 'No file uploaded.' });
    }

    const importedLog = new ImportedLog({
      userId:       req.user._id,
      originalName: req.file.originalname,
      filePath:     req.file.path,
      fileSize:     req.file.size,
      mimeType:     req.file.mimetype,
      status:       'uploaded',
    });
    await importedLog.save();

    // Return immediately and analyse in background
    res.status(202).json({ status: 'success', data: importedLog });

    analyzeLog(importedLog, req.user._id).catch((err) => {
      console.error('[LogImport] Analysis error:', err.message);
    });
  } catch (err) {
    next(err);
  }
}

/* ── Log Analysis Engine ─────────────────────────────────────── */
const THREAT_PATTERNS = [
  {
    pattern:  /(\bfailed password\b|\bfailed login\b|\binvalid password\b|\bauthentication failure\b)/i,
    type:     'Brute Force Attempt',
    severity: 'high',
    desc:     'Multiple failed authentication attempts detected.',
  },
  {
    pattern:  /(\bsql\s*injection\b|\bunion\s+select\b|\bor\s+1\s*=\s*1\b|' OR '|1=1)/i,
    type:     'SQL Injection Attempt',
    severity: 'critical',
    desc:     'SQL injection payload pattern found in log.',
  },
  {
    pattern:  /(\bxss\b|<script\b|javascript:\s*alert|onerror\s*=)/i,
    type:     'XSS Attempt',
    severity: 'high',
    desc:     'Cross-site scripting payload detected.',
  },
  {
    pattern:  /(\bport scan\b|\bnmap\b|\bsyn scan\b|connect\(\) to .+ failed)/i,
    type:     'Port Scan',
    severity: 'medium',
    desc:     'Network reconnaissance / port scanning activity detected.',
  },
  {
    pattern:  /(\bransomware\b|\bencrypted\b.*\bfiles\b|\b\.locked\b|\b\.encrypted\b)/i,
    type:     'Ransomware Activity',
    severity: 'critical',
    desc:     'Indicators of ransomware execution found.',
  },
  {
    pattern:  /(\bmalware\b|\btrojan\b|\bbackdoor\b|\brootkit\b|\bkeylogger\b)/i,
    type:     'Malware Detection',
    severity: 'critical',
    desc:     'Malware-related keyword in log.',
  },
  {
    pattern:  /(\bcommand injection\b|;.*(id|whoami|ls|cat \/etc)\b|\b\$\(.*\)|\`.*\`)/i,
    type:     'Command Injection',
    severity: 'critical',
    desc:     'OS command injection attempt detected.',
  },
  {
    pattern:  /(\bpath traversal\b|\.\.\/|\.\.\\|\%2e\%2e)/i,
    type:     'Path Traversal',
    severity: 'high',
    desc:     'Directory traversal attempt in log.',
  },
  {
    pattern:  /(\bddos\b|\bflood\b|\bhigh volume\b|\brate limit exceeded\b|\btoo many requests\b)/i,
    type:     'DDoS / Flood',
    severity: 'high',
    desc:     'Signs of denial-of-service attack.',
  },
  {
    pattern:  /(\bprivilege escalation\b|\bsudo\b.*(NOPASSWD|ALL=ALL)|\bsetuid\b|\bchmod\s+[47]77\b)/i,
    type:     'Privilege Escalation',
    severity: 'high',
    desc:     'Privilege escalation attempt detected.',
  },
];

// Extract IPs from a log line
function extractIP(line) {
  const match = line.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : null;
}

async function analyzeLog(importedLog, userId) {
  try {
    await ImportedLog.findByIdAndUpdate(importedLog._id, { status: 'processing' });

    const content = fs.readFileSync(importedLog.filePath, 'utf8');
    const lines   = content.split('\n').filter((l) => l.trim().length > 0);

    const threats = [];

    for (const line of lines) {
      for (const { pattern, type, severity, desc } of THREAT_PATTERNS) {
        if (pattern.test(line)) {
          const sourceIP = extractIP(line);
          const geo = await resolveGeo(sourceIP, `${type}-${line.slice(0, 30)}`);
          threats.push({
            userId,
            severity,
            type,
            source:        { ip: sourceIP },
            geo,
            description:   `${desc}\n\nSource line: ${line.slice(0, 300)}`,
            status:        'new',
            fromImport:    true,
            importedLogId: importedLog._id,
          });
          break; // One match per line
        }
      }
    }

    if (threats.length > 0) {
      await Threat.insertMany(threats);
    }

    await ImportedLog.findByIdAndUpdate(importedLog._id, {
      status:      'done',
      threatCount: threats.length,
    });

    console.log(`[LogImport] Analysed ${lines.length} lines → ${threats.length} threats (log: ${importedLog._id})`);
  } catch (err) {
    await ImportedLog.findByIdAndUpdate(importedLog._id, {
      status: 'failed',
      error:  err.message,
    });
    throw err;
  }
}

/* ── GET /api/logs ────────────────────────────────────────────── */
export async function listLogs(req, res, next) {
  try {
    const logs = await ImportedLog.find({ userId: req.user._id })
      .sort('-createdAt')
      .lean();

    return res.status(200).json({ status: 'success', data: logs });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/logs/:id/threats ───────────────────────────────── */
export async function getLogThreats(req, res, next) {
  try {
    const log = await ImportedLog.findOne({
      _id:    req.params.id,
      userId: req.user._id,
    });

    if (!log) {
      return res.status(404).json({ status: 'error', message: 'Log not found.' });
    }

    const threats = await Threat.find({
      importedLogId: log._id,
      userId:        req.user._id,
    }).sort('-createdAt').lean();

    return res.status(200).json({ status: 'success', data: threats });
  } catch (err) {
    next(err);
  }
}
