import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.resolve(__dirname, '../../logs');
const LOG_FILE = path.join(LOG_DIR, 'enforcement-audit.log');

// Ensure log directory exists
try {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
} catch (err) {
  console.warn('[AuditLogger] Could not create logs directory:', err.message);
}

/**
 * Log an OS-level enforcement event to the local audit trail.
 *
 * @param {Object} entry
 * @param {string} entry.actionType - 'isolate_host' | 'release_host' | 'quarantine_file' | 'release_file'
 * @param {string} entry.target - Target PID, host, or file path
 * @param {boolean} entry.success - Whether execution succeeded
 * @param {string} [entry.command] - Exact shell command or API executed
 * @param {number|null} [entry.exitCode] - Subprocess exit code
 * @param {string} [entry.output] - Stderr or verification message
 * @param {Object} [entry.metadata] - Extra context (hashes, manifest IDs)
 */
export function logEnforcement(entry) {
  const record = {
    timestamp: new Date().toISOString(),
    pid: process.pid,
    uid: process.getuid ? process.getuid() : null,
    platform: process.platform,
    ...entry,
  };

  const line = JSON.stringify(record) + '\n';

  try {
    fs.appendFileSync(LOG_FILE, line, 'utf8');
  } catch (err) {
    console.error('[AuditLogger] Failed to write to audit log:', err.message);
  }
}

export function getAuditLogPath() {
  return LOG_FILE;
}
