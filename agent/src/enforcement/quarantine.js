import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logEnforcement } from './auditLogger.js';

// System directories that must never be targeted for quarantine (defense against disruption)
const FORBIDDEN_ROOTS = [
  '/',
  '/bin',
  '/sbin',
  '/usr',
  '/usr/bin',
  '/usr/sbin',
  '/etc',
  '/dev',
  '/proc',
  '/sys',
  '/System',
  '/Library',
  '/Applications',
];

/**
 * Get or initialize the quarantine vault directory.
 */
export function getQuarantineDir() {
  const primaryDir = '/var/lib/eye-agent/quarantine';
  const fallbackDir = path.join(process.env.HOME || '/tmp', '.eye/quarantine');

  try {
    if (!fs.existsSync(primaryDir)) {
      fs.mkdirSync(primaryDir, { recursive: true });
    }
    return primaryDir;
  } catch {
    if (!fs.existsSync(fallbackDir)) {
      fs.mkdirSync(fallbackDir, { recursive: true });
    }
    return fallbackDir;
  }
}

function getManifestPath() {
  return path.join(getQuarantineDir(), 'quarantine-manifest.json');
}

function loadManifest() {
  const manifestPath = getManifestPath();
  if (!fs.existsSync(manifestPath)) return {};
  try {
    return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    return {};
  }
}

function saveManifest(manifest) {
  const manifestPath = getManifestPath();
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
}

/**
 * Validate that a filePath is clean, absolute, and not attempting path traversal or targeting system roots.
 */
export function validateFilePath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') {
    return { valid: false, error: 'filePath must be a non-empty string.' };
  }

  const clean = rawPath.trim();

  // 1. Must be absolute path
  if (!path.isAbsolute(clean)) {
    return {
      valid: false,
      error: `Path must be absolute. Relative paths are rejected: "${clean}"`,
    };
  }

  // 2. Reject path traversal
  if (clean.includes('..')) {
    return {
      valid: false,
      error: `Path traversal sequence ".." is strictly rejected: "${clean}"`,
    };
  }

  // 3. Normalize path
  const resolved = path.resolve(clean);

  // 4. Reject critical OS roots
  const normalized = path.normalize(resolved);
  if (FORBIDDEN_ROOTS.includes(normalized)) {
    return {
      valid: false,
      error: `Security violation: Cannot quarantine critical system path: "${normalized}"`,
    };
  }

  return { valid: true, path: resolved };
}

/**
 * Move a suspicious file into the non-executable quarantine vault, compute its sha256 hash,
 * strip execution bits (chmod 0400), and write a manifest entry for audit and restoration.
 *
 * @param {string} rawFilePath - Path of file to quarantine
 * @param {string} [actionId] - Correlated SOAR defense action ID
 * @returns {Promise<{ success: boolean, output: string, hash?: string, quarantinePath?: string }>}
 */
export async function quarantineFile(rawFilePath, actionId = null) {
  // 1. Validate file path & path traversal checks
  const val = validateFilePath(rawFilePath);
  if (!val.valid) {
    logEnforcement({
      actionType: 'quarantine_file',
      target: rawFilePath,
      success: false,
      output: val.error,
    });
    return { success: false, output: val.error };
  }

  const filePath = val.path;

  // 2. Verify file exists and is a regular file
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (err) {
    const errorMsg = `Quarantine error: Target file does not exist or inaccessible: "${filePath}" (${err.message})`;
    logEnforcement({ actionType: 'quarantine_file', target: filePath, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  if (!stat.isFile()) {
    const errorMsg = `Quarantine error: Target is not a regular file (directories/devices cannot be vaulted): "${filePath}"`;
    logEnforcement({ actionType: 'quarantine_file', target: filePath, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  // 3. Compute SHA256 hash before touching the file
  let hash;
  try {
    const fileBuffer = fs.readFileSync(filePath);
    hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  } catch (err) {
    const errorMsg = `Quarantine error: Failed to compute hash for file: "${filePath}" (${err.message})`;
    logEnforcement({ actionType: 'quarantine_file', target: filePath, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  // 4. Prepare vault destination
  const qDir = getQuarantineDir();
  const fileBaseName = path.basename(filePath);
  const safeVaultName = `${Date.now()}_${hash.slice(0, 10)}_${fileBaseName}.vault`;
  const destPath = path.join(qDir, safeVaultName);

  // 5. Move file into vault (cross-device safe)
  try {
    try {
      fs.renameSync(filePath, destPath);
    } catch (renameErr) {
      if (renameErr.code === 'EXDEV') {
        fs.copyFileSync(filePath, destPath);
        fs.unlinkSync(filePath);
      } else {
        throw renameErr;
      }
    }

    // 6. Strip execution permissions (set read-only 0400)
    fs.chmodSync(destPath, 0o400);

    // 7. Record manifest entry
    const manifest = loadManifest();
    const manifestKey = actionId || hash;
    manifest[manifestKey] = {
      actionId: actionId || null,
      originalPath: filePath,
      quarantinePath: destPath,
      sha256: hash,
      originalMode: stat.mode,
      uid: stat.uid,
      gid: stat.gid,
      size: stat.size,
      quarantinedAt: new Date().toISOString(),
    };
    saveManifest(manifest);

    const successMsg = `File successfully quarantined in secure vault: ${filePath} (SHA256: ${hash}). Permissions stripped to 0400.`;
    logEnforcement({
      actionType: 'quarantine_file',
      target: filePath,
      success: true,
      output: successMsg,
      metadata: { sha256: hash, vaultPath: destPath },
    });

    return {
      success: true,
      output: successMsg,
      hash,
      quarantinePath: destPath,
    };
  } catch (err) {
    const errorMsg = `Quarantine error: Failed to move file to vault: ${err.message}`;
    logEnforcement({ actionType: 'quarantine_file', target: filePath, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }
}

/**
 * Restore a quarantined file back to its original path and permissions.
 *
 * @param {string} actionIdOrTarget - Action ID, target path, or hash
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function releaseFile(actionIdOrTarget) {
  const query = String(actionIdOrTarget || '').trim();
  const manifest = loadManifest();

  // Find matching manifest entry
  let foundKey = null;
  let entry = null;

  if (manifest[query]) {
    foundKey = query;
    entry = manifest[query];
  } else {
    for (const [k, v] of Object.entries(manifest)) {
      if (v.originalPath === query || v.actionId === query || v.sha256 === query) {
        foundKey = k;
        entry = v;
        break;
      }
    }
  }

  if (!entry || !fs.existsSync(entry.quarantinePath)) {
    const errorMsg = `Release failed: No active quarantined file found in manifest for "${query}".`;
    logEnforcement({ actionType: 'release_file', target: query, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  try {
    // 1. Ensure original directory exists
    const originalDir = path.dirname(entry.originalPath);
    if (!fs.existsSync(originalDir)) {
      fs.mkdirSync(originalDir, { recursive: true });
    }

    // 2. Make vault file writable to allow move
    fs.chmodSync(entry.quarantinePath, 0o600);

    // 3. Move file back to original location
    try {
      fs.renameSync(entry.quarantinePath, entry.originalPath);
    } catch (renameErr) {
      if (renameErr.code === 'EXDEV') {
        fs.copyFileSync(entry.quarantinePath, entry.originalPath);
        fs.unlinkSync(entry.quarantinePath);
      } else {
        throw renameErr;
      }
    }

    // 4. Restore original file mode and ownership
    if (entry.originalMode) {
      fs.chmodSync(entry.originalPath, entry.originalMode);
    }
    if (entry.uid !== undefined && entry.gid !== undefined && process.getuid && process.getuid() === 0) {
      try {
        fs.chownSync(entry.originalPath, entry.uid, entry.gid);
      } catch {}
    }

    // 5. Remove manifest entry
    delete manifest[foundKey];
    saveManifest(manifest);

    const successMsg = `File successfully restored from quarantine to original path: ${entry.originalPath}`;
    logEnforcement({ actionType: 'release_file', target: entry.originalPath, success: true, output: successMsg });
    return { success: true, output: successMsg };
  } catch (err) {
    const errorMsg = `Release failed: Could not restore file: ${err.message}`;
    logEnforcement({ actionType: 'release_file', target: entry?.originalPath || query, success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }
}
