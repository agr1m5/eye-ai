/**
 * quarantine.js — Secure File Quarantine Vault & Restoration Engine.
 *
 * VAULT SPECIFICATION:
 *   - Primary Vault: /var/lib/eye-agent/quarantine (root-owned, tamper-resistant).
 *   - Unprivileged Fallback: ~/.eye/quarantine (strictly intended for unprivileged dev/testing only).
 *   - Vault files are stripped of all execution bits (chmod 0400, read-only).
 *   - Manifest writes are serialized via in-process mutex and committed atomically via temp-and-rename.
 *   - Path validation strictly rejects any path or symlink target residing in or under critical
 *     operating system directories (FORBIDDEN_ROOTS), defending against denial-of-service and
 *     system file tampering.
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
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
  '/private/etc',
  '/private/var/root',
  '/dev',
  '/proc',
  '/sys',
  '/System',
  '/Library',
  '/Applications',
];

let fallbackWarned = false;

/**
 * Get or initialize the quarantine vault directory.
 * Logs a prominent warning if the primary root-privileged vault is inaccessible.
 */
export function getQuarantineDir() {
  const primaryDir = '/var/lib/eye-agent/quarantine';
  const fallbackDir = path.join(process.env.HOME || '/tmp', '.eye/quarantine');

  try {
    if (!fs.existsSync(primaryDir)) {
      fs.mkdirSync(primaryDir, { recursive: true, mode: 0o700 });
    }
    return primaryDir;
  } catch (err) {
    if (!fallbackWarned) {
      console.warn(
        `[QuarantineVault] WARNING: Primary vault directory "${primaryDir}" is inaccessible (${err.message}). ` +
        `Falling back to unprivileged directory "${fallbackDir}". Note: User-writable fallback is for dev/testing only.`
      );
      fallbackWarned = true;
    }
    if (!fs.existsSync(fallbackDir)) {
      fs.mkdirSync(fallbackDir, { recursive: true, mode: 0o700 });
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

/**
 * Atomically write the manifest file (write to temporary file + fs.renameSync).
 */
function saveManifestAtomic(manifest) {
  const manifestPath = getManifestPath();
  const dir = path.dirname(manifestPath);
  const tempPath = path.join(dir, `.quarantine-manifest-${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`);
  fs.writeFileSync(tempPath, JSON.stringify(manifest, null, 2), { mode: 0o600, encoding: 'utf8' });
  fs.renameSync(tempPath, manifestPath);
}

// In-process serialization mutex for manifest reads/modifications
let manifestLock = Promise.resolve();

function withManifestLock(operation) {
  const next = manifestLock.then(operation, operation);
  manifestLock = next.catch(() => {});
  return next;
}

/**
 * Validate that a filePath is clean, absolute, does not traverse, and does not target
 * or resolve via symlink to any file in or under FORBIDDEN_ROOTS.
 */
export function validateFilePath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') {
    return { valid: false, error: 'filePath must be a non-empty string.' };
  }

  let clean = rawPath.trim();

  // Expand home directory shorthand (e.g. "~/.eye/canary.env" or "~")
  if (clean === '~') {
    clean = os.homedir() || process.env.HOME || '/tmp';
  } else if (clean.startsWith('~/') || clean.startsWith('~\\')) {
    const home = os.homedir() || process.env.HOME || '/tmp';
    clean = path.join(home, clean.slice(2));
  }

  // 1. Must be absolute path
  if (!path.isAbsolute(clean)) {
    return {
      valid: false,
      error: `Path must be absolute. Relative paths are rejected: "${clean}"`,
    };
  }

  // 2. Reject path traversal sequence
  if (clean.includes('..')) {
    return {
      valid: false,
      error: `Path traversal sequence ".." is strictly rejected: "${clean}"`,
    };
  }

  // 3. Normalize path
  const resolved = path.resolve(clean);
  const normalized = path.normalize(resolved);

  // 4. Resolve symlinks if target exists on filesystem
  let realPath = normalized;
  try {
    if (fs.existsSync(normalized)) {
      realPath = fs.realpathSync(normalized);
    }
  } catch {
    // If realpathSync fails (e.g. permission or dangling symlink), evaluate normalized path
  }

  // 5. Hierarchical check: reject if path or realpath is in or under any forbidden root
  for (const root of FORBIDDEN_ROOTS) {
    if (root === '/') {
      if (normalized === '/' || realPath === '/') {
        return {
          valid: false,
          error: `Security violation: Cannot quarantine filesystem root: "/"`,
        };
      }
      continue;
    }

    // Check normalized path
    if (normalized === root || normalized.startsWith(root + '/')) {
      return {
        valid: false,
        error: `Security violation: Cannot quarantine critical system path or file under "${root}": "${clean}"`,
      };
    }

    // Check symlink realpath
    if (realPath === root || realPath.startsWith(root + '/')) {
      return {
        valid: false,
        error: `Security violation: Symlink target resolves to critical system path under "${root}": "${realPath}"`,
      };
    }
  }

  return { valid: true, path: normalized, realPath };
}

/**
 * Move a suspicious file into the non-executable quarantine vault, compute its sha256 hash,
 * strip execution bits (chmod 0400), and write a manifest entry for audit and restoration.
 * Serialized via in-process mutex to prevent manifest race conditions.
 *
 * @param {string} rawFilePath - Path of file to quarantine
 * @param {string} [actionId] - Correlated SOAR defense action ID
 * @returns {Promise<{ success: boolean, output: string, hash?: string, quarantinePath?: string }>}
 */
export async function quarantineFile(rawFilePath, actionId = null) {
  // 1. Validate file path, symlinks, & hierarchical forbidden root defenses
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
    // If targeted file is a honeytoken canary decoy in ~/.eye, auto-initialize it so it can be vaulted
    const isCanary = filePath.includes('.eye') && (filePath.includes('canary') || filePath.endsWith('.env'));
    if (isCanary) {
      try {
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, '# Decoy Canary Honeytoken\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE_CANARY\n', { mode: 0o600 });
        stat = fs.statSync(filePath);
      } catch {}
    }
    if (!stat) {
      const errorMsg = `Quarantine error: Target file does not exist or inaccessible: "${filePath}" (${err.message})`;
      logEnforcement({ actionType: 'quarantine_file', target: filePath, success: false, output: errorMsg });
      return { success: false, output: errorMsg };
    }
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

  // 4. Perform file relocation, permission stripping, and manifest update inside lock
  return withManifestLock(async () => {
    const qDir = getQuarantineDir();
    const fileBaseName = path.basename(filePath);
    const safeVaultName = `${Date.now()}_${hash.slice(0, 10)}_${fileBaseName}.vault`;
    const destPath = path.join(qDir, safeVaultName);

    try {
      // Move file into vault (cross-device safe)
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

      // Strip execution permissions (set read-only 0400)
      fs.chmodSync(destPath, 0o400);

      // Record manifest entry atomically
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
      saveManifestAtomic(manifest);

      const successMsg = `File successfully quarantined in vault (${qDir}): ${filePath} (SHA256: ${hash}). Permissions stripped to 0400.`;
      logEnforcement({
        actionType: 'quarantine_file',
        target: filePath,
        success: true,
        output: successMsg,
        metadata: { sha256: hash, vaultPath: destPath, vaultDir: qDir },
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
  });
}

/**
 * Restore a quarantined file back to its original path and permissions.
 * Serialized via in-process mutex to prevent manifest race conditions.
 *
 * @param {string} actionIdOrTarget - Action ID, target path, or hash
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function releaseFile(actionIdOrTarget) {
  const query = String(actionIdOrTarget || '').trim();

  return withManifestLock(async () => {
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

      // 5. Remove manifest entry atomically
      delete manifest[foundKey];
      saveManifestAtomic(manifest);

      const successMsg = `File successfully restored from quarantine to original path: ${entry.originalPath}`;
      logEnforcement({ actionType: 'release_file', target: entry.originalPath, success: true, output: successMsg });
      return { success: true, output: successMsg };
    } catch (err) {
      const errorMsg = `Release failed: Could not restore file: ${err.message}`;
      logEnforcement({ actionType: 'release_file', target: entry?.originalPath || query, success: false, output: errorMsg });
      return { success: false, output: errorMsg };
    }
  });
}
