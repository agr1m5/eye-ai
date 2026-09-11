/**
 * consent.js — Device Access Permission & Authorization Controller
 *
 * Enforces explicit user consent before any host collectors (processes,
 * network sockets, system logs, honeytokens) are permitted to inspect the machine.
 */
import fs from 'fs';
import path from 'path';
import os from 'os';
import readline from 'readline';

const CONSENT_DIR  = path.join(os.homedir(), '.eye');
const CONSENT_FILE = path.join(CONSENT_DIR,  'device_consent.json');

const WATCH_INTERVAL_MS = 30_000; // re-check consent every 30 seconds

/**
 * Checks whether device access consent has already been granted.
 */
export function hasConsent() {
  // Check env variable
  if (process.env.DEVICE_ACCESS_GRANTED === 'true') {
    return true;
  }

  // Check persistent consent file
  try {
    if (fs.existsSync(CONSENT_FILE)) {
      const data = JSON.parse(fs.readFileSync(CONSENT_FILE, 'utf8'));
      if (data.status === 'granted') {
        return true;
      }
    }
  } catch {}

  return false;
}

/**
 * Persists the user's authorization to disk and agent .env
 */
export function recordConsent(granted = true) {
  try {
    if (!fs.existsSync(CONSENT_DIR)) {
      fs.mkdirSync(CONSENT_DIR, { recursive: true });
    }

    const payload = {
      status: granted ? 'granted' : 'denied',
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      user: os.userInfo().username,
      scopes: [
        'process_monitoring',
        'network_socket_audit',
        'system_auth_log_stream',
        'honeytoken_canary_trap',
      ],
    };

    fs.writeFileSync(CONSENT_FILE, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    console.error(`[Consent] Warning: Could not write consent file: ${err.message}`);
  }
}

/**
 * Ensures device monitoring permission is granted before starting collectors.
 * If running in an interactive terminal, prompts the user explicitly.
 * If non-interactive and unapproved, prevents execution.
 */
export async function ensureDevicePermissionGranted() {
  if (hasConsent()) {
    console.log('[Consent] Device access permission verified: GRANTED.');
    return true;
  }

  // If interactive terminal, ask the user directly
  if (process.stdin.isTTY) {
    console.log('\n' + '='.repeat(78));
    console.log('🛡️  RAKSHAK LIVE SOC — DEVICE ACCESS PERMISSION REQUEST');
    console.log('='.repeat(78));
    console.log('Before endpoint monitoring can begin, you must authorize this agent');
    console.log('to inspect system activity on your machine:');
    console.log('');
    console.log('  [✓] System Auth Logs       : Streams authentication, sudo, and SSH logs');
    console.log('  [✓] Process Tree Audit     : Enumerates and diffs active processes (ps)');
    console.log('  [✓] Network Socket Monitor : Audits listening ports and TCP sockets (lsof/ss)');
    console.log('  [✓] Canary Honeytoken Trap : Watches decoy credentials in ~/.eye');
    console.log('');
    console.log('🔒 PRIVACY GUARANTEE:');
    console.log('  • All raw logs, process arguments, and commands stay strictly local on this host.');
    console.log('  • Only cryptographically classified security alerts are sent to the SOC server.');
    console.log('='.repeat(78));

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const answer = await new Promise((resolve) => {
      rl.question('\nDo you authorize Eye to access and monitor this device? [y/N]: ', (ans) => {
        rl.close();
        resolve((ans || '').trim().toLowerCase());
      });
    });

    if (answer === 'y' || answer === 'yes') {
      recordConsent(true);
      console.log('✓ Permission GRANTED. Device telemetry collectors will now initialize.\n');
      return true;
    } else {
      recordConsent(false);
      console.log('\n❌ Permission DENIED. Agent will not monitor this device without authorization.');
      console.log('Exiting safely.\n');
      process.exit(0);
    }
  }

  // Non-interactive (daemon / headless service) without prior consent
  console.error('\n' + '!'.repeat(78));
  console.error('❌ [SECURITY ERROR] Device monitoring permission has NOT been granted on this machine.');
  console.error('Eye requires explicit authorization before accessing host telemetry.');
  console.error('');
  console.error('To grant permission:');
  console.error('  1. Run "npm run agent" in an interactive terminal to approve the prompt.');
  console.error('  OR');
  console.error('  2. Add DEVICE_ACCESS_GRANTED=true to agent/.env');
  console.error('!'.repeat(78) + '\n');
  process.exit(1);
}

// Allow standalone execution: node src/consent.js --grant
if (process.argv.includes('--grant')) {
  recordConsent(true);
  console.log('✓ Device access permission recorded successfully.');
  process.exit(0);
}

/**
 * Watches ~/.eye/device_consent.json for live consent changes while the agent runs.
 *
 * Called AFTER startup with the agent already running. Polls every 30s.
 * - If consent is revoked  → calls onRevoke() immediately to stop collectors.
 * - If consent is restored → calls onGrant() to resume collectors.
 *
 * Returns a stop function to cancel the watcher.
 */
export function watchConsent({ onRevoke, onGrant } = {}) {
  let lastStatus = hasConsent() ? 'granted' : 'denied';

  const timer = setInterval(() => {
    try {
      let currentStatus = 'denied';
      if (fs.existsSync(CONSENT_FILE)) {
        const data = JSON.parse(fs.readFileSync(CONSENT_FILE, 'utf8'));
        currentStatus = data?.status === 'granted' ? 'granted' : 'denied';
      }

      if (currentStatus !== lastStatus) {
        console.log(`[Consent] ⚡ Consent changed: ${lastStatus} → ${currentStatus}`);
        lastStatus = currentStatus;

        if (currentStatus === 'denied') {
          console.warn('[Consent] 🚫 Device access REVOKED — stopping all collectors immediately.');
          if (typeof onRevoke === 'function') onRevoke();
        } else {
          console.log('[Consent] ✅ Device access GRANTED — resuming collectors.');
          if (typeof onGrant === 'function') onGrant();
        }
      }
    } catch (err) {
      console.warn(`[Consent] Warning: Could not read consent file during watch: ${err.message}`);
    }
  }, WATCH_INTERVAL_MS);

  return () => clearInterval(timer);
}
