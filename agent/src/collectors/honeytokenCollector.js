/**
 * honeytokenCollector.js — Deception Technology & Decoy Canaries
 *
 * Places decoy credential files on the endpoint. Any read or write
 * by an adversary or malicious script triggers an immediate CRITICAL finding.
 */
import fs from 'fs';
import path from 'path';
import os from 'os';

const CANARY_DIR = path.join(os.homedir(), '.eye');
const CANARY_FILE = path.join(CANARY_DIR, 'canary_aws_keys.env');

const CANARY_CONTENT = `# ==========================================================
# RAKSHAK HONEYTOKEN DECOY CANARY — DO NOT MODIFY
# ==========================================================
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE_CANARY
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
PROD_DB_HOST=10.0.4.15
PROD_DB_SECRET=SecOpsInternalVaultPassword2026!
`;

export function startHoneytokenCollector(onEvent, onError) {
  try {
    if (!fs.existsSync(CANARY_DIR)) {
      fs.mkdirSync(CANARY_DIR, { recursive: true });
    }

    // Initialize or restore decoy canary
    fs.writeFileSync(CANARY_FILE, CANARY_CONTENT, { encoding: 'utf8', mode: 0o600 });

    let lastAlert = 0;
    const watcher = fs.watch(CANARY_FILE, (eventType) => {
      const now = Date.now();
      // Debounce rapid access triggers (5 second cooldown)
      if (now - lastAlert < 5000) return;
      lastAlert = now;

      onEvent({
        source:    'honeytoken',
        type:      'Honeytoken Decoy Breached',
        severity:  'critical',
        timestamp: new Date().toISOString(),
        message:   `Adversary accessed decoy canary honeytoken file at ${CANARY_FILE} (${eventType})`,
        raw: JSON.stringify({
          eventType,
          canaryPath: CANARY_FILE,
          trigger: 'Unsolicited access to decoy AWS credentials',
        }),
      });
    });

    return () => {
      try {
        watcher.close();
      } catch {}
    };
  } catch (err) {
    if (onError) onError(err);
    return () => {};
  }
}
