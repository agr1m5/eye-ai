/**
 * processControl.js — Hardened Process Termination Engine with Pre & Post-Kill Verification.
 *
 * SPECIFICATION:
 *   - Target Parsing: Requires an explicit numeric PID (positive integer).
 *   - Pre-Kill Validation:
 *       1. Rejects protected system PIDs (PID <= 1, such as init/launchd).
 *       2. Rejects terminating the agent's own PID (defense against self-disruption).
 *       3. Inspects current process command name (/proc/<pid>/comm or ps -p <pid> -o comm=).
 *       4. Detects prior absence (ESRCH) and distinguishes "already absent" from active termination.
 *       5. Warns if inspected command name does not match expectedProcessName, but allows termination.
 *   - Execution: Sends SIGKILL via process.kill(pid, 'SIGKILL').
 *   - Post-Kill Verification:
 *       Polls up to 500ms (50ms interval) to verify the process is completely absent.
 *       Returns success: false if the process remains active after the retry window.
 *   - Audit: Records all attempts and outcomes to local enforcement audit log.
 */
import { execFile } from 'child_process';
import fs from 'fs';
import { promisify } from 'util';
import { logEnforcement } from './auditLogger.js';

const execFileAsync = promisify(execFile);

/**
 * Check whether a process PID is currently active.
 * @param {number} pid
 * @returns {boolean}
 */
export function isProcessRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err.code === 'ESRCH') {
      return false; // No such process
    }
    // EPERM means process exists but we lack permission to signal it
    return true;
  }
}

/**
 * Inspect the command/process name for a running PID.
 * @param {number} pid
 * @returns {Promise<string|null>}
 */
export async function getProcessName(pid) {
  if (process.platform === 'linux') {
    try {
      const commPath = `/proc/${pid}/comm`;
      if (fs.existsSync(commPath)) {
        return fs.readFileSync(commPath, 'utf8').trim();
      }
      const cmdlinePath = `/proc/${pid}/cmdline`;
      if (fs.existsSync(cmdlinePath)) {
        const cmdline = fs.readFileSync(cmdlinePath, 'utf8');
        const firstArg = cmdline.split('\0')[0];
        if (firstArg) return firstArg.trim();
      }
    } catch (_) {
      // Fall through to ps
    }
  }

  try {
    const { stdout } = await execFileAsync('ps', ['-p', String(pid), '-o', 'comm=']);
    const line = stdout.trim();
    return line || null;
  } catch (_) {
    return null;
  }
}

/**
 * Wait for a process to terminate, polling up to maxWaitMs.
 * @param {number} pid
 * @param {number} maxWaitMs
 * @param {number} intervalMs
 * @returns {Promise<boolean>} true if process is confirmed absent, false if still active
 */
export async function pollProcessGone(pid, maxWaitMs = 500, intervalMs = 50) {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    if (!isProcessRunning(pid)) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return !isProcessRunning(pid);
}

/**
 * Hardened kill_process enforcement with pre- and post-kill verification.
 *
 * @param {number|string} pidInput - Explicit numeric PID to terminate
 * @param {string} [expectedName] - Optional expected process name for identity sanity check
 * @returns {Promise<{ success: boolean, output: string, matchedProcessName?: string|null, outcome?: 'terminated'|'already_absent'|'failed' }>}
 */
export async function killProcess(pidInput, expectedName = null) {
  const result = {
    success: false,
    output: '',
    matchedProcessName: null,
    outcome: 'failed',
  };

  // 1. TARGET PARSING & VALIDATION
  const pid = Number(pidInput);
  if (!Number.isInteger(pid) || pid <= 0) {
    result.output = `Invalid PID: "${pidInput}". Target must be a positive integer.`;
    logEnforcement({
      actionType: 'kill_process',
      target: String(pidInput),
      success: false,
      output: result.output,
      metadata: { outcome: result.outcome },
    });
    return result;
  }

  // 2. PRE-KILL SAFETY CHECKS
  if (pid <= 1) {
    result.output = `Refused: PID ${pid} is a protected system process (PID <= 1).`;
    logEnforcement({
      actionType: 'kill_process',
      target: String(pid),
      success: false,
      output: result.output,
      metadata: { outcome: result.outcome },
    });
    return result;
  }

  if (pid === process.pid) {
    result.output = `Refused: PID ${pid} is the agent's own process.`;
    logEnforcement({
      actionType: 'kill_process',
      target: String(pid),
      success: false,
      output: result.output,
      metadata: { outcome: result.outcome },
    });
    return result;
  }

  // 3. PRE-KILL INSPECTION & RUNNING CHECK
  const currentlyRunning = isProcessRunning(pid);
  if (!currentlyRunning) {
    result.success = true;
    result.outcome = 'already_absent';
    result.output = `Process PID ${pid} was not active prior to kill signal (already absent).`;
    logEnforcement({
      actionType: 'kill_process',
      target: String(pid),
      success: true,
      output: result.output,
      metadata: { outcome: result.outcome },
    });
    return result;
  }

  const inspectedName = await getProcessName(pid);
  result.matchedProcessName = inspectedName;

  let mismatchWarning = '';
  if (expectedName && inspectedName) {
    const normExpected = String(expectedName).toLowerCase().trim();
    const normInspected = String(inspectedName).toLowerCase().trim();
    if (!normInspected.includes(normExpected) && !normExpected.includes(normInspected)) {
      mismatchWarning = ` [WARNING: Expected process name "${expectedName}" does not match inspected name "${inspectedName}"]`;
    }
  }

  // 4. EXECUTION
  let signalSent = false;
  try {
    process.kill(pid, 'SIGKILL');
    signalSent = true;
  } catch (kErr) {
    if (kErr.code === 'ESRCH') {
      // Process exited between inspect and kill
      result.success = true;
      result.outcome = 'already_absent';
      result.output = `Process PID ${pid}${inspectedName ? ` (${inspectedName})` : ''} exited prior to signal delivery (already absent).${mismatchWarning}`;
      logEnforcement({
        actionType: 'kill_process',
        target: String(pid),
        success: true,
        output: result.output,
        metadata: { matchedProcessName: inspectedName, outcome: result.outcome },
      });
      return result;
    }

    result.output = `Failed to send SIGKILL to PID ${pid} (${kErr.code || kErr.message}).${mismatchWarning}`;
    logEnforcement({
      actionType: 'kill_process',
      target: String(pid),
      success: false,
      output: result.output,
      metadata: { matchedProcessName: inspectedName, outcome: result.outcome, error: kErr.message },
    });
    return result;
  }

  // 5. POST-KILL VERIFICATION
  const confirmedGone = await pollProcessGone(pid, 500, 50);
  if (confirmedGone) {
    result.success = true;
    result.outcome = 'terminated';
    result.output = `Process PID ${pid}${inspectedName ? ` (${inspectedName})` : ''} successfully terminated via SIGKILL and confirmed absent.${mismatchWarning}`;
  } else {
    result.success = false;
    result.outcome = 'failed';
    result.output = `Kill signal SIGKILL sent to PID ${pid}${inspectedName ? ` (${inspectedName})` : ''}, but process remains active after 500ms verification window.${mismatchWarning}`;
  }

  logEnforcement({
    actionType: 'kill_process',
    target: String(pid),
    success: result.success,
    output: result.output,
    metadata: {
      matchedProcessName: inspectedName,
      outcome: result.outcome,
      signalSent,
    },
  });

  return result;
}
