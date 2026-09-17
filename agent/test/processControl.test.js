/**
 * processControl.test.js — Hardened Process Termination Engine Unit Tests.
 *
 * Verifies:
 *   1. Rejection of protected PID 1 (success: false)
 *   2. Rejection of agent's own PID (success: false)
 *   3. Rejection of missing/invalid/negative PIDs (success: false)
 *   4. Spawning a live child process (sleep 30), terminating via killProcess(),
 *      verifying process absence in OS process table, outcome === 'terminated',
 *      and matchedProcessName correctly inspected.
 *   5. Terminating a non-existent PID, verifying outcome === 'already_absent'
 *      distinguished from active termination.
 *   6. Expected process name mismatch generates warning in output but proceeds with kill.
 */
import assert from 'assert';
import { spawn } from 'child_process';
import {
  killProcess,
  isProcessRunning,
  getProcessName,
} from '../src/enforcement/processControl.js';

async function runTests() {
  console.log('--- RUNNING HARDENED PROCESS CONTROL UNIT TESTS ---');

  // 1. Rejection of protected PID 1
  console.log('1. Testing rejection of protected PID 1...');
  const resPid1 = await killProcess(1);
  assert.strictEqual(resPid1.success, false, 'PID 1 must not report success');
  assert.strictEqual(resPid1.outcome, 'failed', 'Outcome must be failed for PID 1');
  assert.ok(
    resPid1.output.includes('protected system process'),
    `Output must mention protected process, got: "${resPid1.output}"`
  );
  console.log('✓ Protected PID 1 correctly rejected.\n');

  // 2. Rejection of agent's own PID
  console.log("2. Testing rejection of agent's own PID...");
  const resOwnPid = await killProcess(process.pid);
  assert.strictEqual(resOwnPid.success, false, 'Self-PID must not report success');
  assert.strictEqual(resOwnPid.outcome, 'failed', 'Outcome must be failed for self-PID');
  assert.ok(
    resOwnPid.output.includes("agent's own process"),
    `Output must mention agent's own process, got: "${resOwnPid.output}"`
  );
  console.log("✓ Agent's own PID correctly rejected.\n");

  // 3. Rejection of missing/non-numeric/negative PID
  console.log('3. Testing rejection of missing/invalid PIDs...');
  for (const badPid of [undefined, null, 'malware-4921', -5, 0, NaN, '']) {
    const resBad = await killProcess(badPid);
    assert.strictEqual(resBad.success, false, `Bad PID "${badPid}" must not succeed`);
    assert.strictEqual(resBad.outcome, 'failed');
    assert.ok(resBad.output.includes('Invalid PID'), `Output must state invalid PID for ${badPid}`);
  }
  console.log('✓ Invalid and non-positive PIDs correctly rejected.\n');

  // 4. Active termination of a real spawned child process
  console.log('4. Testing active termination and absence verification for a live spawned process...');
  const child = spawn('sleep', ['30'], { stdio: 'ignore' });
  const childPid = child.pid;
  assert.ok(childPid > 1, 'Child PID must be valid positive integer');
  assert.strictEqual(isProcessRunning(childPid), true, 'Spawned child must be running');

  // Pre-inspect process name
  const inspectedName = await getProcessName(childPid);
  assert.ok(inspectedName && inspectedName.includes('sleep'), `Inspected name should include sleep, got: "${inspectedName}"`);

  // Kill the process
  const killRes = await killProcess(childPid, 'sleep');
  assert.strictEqual(killRes.success, true, 'Termination must succeed for live spawned child');
  assert.strictEqual(killRes.outcome, 'terminated', 'Outcome must be "terminated"');
  assert.strictEqual(isProcessRunning(childPid), false, 'Child process must be confirmed gone from OS');
  assert.ok(killRes.output.includes('successfully terminated via SIGKILL'), 'Output must state SIGKILL termination');
  assert.ok(killRes.matchedProcessName && killRes.matchedProcessName.includes('sleep'), 'matchedProcessName must be sleep');
  console.log(`✓ Live process PID ${childPid} terminated, outcome="${killRes.outcome}", matchedProcessName="${killRes.matchedProcessName}".\n`);

  // 5. Handling of non-existent PID (already absent)
  console.log('5. Testing handling of non-existent PID (forensic prior absence)...');
  // Use a PID that definitely does not exist (e.g. 999999 or childPid that was just killed)
  const deadPid = 999999;
  assert.strictEqual(isProcessRunning(deadPid), false, 'deadPid must not be running');

  const resDead = await killProcess(deadPid);
  assert.strictEqual(resDead.success, true, 'Must report success: true for already absent target');
  assert.strictEqual(resDead.outcome, 'already_absent', 'Outcome must distinguish prior absence from active termination');
  assert.ok(
    resDead.output.includes('already absent'),
    `Output must explicitly note prior absence, got: "${resDead.output}"`
  );
  console.log(`✓ Non-existent PID reported distinct outcome: "${resDead.outcome}" ("${resDead.output}").\n`);

  // 6. Process name mismatch warning
  console.log('6. Testing expected process name mismatch warning...');
  const child2 = spawn('sleep', ['20'], { stdio: 'ignore' });
  const child2Pid = child2.pid;
  try {
    const mismatchRes = await killProcess(child2Pid, 'nginx_worker');
    assert.strictEqual(mismatchRes.success, true, 'Kill should still succeed despite name mismatch');
    assert.strictEqual(mismatchRes.outcome, 'terminated', 'Outcome must be terminated');
    assert.ok(
      mismatchRes.output.includes('WARNING: Expected process name "nginx_worker" does not match'),
      `Output must include mismatch warning, got: "${mismatchRes.output}"`
    );
    assert.strictEqual(isProcessRunning(child2Pid), false, 'Process must be terminated');
    console.log(`✓ Mismatch warning logged cleanly while proceeding with kill: "${mismatchRes.output}".\n`);
  } finally {
    try { process.kill(child2Pid, 'SIGKILL'); } catch (_) {}
  }

  console.log('=============================================');
  console.log(' ALL HARDENED PROCESS CONTROL TESTS PASSED! ✓');
  console.log('=============================================');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
