import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { validateFilePath, quarantineFile, releaseFile, getQuarantineDir } from '../src/enforcement/quarantine.js';

console.log('--- RUNNING QUARANTINE UNIT TESTS ---');

// 1. Path validation tests
console.log('1. Testing validateFilePath...');
assert.strictEqual(validateFilePath('/tmp/malware.bin').valid, true, 'Valid absolute path should pass');
assert.strictEqual(validateFilePath('relative/file.bin').valid, false, 'Relative path must be rejected');
assert.strictEqual(validateFilePath('/tmp/../etc/shadow').valid, false, 'Path traversal must be rejected');
assert.strictEqual(validateFilePath('/etc').valid, false, 'Critical system directory /etc must be rejected');
assert.strictEqual(validateFilePath('/').valid, false, 'Root / must be rejected');
assert.strictEqual(validateFilePath('').valid, false, 'Empty path must be rejected');
console.log('✓ Path validation & traversal defense tests passed.');

// 2. Quarantine Vault & Restoration End-to-End
console.log('\n2. Testing end-to-end file quarantine and restoration...');
const testFile = '/tmp/test_payload_' + Date.now() + '.sh';
const payloadContent = '#!/bin/bash\necho "Simulated threat payload"\n';
fs.writeFileSync(testFile, payloadContent, { mode: 0o755 });

const actionId = 'test_action_' + Date.now();

async function testQuarantineCycle() {
  // Verify file exists
  assert.ok(fs.existsSync(testFile), 'Test file must exist before quarantine');

  // Perform quarantine
  const qResult = await quarantineFile(testFile, actionId);
  console.log(`Quarantine output: ${qResult.output}`);
  assert.strictEqual(qResult.success, true, 'Quarantine must succeed');
  assert.ok(qResult.hash, 'Quarantine result must include SHA256 hash');

  // Verify original file is gone from original path
  assert.strictEqual(fs.existsSync(testFile), false, 'Original file must no longer exist at original path');

  // Verify vault file exists and permissions are non-executable (0400)
  assert.ok(fs.existsSync(qResult.quarantinePath), 'Vault file must exist in quarantine directory');
  const vaultStat = fs.statSync(qResult.quarantinePath);
  // (mode & 0777) === 0400
  const modeOctal = (vaultStat.mode & 0o777).toString(8);
  console.log(`Vault file mode: ${modeOctal} (expected 400)`);
  assert.strictEqual(modeOctal, '400', 'Vault file permissions must be stripped to 0400');

  // Perform restoration (releaseFile)
  console.log('\n3. Testing file restoration (releaseFile)...');
  const rResult = await releaseFile(actionId);
  console.log(`Release output: ${rResult.output}`);
  assert.strictEqual(rResult.success, true, 'File release must succeed');

  // Verify file restored at original path with original content
  assert.ok(fs.existsSync(testFile), 'File must be restored to original path');
  const restoredContent = fs.readFileSync(testFile, 'utf8');
  assert.strictEqual(restoredContent, payloadContent, 'Restored content must match original payload');

  // Verify vault file is removed
  assert.strictEqual(fs.existsSync(qResult.quarantinePath), false, 'Vault file must be cleaned up on release');

  // Clean up test file
  try { fs.unlinkSync(testFile); } catch {}

  console.log('\n=========================================');
  console.log(' ALL QUARANTINE TESTS PASSED! ✓');
  console.log('=========================================');
}

testQuarantineCycle().catch((err) => {
  console.error('Quarantine test error:', err);
  // Clean up if test fails
  try { fs.unlinkSync(testFile); } catch {}
  process.exit(1);
});
