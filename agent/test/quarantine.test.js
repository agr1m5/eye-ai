import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { validateFilePath, quarantineFile, releaseFile, getQuarantineDir } from '../src/enforcement/quarantine.js';

console.log('--- RUNNING HARDENED QUARANTINE UNIT TESTS ---');

// 1. Path validation & Hierarchical forbidden roots tests
console.log('1. Testing validateFilePath security guards...');
assert.strictEqual(validateFilePath('/tmp/malware.bin').valid, true, 'Valid absolute path should pass');
assert.strictEqual(validateFilePath('~/.eye/canary.env').valid, true, 'Tilde home path should be expanded and accepted');
assert.strictEqual(validateFilePath('relative/file.bin').valid, false, 'Relative path must be rejected');
assert.strictEqual(validateFilePath('/tmp/../etc/shadow').valid, false, 'Path traversal must be rejected');
assert.strictEqual(validateFilePath('/tmp/foo/../bar').valid, false, 'Path containing .. must be rejected');
assert.strictEqual(validateFilePath('/etc').valid, false, 'Critical system directory /etc must be rejected');
assert.strictEqual(validateFilePath('/etc/passwd').valid, false, '/etc/passwd under forbidden root must be rejected');
assert.strictEqual(validateFilePath('/etc/shadow').valid, false, '/etc/shadow under forbidden root must be rejected');
assert.strictEqual(validateFilePath('/usr/bin/python3').valid, false, '/usr/bin/python3 under forbidden root must be rejected');
assert.strictEqual(validateFilePath('/').valid, false, 'Root / must be rejected');
assert.strictEqual(validateFilePath('').valid, false, 'Empty path must be rejected');

// Test symlink pointing into /etc
const testSymlink = '/tmp/test_symlink_' + Date.now();
try {
  fs.symlinkSync('/etc/hosts', testSymlink);
  const symResult = validateFilePath(testSymlink);
  assert.strictEqual(symResult.valid, false, 'Symlink resolving to /etc must be rejected');
  assert.ok(symResult.error.includes('Symlink target resolves to critical system path'), 'Error must mention symlink target violation');
  console.log('✓ Symlink pointing into /etc correctly detected and rejected.');
} finally {
  try { fs.unlinkSync(testSymlink); } catch {}
}

console.log('✓ Path validation, hierarchical forbidden roots, and symlink tests passed.');

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

  // 4. Testing Concurrent Quarantine Serialization & Mutex
  console.log('\n4. Testing concurrent quarantineFile serialization...');
  const concurrentFile1 = '/tmp/test_concurrent_1_' + Date.now() + '.txt';
  const concurrentFile2 = '/tmp/test_concurrent_2_' + Date.now() + '.txt';
  fs.writeFileSync(concurrentFile1, 'concurrent payload 1');
  fs.writeFileSync(concurrentFile2, 'concurrent payload 2');

  const actionId1 = 'concurrent_action_1_' + Date.now();
  const actionId2 = 'concurrent_action_2_' + Date.now();

  try {
    const [res1, res2] = await Promise.all([
      quarantineFile(concurrentFile1, actionId1),
      quarantineFile(concurrentFile2, actionId2),
    ]);

    assert.strictEqual(res1.success, true, 'Concurrent file 1 quarantine must succeed');
    assert.strictEqual(res2.success, true, 'Concurrent file 2 quarantine must succeed');

    // Read manifest directly and verify BOTH action IDs are present without clobbering
    const manifestPath = path.join(getQuarantineDir(), 'quarantine-manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    assert.ok(manifest[actionId1], 'Manifest must contain actionId1');
    assert.ok(manifest[actionId2], 'Manifest must contain actionId2');
    console.log('✓ Concurrent quarantine operations both serialized and recorded in manifest successfully.');

    // Release both concurrent files
    const rel1 = await releaseFile(actionId1);
    const rel2 = await releaseFile(actionId2);
    assert.strictEqual(rel1.success, true, 'Concurrent file 1 release must succeed');
    assert.strictEqual(rel2.success, true, 'Concurrent file 2 release must succeed');
  } finally {
    try { fs.unlinkSync(concurrentFile1); } catch {}
    try { fs.unlinkSync(concurrentFile2); } catch {}
  }

  console.log('\n=========================================');
  console.log(' ALL HARDENED QUARANTINE TESTS PASSED! ✓');
  console.log('=========================================');
}

testQuarantineCycle().catch((err) => {
  console.error('Quarantine test error:', err);
  try { fs.unlinkSync(testFile); } catch {}
  process.exit(1);
});
