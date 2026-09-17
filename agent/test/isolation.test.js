import assert from 'assert';
import { resolveBackendEndpoint, isolateHost, releaseHost, isRoot, releaseHostLinux } from '../src/enforcement/isolation.js';

console.log('--- RUNNING HARDENED ISOLATION UNIT TESTS ---');

async function testIsolation() {
  // 1. Endpoint resolution & IP validation
  console.log('1. Testing resolveBackendEndpoint IP validation...');
  const backend = await resolveBackendEndpoint();
  assert.ok(backend.ip, 'Backend IP must be resolved');
  assert.ok(backend.port, 'Backend Port must be resolved');
  assert.match(backend.ip, /^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)$/, 'Resolved IP must be valid IPv4/IPv6');
  console.log(`✓ Resolved and validated backend endpoint: ${backend.ip}:${backend.port}`);

  // 2. Non-root safety checks
  if (!isRoot()) {
    console.log('\n2. Testing non-root privilege failure for isolateHost...');
    const isoResult = await isolateHost();
    assert.strictEqual(isoResult.success, false, 'isolateHost must fail when non-root');
    assert.ok(isoResult.output.includes('privileges required'), 'Error must mention root privileges');
    console.log('✓ isolateHost returned loud non-root failure.');

    console.log('\n3. Testing non-root privilege failure for releaseHost...');
    const relResult = await releaseHost();
    assert.strictEqual(relResult.success, false, 'releaseHost must fail when non-root');
    assert.ok(relResult.output.includes('privileges required'), 'Error must mention root privileges');
    console.log('✓ releaseHost returned loud non-root failure.');

    console.log('\n4. Testing releaseHostLinux failure handling when unprivileged...');
    // Directly invoke releaseHostLinux when non-root to verify it fails loudly rather than reporting fake success
    const linuxRelResult = await releaseHostLinux();
    assert.strictEqual(linuxRelResult.success, false, 'releaseHostLinux must fail when chain cannot be deleted');
    assert.ok(
      linuxRelResult.output.includes('failed') || linuxRelResult.output.includes('Could not delete'),
      'Output must specify deletion or verification failure'
    );
    console.log('✓ releaseHostLinux properly returned success:false with real error output.');
  }

  console.log('\n=========================================');
  console.log(' ALL HARDENED ISOLATION TESTS PASSED! ✓');
  console.log('=========================================');
}

testIsolation().catch((err) => {
  console.error('Isolation test error:', err);
  process.exit(1);
});
