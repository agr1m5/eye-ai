import assert from 'assert';
import { resolveBackendEndpoint, isolateHost, releaseHost, isRoot } from '../src/enforcement/isolation.js';

console.log('--- RUNNING ISOLATION UNIT TESTS ---');

async function testIsolation() {
  console.log('1. Testing resolveBackendEndpoint...');
  const backend = await resolveBackendEndpoint();
  assert.ok(backend.ip, 'Backend IP must be resolved');
  assert.ok(backend.port, 'Backend Port must be resolved');
  console.log(`✓ Resolved backend endpoint: ${backend.ip}:${backend.port}`);

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
  }

  console.log('\n=========================================');
  console.log(' ALL ISOLATION TESTS PASSED! ✓');
  console.log('=========================================');
}

testIsolation().catch((err) => {
  console.error('Isolation test error:', err);
  process.exit(1);
});
