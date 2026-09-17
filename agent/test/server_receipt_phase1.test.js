import assert from 'assert';
import http from 'http';
import jwt from 'jsonwebtoken';
import { io } from 'socket.io-client';

const JWT_SECRET = 'eye_live_jwt_secret_key_change_in_production_32chars';
const USER_ID = '6a98f8695dcd1cccaff0cce3';
const token = jwt.sign(
  { sub: USER_ID, email: 'testsoc@rakshak.local', role: 'analyst' },
  JWT_SECRET,
  { expiresIn: '24h' }
);

function post(path, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const req = http.request({
      hostname: 'localhost',
      port: 5050,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Authorization': `Bearer ${token}`
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function get(path) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: 5050,
      path,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, data: body });
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function run() {
  console.log('=== RUNNING PHASE 1 SOAR INTEGRATION TEST (ISOLATE & QUARANTINE ONLY) ===');

  // Pair agent to obtain a valid pairing token
  console.log('0. Pairing mock agent with backend to obtain auth token...');
  const pairRes = await post('/api/agent/pair', { label: 'Test Phase 1 Sensor' });
  assert.strictEqual(pairRes.status, 200, 'Agent pair must succeed');
  const agentToken = pairRes.data?.token || pairRes.data?.data?.token;
  assert.ok(agentToken, 'Agent token must be present');
  console.log('✓ Mock agent paired successfully.');

  // Connect mock agent socket
  const agentSocket = io('http://localhost:5050/agent', {
    auth: {
      userId: USER_ID,
      agentToken: agentToken,
      role: 'agent',
    },
  });

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Agent socket connection timed out')), 5000);
    agentSocket.on('connect', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
  console.log('✓ Agent connected to /agent namespace.\n');

  /* ─────────────────────────────────────────────────────────────
   * PART 1: ISOLATE HOST CONTAINMENT & RECEIPT VERIFICATION
   * ───────────────────────────────────────────────────────────── */
  console.log('--- PART 1: ISOLATE_HOST VERIFICATION ---');

  // 1. Simulate attack vector to produce an active incident
  console.log('1.1 Detonating simulated C2 beacon vector...');
  const simRes1 = await post('/api/threats/simulate', {
    type: 'c2_beacon',
    severity: 'critical',
    sourceIp: '185.193.65.19',
    description: 'Outbound C2 connection on port 4444',
  });

  const incidentId1 = simRes1.data?.data?.incident?._id;
  assert.ok(incidentId1, 'Simulation must produce an incident');
  console.log(`Incident #1 created: ID = ${incidentId1}, initial status = open`);

  // 1.2 Dispatch isolate_host containment
  console.log('1.2 Dispatching isolate_host containment to agent...');
  const containRes1 = await post('/api/defense/contain', {
    actionType: 'isolate_host',
    target: 'soc-collector-01',
    incidentId: incidentId1,
    reason: 'Active C2 exfiltration observed',
  });

  assert.strictEqual(containRes1.status, 200, 'Containment dispatch must return 200');
  const actionId1 = containRes1.data?.data?._id;
  assert.ok(actionId1, 'DefenseAction must be created');

  // Verify incident is NOT prematurely resolved
  const incCheck1 = await get(`/api/incidents/${incidentId1}`);
  const incData1 = incCheck1.data?.data?.incident || incCheck1.data?.data;
  assert.strictEqual(incData1.status, 'open', 'Incident must remain open on dispatch');
  console.log('✓ Incident remained open upon dispatch without premature optimistic resolution.');

  // 1.3 Simulate failed receipt (e.g. non-root privilege failure)
  console.log('1.3 Simulating non-root failure receipt from agent...');
  agentSocket.emit('agent:contain:receipt', {
    actionId: actionId1,
    actionType: 'isolate_host',
    target: 'soc-collector-01',
    success: false,
    output: 'Enforcement failed: Root/Administrator privileges required to enforce host isolation.',
  });

  await new Promise((r) => setTimeout(r, 600));

  // Verify incident is STILL not resolved
  const incCheckFail1 = await get(`/api/incidents/${incidentId1}`);
  const incDataFail1 = incCheckFail1.data?.data?.incident || incCheckFail1.data?.data;
  assert.strictEqual(incDataFail1.status, 'open', 'Incident must NOT resolve on failure receipt');

  // Verify action status is 'failed'
  const actCheck1 = await get('/api/defense/actions');
  const action1 = (actCheck1.data?.data?.actions || []).find((a) => a._id === actionId1);
  assert.strictEqual(action1?.status, 'failed', 'DefenseAction must be marked failed');
  console.log('✓ Failed receipt properly recorded; incident remains open.');

  // 1.4 Simulate verified successful receipt
  console.log('1.4 Simulating verified success receipt from agent...');
  agentSocket.emit('agent:contain:receipt', {
    actionId: actionId1,
    actionType: 'isolate_host',
    target: 'soc-collector-01',
    success: true,
    output: 'Host network isolation active. All egress dropped except control channel (127.0.0.1:5050) and loopback.',
  });

  await new Promise((r) => setTimeout(r, 600));

  // Verify incident is now resolved with Host Daemon Verification notes
  const incCheckSuccess1 = await get(`/api/incidents/${incidentId1}`);
  const incDataSuccess1 = incCheckSuccess1.data?.data?.incident || incCheckSuccess1.data?.data;
  assert.strictEqual(incDataSuccess1.status, 'resolved', 'Incident must resolve on verified success receipt');
  assert.ok(incDataSuccess1.notes?.includes('Host Daemon Verification'), 'Notes must include Host Daemon Verification');
  console.log('✓ Incident successfully marked resolved upon verified agent receipt.');

  // 1.5 Test containment release
  console.log('1.5 Testing isolate_host release...');
  const releaseRes1 = await post(`/api/defense/${actionId1}/release`, {});
  assert.strictEqual(releaseRes1.status, 200, 'Release must return 200');
  console.log('✓ Host isolation release executed successfully.\n');

  /* ─────────────────────────────────────────────────────────────
   * PART 2: QUARANTINE FILE CONTAINMENT & RECEIPT VERIFICATION
   * ───────────────────────────────────────────────────────────── */
  console.log('--- PART 2: QUARANTINE_FILE VERIFICATION ---');

  // 2.1 Simulate malware dropped vector
  console.log('2.1 Detonating simulated malware payload vector...');
  const simRes2 = await post('/api/threats/simulate', {
    type: 'malware_dropped',
    severity: 'high',
    description: 'Suspicious payload /tmp/dropper_payload.sh written to disk',
  });

  const incidentId2 = simRes2.data?.data?.incident?._id;
  assert.ok(incidentId2, 'Simulation must produce an incident');
  console.log(`Incident #2 created: ID = ${incidentId2}, initial status = open`);

  // 2.2 Dispatch quarantine_file containment
  console.log('2.2 Dispatching quarantine_file containment to agent...');
  const containRes2 = await post('/api/defense/contain', {
    actionType: 'quarantine_file',
    target: '/tmp/dropper_payload.sh',
    filePath: '/tmp/dropper_payload.sh',
    incidentId: incidentId2,
    reason: 'Suspicious payload binary detected',
  });

  assert.strictEqual(containRes2.status, 200, 'Containment dispatch must return 200');
  const actionId2 = containRes2.data?.data?._id;
  assert.ok(actionId2, 'DefenseAction must be created');

  // Verify incident is NOT prematurely resolved
  const incCheck2 = await get(`/api/incidents/${incidentId2}`);
  const incData2 = incCheck2.data?.data?.incident || incCheck2.data?.data;
  assert.strictEqual(incData2.status, 'open', 'Incident must remain open on dispatch');
  console.log('✓ Incident remained open upon dispatch without premature optimistic resolution.');

  // 2.3 Simulate failed receipt (e.g. file not found or invalid traversal)
  console.log('2.3 Simulating failure receipt (file not found) from agent...');
  agentSocket.emit('agent:contain:receipt', {
    actionId: actionId2,
    actionType: 'quarantine_file',
    target: '/tmp/dropper_payload.sh',
    success: false,
    output: 'Quarantine error: Target file does not exist or inaccessible: "/tmp/dropper_payload.sh"',
  });

  await new Promise((r) => setTimeout(r, 600));

  // Verify incident is STILL not resolved
  const incCheckFail2 = await get(`/api/incidents/${incidentId2}`);
  const incDataFail2 = incCheckFail2.data?.data?.incident || incCheckFail2.data?.data;
  assert.strictEqual(incDataFail2.status, 'open', 'Incident must NOT resolve on failure receipt');

  // Verify action status is 'failed'
  const actCheck2 = await get('/api/defense/actions');
  const action2 = (actCheck2.data?.data?.actions || []).find((a) => a._id === actionId2);
  assert.strictEqual(action2?.status, 'failed', 'DefenseAction must be marked failed');
  console.log('✓ Failed receipt properly recorded; incident remains open.');

  // 2.4 Simulate verified successful receipt with sha256
  console.log('2.4 Simulating verified success receipt from agent with SHA256...');
  agentSocket.emit('agent:contain:receipt', {
    actionId: actionId2,
    actionType: 'quarantine_file',
    target: '/tmp/dropper_payload.sh',
    success: true,
    hash: 'aab6f16d31d3718739e7c7d6a99363e2e765dc34ce9e8e7e3df3c775bc55f1f1',
    output: 'File successfully quarantined in secure vault: /tmp/dropper_payload.sh (SHA256: aab6f16d31d3718739e7c7d6a99363e2e765dc34ce9e8e7e3df3c775bc55f1f1). Permissions stripped to 0400.',
  });

  await new Promise((r) => setTimeout(r, 600));

  // Verify incident is now resolved with Host Daemon Verification notes
  const incCheckSuccess2 = await get(`/api/incidents/${incidentId2}`);
  const incDataSuccess2 = incCheckSuccess2.data?.data?.incident || incCheckSuccess2.data?.data;
  assert.strictEqual(incDataSuccess2.status, 'resolved', 'Incident must resolve on verified success receipt');
  assert.ok(incDataSuccess2.notes?.includes('Host Daemon Verification'), 'Notes must include Host Daemon Verification');
  console.log('✓ Incident successfully marked resolved upon verified quarantine receipt.');

  // 2.5 Test containment release
  console.log('2.5 Testing quarantine_file release...');
  const releaseRes2 = await post(`/api/defense/${actionId2}/release`, {});
  assert.strictEqual(releaseRes2.status, 200, 'Release must return 200');
  console.log('✓ Quarantine release executed successfully.\n');

  agentSocket.disconnect();

  console.log('========================================================================');
  console.log(' ALL PHASE 1 ISOLATE & QUARANTINE SERVER RECEIPT TESTS PASSED! ✓');
  console.log('========================================================================');
}

run().catch((err) => {
  console.error('Integration test failed:', err);
  process.exit(1);
});
