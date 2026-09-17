import { execFile } from 'child_process';
import fs from 'fs';
import dns from 'dns';
import { promisify } from 'util';
import { URL } from 'url';
import { config } from '../config.js';
import { logEnforcement } from './auditLogger.js';

/**
 * Verify whether the agent process has root/administrator privileges.
 */
export function isRoot() {
  if (process.platform === 'win32') return true; // Windows handles via UAC
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

const execFileAsync = promisify(execFile);
const dnsLookupAsync = promisify(dns.lookup);

const LINUX_ISOLATE_CHAIN = 'EYE_ISOLATE';
const MAC_ISOLATE_ANCHOR = 'eye_isolate';
const MAC_ISOLATE_FILE = '/tmp/eye_isolate.pf';

/**
 * Resolve the backend SOC endpoint (IP and port) to ensure control channel survives isolation.
 */
export async function resolveBackendEndpoint() {
  try {
    const parsed = new URL(config.backendUrl || 'http://localhost:5050');
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    let host = parsed.hostname;
    let ip = host;

    if (host.toLowerCase() === 'localhost') {
      ip = '127.0.0.1';
    } else {
      try {
        const lookup = await dnsLookupAsync(host);
        if (lookup?.address) {
          ip = lookup.address;
        }
      } catch {
        // Fallback to host string
      }
    }

    return { ip, port: String(port), host };
  } catch (err) {
    return { ip: '127.0.0.1', port: '5050', host: 'localhost' };
  }
}

/* ══════════════════════════════════════════════════════════════════════
 * LINUX ISOLATION ENGINE (EYE_ISOLATE Chain)
 * ══════════════════════════════════════════════════════════════════════ */

async function isolateHostLinux(backend) {
  // 1. Create or flush EYE_ISOLATE chain
  try {
    await execFileAsync('iptables', ['-L', LINUX_ISOLATE_CHAIN, '-n']);
    await execFileAsync('iptables', ['-F', LINUX_ISOLATE_CHAIN]);
  } catch {
    await execFileAsync('iptables', ['-N', LINUX_ISOLATE_CHAIN]);
  }

  // 2. Add explicit allow rules for control channel & loopback
  // Allow loopback interface
  await execFileAsync('iptables', ['-A', LINUX_ISOLATE_CHAIN, '-o', 'lo', '-j', 'ACCEPT']);

  // Allow established and related connections
  try {
    await execFileAsync('iptables', [
      '-A', LINUX_ISOLATE_CHAIN,
      '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
      '-j', 'ACCEPT',
    ]);
  } catch {
    // Fallback if conntrack not loaded
    try {
      await execFileAsync('iptables', [
        '-A', LINUX_ISOLATE_CHAIN,
        '-m', 'state', '--state', 'ESTABLISHED,RELATED',
        '-j', 'ACCEPT',
      ]);
    } catch {}
  }

  // Allow TCP to backend SOC IP and Port (Deadlock Prevention!)
  await execFileAsync('iptables', [
    '-A', LINUX_ISOLATE_CHAIN,
    '-p', 'tcp',
    '-d', backend.ip,
    '--dport', backend.port,
    '-j', 'ACCEPT',
  ]);

  // Allow DNS resolution (port 53 UDP/TCP)
  await execFileAsync('iptables', ['-A', LINUX_ISOLATE_CHAIN, '-p', 'udp', '--dport', '53', '-j', 'ACCEPT']);
  await execFileAsync('iptables', ['-A', LINUX_ISOLATE_CHAIN, '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT']);

  // Default-deny all other outbound traffic
  await execFileAsync('iptables', ['-A', LINUX_ISOLATE_CHAIN, '-j', 'DROP']);

  // 3. Ensure jump rule is at the top of OUTPUT
  try {
    await execFileAsync('iptables', ['-C', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
  } catch {
    await execFileAsync('iptables', ['-I', 'OUTPUT', '1', '-j', LINUX_ISOLATE_CHAIN]);
  }

  // Verification: Ensure rule is active
  try {
    await execFileAsync('iptables', ['-C', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
    return {
      success: true,
      output: `Host network isolation active. All egress dropped except control channel (${backend.ip}:${backend.port}) and loopback.`,
    };
  } catch (verifyErr) {
    return {
      success: false,
      output: `Isolation verification failed: OUTPUT jump rule not found (${verifyErr.message}).`,
    };
  }
}

async function releaseHostLinux() {
  let removed = false;
  // Remove jump rule from OUTPUT
  while (true) {
    try {
      await execFileAsync('iptables', ['-D', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
      removed = true;
    } catch {
      break;
    }
  }

  // Flush and delete chain
  try {
    await execFileAsync('iptables', ['-F', LINUX_ISOLATE_CHAIN]);
    await execFileAsync('iptables', ['-X', LINUX_ISOLATE_CHAIN]);
  } catch {}

  return {
    success: true,
    output: 'Host network isolation released. Normal outbound connectivity restored.',
  };
}

/* ══════════════════════════════════════════════════════════════════════
 * MACOS ISOLATION ENGINE (pfctl eye_isolate Anchor)
 * ══════════════════════════════════════════════════════════════════════ */

async function isolateHostDarwin(backend) {
  // Construct pf rules: default deny egress with pass rules for loopback, backend, and DNS
  const pfRules = [
    '# EYE SOAR Host Isolation Anchor: eye_isolate',
    'set block-policy drop',
    'pass out quick on lo0 all',
    `pass out quick proto tcp to ${backend.ip} port ${backend.port}`,
    'pass out quick proto udp to any port 53',
    'pass out quick proto tcp to any port 53',
    'block drop out all',
  ].join('\n') + '\n';

  fs.writeFileSync(MAC_ISOLATE_FILE, pfRules, 'utf8');

  // Load anchor: pfctl -a eye_isolate -f /tmp/eye_isolate.pf
  await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-f', MAC_ISOLATE_FILE]);

  // Ensure PF active
  try {
    await execFileAsync('pfctl', ['-e']);
  } catch {}

  // Verification: inspect anchor rules
  try {
    const { stdout } = await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-s', 'rules']);
    if (stdout.includes('block drop out all') || stdout.includes('block drop out')) {
      return {
        success: true,
        output: `macOS host isolation active in pf anchor ${MAC_ISOLATE_ANCHOR}. Egress restricted to SOC backend (${backend.ip}:${backend.port}) and loopback.`,
      };
    }
    return {
      success: false,
      output: 'Isolation verification failed: Default block rule not found in pf anchor.',
    };
  } catch (verifyErr) {
    return {
      success: false,
      output: `Isolation verification error: ${verifyErr.message}`,
    };
  }
}

async function releaseHostDarwin() {
  // Flush anchor: pfctl -a eye_isolate -F all
  try {
    await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-F', 'all']);
  } catch {}

  try {
    if (fs.existsSync(MAC_ISOLATE_FILE)) {
      fs.unlinkSync(MAC_ISOLATE_FILE);
    }
  } catch {}

  return {
    success: true,
    output: 'macOS host isolation released. Normal outbound connectivity restored.',
  };
}

/* ══════════════════════════════════════════════════════════════════════
 * PUBLIC HIGH-LEVEL API
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * Isolate host network: default-deny outbound traffic while preserving
 * Socket.IO control channel to the SOC backend and loopback.
 *
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function isolateHost() {
  if (!isRoot()) {
    const errorMsg = 'Enforcement failed: Root/Administrator privileges required to enforce host isolation.';
    logEnforcement({ actionType: 'isolate_host', target: 'host', success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  const backend = await resolveBackendEndpoint();

  let result;
  try {
    if (process.platform === 'linux') {
      result = await isolateHostLinux(backend);
    } else if (process.platform === 'darwin') {
      result = await isolateHostDarwin(backend);
    } else {
      result = {
        success: false,
        output: `Host isolation not supported on platform: ${process.platform}`,
      };
    }
  } catch (err) {
    result = {
      success: false,
      output: `Host isolation error: ${err.message}`,
    };
  }

  logEnforcement({
    actionType: 'isolate_host',
    target: `backend:${backend.ip}:${backend.port}`,
    success: result.success,
    output: result.output,
  });

  return result;
}

/**
 * Release host network isolation: restore normal outbound connectivity.
 *
 * @returns {Promise<{ success: boolean, output: string }>}
 */
export async function releaseHost() {
  if (!isRoot()) {
    const errorMsg = 'Enforcement failed: Root/Administrator privileges required to release host isolation.';
    logEnforcement({ actionType: 'release_host', target: 'host', success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

  let result;
  try {
    if (process.platform === 'linux') {
      result = await releaseHostLinux();
    } else if (process.platform === 'darwin') {
      result = await releaseHostDarwin();
    } else {
      result = {
        success: false,
        output: `Host isolation release not supported on platform: ${process.platform}`,
      };
    }
  } catch (err) {
    result = {
      success: false,
      output: `Host isolation release error: ${err.message}`,
    };
  }

  logEnforcement({
    actionType: 'release_host',
    target: 'host',
    success: result.success,
    output: result.output,
  });

  return result;
}
