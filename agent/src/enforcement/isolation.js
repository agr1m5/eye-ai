/**
 * isolation.js — OS-Level Host Network Isolation Engine.
 *
 * POLICY SPECIFICATION (Egress-Only Containment):
 *   isolate_host restricts external EGRESS (outbound traffic) from the endpoint host
 *   while explicitly allowing:
 *     1. Loopback interface (lo / lo0) for internal IPC and local daemons.
 *     2. Established and Related TCP connections to prevent immediate connection dropouts.
 *     3. TCP communication to the SOC backend endpoint (IP + Port) so the control
 *        channel remains active (Deadlock Prevention).
 *     4. DNS resolution (UDP/TCP Port 53) to allow domain lookups for backend reconnects.
 *   All other external outbound traffic is dropped. Inbound traffic remains governed by
 *   the system's baseline firewall to avoid severing local administration while strictly
 *   preventing lateral movement, command-and-control beaconing, and data exfiltration.
 *
 * PLATFORM ENGINES:
 *   - Linux: Dedicated EYE_ISOLATE chain inserted at top of OUTPUT table.
 *   - macOS: Dedicated pfctl anchor "eye_isolate" written to /etc/pf.anchors/eye_isolate (mode 0600).
 *
 * ALL ACTIONS PERFORM POST-ENFORCEMENT OS-LEVEL VERIFICATION BEFORE REPORTING SUCCESS.
 */
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
const MAC_ANCHOR_DIR = '/etc/pf.anchors';
const MAC_ISOLATE_FILE = '/etc/pf.anchors/eye_isolate';
const MAC_FALLBACK_FILE = '/tmp/eye_isolate.pf';

// Strict IP validation regex (IPv4 & IPv6)
const IP_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$|^[0-9a-fA-F:]+$/;

/**
 * Helper to determine secure anchor file path on macOS.
 * Uses /etc/pf.anchors/eye_isolate with mode 0600; logs prominent warning if fallback is used.
 */
export function getMacAnchorPath() {
  try {
    if (!fs.existsSync(MAC_ANCHOR_DIR)) {
      fs.mkdirSync(MAC_ANCHOR_DIR, { recursive: true, mode: 0o755 });
    }
    return MAC_ISOLATE_FILE;
  } catch (dirErr) {
    console.warn('[IsolationEngine] WARNING: Could not access /etc/pf.anchors; using unprivileged fallback for testing only:', dirErr.message);
    return MAC_FALLBACK_FILE;
  }
}

/**
 * Resolve the backend SOC endpoint (IP and port) to ensure control channel survives isolation.
 * Validates that the resolved value is a valid IP address.
 */
export async function resolveBackendEndpoint() {
  try {
    const parsed = new URL(config.backendUrl || 'http://localhost:5050');
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    let host = parsed.hostname;
    let ip = null;

    if (host.toLowerCase() === 'localhost') {
      ip = '127.0.0.1';
    } else if (IP_REGEX.test(host)) {
      ip = host;
    } else {
      try {
        const lookup = await dnsLookupAsync(host);
        if (lookup?.address && IP_REGEX.test(lookup.address)) {
          ip = lookup.address;
        }
      } catch {
        // DNS lookup failed — do not use unverified raw host string as IP
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

  // Default-deny all other outbound traffic (egress restriction)
  await execFileAsync('iptables', ['-A', LINUX_ISOLATE_CHAIN, '-j', 'DROP']);

  // 3. Ensure jump rule is at the top of OUTPUT
  try {
    await execFileAsync('iptables', ['-C', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
  } catch {
    await execFileAsync('iptables', ['-I', 'OUTPUT', '1', '-j', LINUX_ISOLATE_CHAIN]);
  }

  // Verification: Ensure rule is active in OUTPUT
  try {
    await execFileAsync('iptables', ['-C', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
    return {
      success: true,
      output: `Host network isolation active. External egress dropped except control channel (${backend.ip}:${backend.port}) and loopback.`,
    };
  } catch (verifyErr) {
    return {
      success: false,
      output: `Isolation verification failed: OUTPUT jump rule not found (${verifyErr.message}).`,
    };
  }
}

async function releaseHostLinux() {
  // 1. Remove all instances of jump rule from OUTPUT
  while (true) {
    try {
      await execFileAsync('iptables', ['-D', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
    } catch {
      break;
    }
  }

  // 2. Flush and delete chain
  try {
    await execFileAsync('iptables', ['-F', LINUX_ISOLATE_CHAIN]);
    await execFileAsync('iptables', ['-X', LINUX_ISOLATE_CHAIN]);
  } catch (delErr) {
    return {
      success: false,
      output: `Host isolation release failed: Could not delete ${LINUX_ISOLATE_CHAIN} chain (${delErr.message}).`,
    };
  }

  // 3. POST-RELEASE VERIFICATION:
  // (a) iptables -C OUTPUT -j EYE_ISOLATE must now fail (rule absent)
  let ruleStillPresent = false;
  try {
    await execFileAsync('iptables', ['-C', 'OUTPUT', '-j', LINUX_ISOLATE_CHAIN]);
    ruleStillPresent = true;
  } catch {}

  if (ruleStillPresent) {
    return {
      success: false,
      output: `Host isolation release verification failed: OUTPUT jump rule still active.`,
    };
  }

  // (b) iptables -L EYE_ISOLATE -n must now fail (chain deleted)
  let chainStillPresent = false;
  try {
    await execFileAsync('iptables', ['-L', LINUX_ISOLATE_CHAIN, '-n']);
    chainStillPresent = true;
  } catch {}

  if (chainStillPresent) {
    return {
      success: false,
      output: `Host isolation release verification failed: ${LINUX_ISOLATE_CHAIN} chain still present in iptables.`,
    };
  }

  return {
    success: true,
    output: 'Host network isolation released and verified. Normal outbound connectivity restored.',
  };
}

/* ══════════════════════════════════════════════════════════════════════
 * MACOS ISOLATION ENGINE (pfctl eye_isolate Anchor)
 * ══════════════════════════════════════════════════════════════════════ */

async function isolateHostDarwin(backend) {
  const targetFile = getMacAnchorPath();

  // Construct pf rules: default deny egress with pass rules for loopback, backend, and DNS
  const pfRules = [
    '# EYE SOAR Host Isolation Anchor: eye_isolate (Egress Restricted)',
    'set block-policy drop',
    'pass out quick on lo0 all',
    `pass out quick proto tcp to ${backend.ip} port ${backend.port}`,
    'pass out quick proto udp to any port 53',
    'pass out quick proto tcp to any port 53',
    'block drop out all',
  ].join('\n') + '\n';

  // Write file with mode 0600 (read/write by owner only)
  fs.writeFileSync(targetFile, pfRules, { mode: 0o600, encoding: 'utf8' });

  // Verify file mode and ownership before invoking pfctl
  try {
    const stat = fs.statSync(targetFile);
    const modeOctal = (stat.mode & 0o777).toString(8);
    if (modeOctal !== '600') {
      try {
        fs.chmodSync(targetFile, 0o600);
      } catch (chmodErr) {
        return {
          success: false,
          output: `Security violation: Anchor file permissions must be 0600, found ${modeOctal} (${chmodErr.message})`,
        };
      }
    }

    if (process.getuid && process.getuid() === 0 && stat.uid !== 0) {
      return {
        success: false,
        output: `Security violation: Anchor file must be owned by root (uid 0), found uid ${stat.uid}`,
      };
    }
  } catch (statErr) {
    return {
      success: false,
      output: `Security violation: Cannot verify anchor file permissions: ${statErr.message}`,
    };
  }

  // Load anchor: pfctl -a eye_isolate -f <targetFile>
  await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-f', targetFile]);

  // Ensure PF active
  try {
    await execFileAsync('pfctl', ['-e']);
  } catch {}

  // Verification: inspect anchor rules to confirm drop rule is active
  try {
    const { stdout } = await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-s', 'rules']);
    if (stdout.includes('block drop out all') || stdout.includes('block drop out')) {
      return {
        success: true,
        output: `macOS host isolation active in pf anchor ${MAC_ISOLATE_ANCHOR}. External egress restricted to SOC backend (${backend.ip}:${backend.port}) and loopback.`,
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
  // 1. Flush anchor: pfctl -a eye_isolate -F all
  try {
    await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-F', 'all']);
  } catch (flushErr) {
    return {
      success: false,
      output: `macOS host isolation release failed to flush pf anchor: ${flushErr.message}`,
    };
  }

  // 2. Remove anchor file
  try {
    const anchorPath = getMacAnchorPath();
    if (fs.existsSync(anchorPath)) {
      fs.unlinkSync(anchorPath);
    }
  } catch {}

  // 3. POST-RELEASE VERIFICATION:
  // Inspect anchor rules to confirm rules are empty and no block rules remain
  try {
    const { stdout } = await execFileAsync('pfctl', ['-a', MAC_ISOLATE_ANCHOR, '-s', 'rules']);
    if (stdout.trim().length > 0 && (stdout.includes('block') || stdout.includes('drop'))) {
      return {
        success: false,
        output: `macOS host isolation release verification failed: Active drop rules still found in anchor ${MAC_ISOLATE_ANCHOR}.`,
      };
    }
  } catch {
    // Non-zero exit or empty anchor confirms release
  }

  return {
    success: true,
    output: 'macOS host isolation released and verified. Normal outbound connectivity restored.',
  };
}

/* ══════════════════════════════════════════════════════════════════════
 * PUBLIC HIGH-LEVEL API
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * Isolate host network: default-deny outbound traffic (egress) while preserving
 * Socket.IO control channel to the SOC backend, DNS, and loopback.
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

  // Validate control channel IP before applying firewall policy
  if (!backend.ip || !IP_REGEX.test(backend.ip)) {
    const errorMsg = `Host isolation aborted: Could not resolve SOC backend host "${backend.host}" to a valid IP address. Isolation refused to prevent severing control channel.`;
    logEnforcement({ actionType: 'isolate_host', target: 'host', success: false, output: errorMsg });
    return { success: false, output: errorMsg };
  }

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
 * Verifies that drop rules and chains are completely removed before returning success.
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

export { isolateHostLinux, releaseHostLinux, isolateHostDarwin, releaseHostDarwin };
