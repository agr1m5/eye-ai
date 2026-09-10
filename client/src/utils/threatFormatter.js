/**
 * threatFormatter.js — Human-readable translation layer for cybersecurity alerts.
 *
 * Converts raw snake_case threats and cryptic MITRE codes into clear,
 * plain-English explanations that anyone can understand immediately.
 */

export const THREAT_CATALOG = {
  honeytoken_breached: {
    title: 'Honeytoken Decoy Trap Triggered',
    subtitle: 'An unauthorized process accessed a decoy canary credential file.',
    whatHappened: 'A decoy credential honeytoken placed on the host was accessed or tampered with. Legitimate applications never touch this file — this is a definitive indicator of internal reconnaissance or malware searching for credentials.',
    mitreCode: 'T1552',
    mitreName: 'Unsecured Credentials / Trap Wire',
    mitrePlain: 'Adversaries search the local filesystem for AWS keys, API tokens, and passwords.',
    tactic: 'Credential Access',
    remediation: 'Immediately isolate the host, inspect which PID touched the file, and terminate the offending process.',
  },
  command_injection: {
    title: 'Suspicious Shell Command',
    subtitle: 'A process executed a shell command using execution flags or chained operators.',
    whatHappened: 'A program on your computer executed a terminal command (using bash, sh, or python) containing special command-line operators. Malware often uses this technique to run background payloads.',
    mitreCode: 'T1059',
    mitreName: 'Command & Scripting Interpreter',
    mitrePlain: 'Adversaries abuse terminal command interpreters to execute commands, scripts, or binaries.',
    tactic: 'Execution',
    remediation: 'Check if this command was triggered by an intentional development build or a background tool.',
  },
  sql_injection: {
    title: 'Database Query Injection Attempt',
    subtitle: 'Input containing database syntax was detected in a web or API request.',
    whatHappened: 'Someone tried submitting malicious SQL code in a form or URL to trick the database into revealing unauthorized records or bypassing authentication.',
    mitreCode: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    mitrePlain: 'Adversaries manipulate vulnerable web forms and query parameters to access database servers.',
    tactic: 'Initial Access',
    remediation: 'Ensure all database queries use parameterized SQL prepared statements and validate user input.',
  },
  directory_traversal: {
    title: 'Path Traversal File Access',
    subtitle: 'An attempt to escape web folder boundaries to view system files was detected.',
    whatHappened: 'A request contained parent directory references (like ../) attempting to break out of the allowed folder to read sensitive configuration files or system directories.',
    mitreCode: 'T1083',
    mitreName: 'File & Directory Discovery',
    mitrePlain: 'Adversaries enumerate filesystem paths to locate passwords, certificates, or system binaries.',
    tactic: 'Discovery',
    remediation: 'Sanitize file path parameters and block directory traversal characters.',
  },
  brute_force: {
    title: 'Password Guessing (Brute Force)',
    subtitle: 'Multiple rapid failed authentication attempts detected from a single source.',
    whatHappened: 'An automated script or attacker tried repeatedly guessing login passwords or authentication credentials in a short window of time.',
    mitreCode: 'T1110',
    mitreName: 'Brute Force / Credential Stuffing',
    mitrePlain: 'Adversaries systematically guess passwords or credential combinations to gain access to accounts.',
    tactic: 'Credential Access',
    remediation: 'Enable multi-factor authentication (MFA), account lockout after 5 attempts, and rate limiting.',
  },
  c2_beacon: {
    title: 'Suspicious Outbound Connection (C2 Beacon)',
    subtitle: 'A local process connected to a high-risk port commonly used by malware.',
    whatHappened: 'A program initiated an outbound network connection to a suspicious external port (such as 4444, 1337, or 6667). In real attacks, this is how malware communicates with its Command & Control (C2) server.',
    mitreCode: 'T1071',
    mitreName: 'Application Layer Protocol',
    mitrePlain: 'Adversaries communicate with external servers using standard or non-standard network protocols.',
    tactic: 'Command & Control',
    remediation: 'Identify the originating process PID, kill the socket connection, and block the remote destination.',
  },
  recon_scanner: {
    title: 'Network Port Scanner / Reconnaissance',
    subtitle: 'Network probing or port scanner activity was observed on your host.',
    whatHappened: 'Scanning tools (such as nmap, hydra, or port probes) were detected querying your device to discover open services and potential vulnerabilities.',
    mitreCode: 'T1046',
    mitreName: 'Network Service Discovery',
    mitrePlain: 'Adversaries probe host and network ports to discover running services and vulnerable software.',
    tactic: 'Discovery',
    remediation: 'Review listening firewall rules and ensure all non-essential ports are closed.',
  },
  sensitive_data_access: {
    title: 'Protected File Access Attempt',
    subtitle: 'A process tried reading sensitive system credentials or secret key files.',
    whatHappened: 'A program attempted to read system password files (/etc/passwd), SSH private keys, or environment secrets (.env files).',
    mitreCode: 'T1555',
    mitreName: 'Credentials from Password Stores',
    mitrePlain: 'Adversaries search file systems for stored passwords, private keys, and environment API tokens.',
    tactic: 'Credential Access',
    remediation: 'Lock down file permissions (chmod 600) on private keys and audit access logs.',
  },
  xss: {
    title: 'Cross-Site Scripting (XSS) Injection',
    subtitle: 'Malicious browser script payload detected in request parameters.',
    whatHappened: 'An attacker submitted JavaScript or HTML tags into a request, aiming to run unauthorized code inside another user\'s browser.',
    mitreCode: 'T1059.007',
    mitreName: 'Command & Scripting: JavaScript',
    mitrePlain: 'Adversaries inject malicious browser scripts to steal session tokens or impersonate users.',
    tactic: 'Execution',
    remediation: 'Encode and sanitize all user input before rendering it into the HTML DOM.',
  },
};

/**
 * Returns complete human-readable information for any threat type.
 */
export function getHumanThreat(type = '', threat = {}) {
  const normalized = (type || '').toLowerCase().replace(/[\s-]/g, '_');
  const match = THREAT_CATALOG[normalized];

  if (match) {
    return {
      ...match,
      typeLabel: match.title,
      summary: threat.description || match.subtitle,
    };
  }

  // Fallback: capitalize snake_case gracefully
  const fallbackTitle = type
    ? type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
    : 'Unknown Threat Event';

  return {
    title:        fallbackTitle,
    subtitle:     threat.description || 'Security anomaly detected by telemetry sensor.',
    whatHappened: 'A telemetry sensor on your host identified an unusual activity pattern.',
    mitreCode:    'T1059',
    mitreName:    'General Security Detection',
    mitrePlain:   'Categorized under standard host security event monitoring.',
    tactic:       'Host Monitoring',
    remediation:  'Review the process command and source details to determine legitimacy.',
    typeLabel:    fallbackTitle,
    summary:      threat.description || 'Suspicious system activity detected.',
  };
}

/**
 * Returns a human-friendly description of where the threat came from.
 */
export function getHumanSource(source = {}) {
  if (source.ip) {
    const geoInfo = source.city || source.country ? ` (${[source.city, source.country].filter(Boolean).join(', ')})` : '';
    return `Remote IP: ${source.ip}${geoInfo}`;
  }
  if (source.processName) {
    return `Local Process: ${source.processName}${source.pid ? ` (PID ${source.pid})` : ''}`;
  }
  if (source.hostname) {
    return `Host: ${source.hostname}`;
  }
  return 'Local Device (Endpoint Sensor)';
}

export const TECHNIQUE_NAMES = {
  T1059: 'Command & Scripting (T1059)',
  'T1059.007': 'JavaScript XSS (T1059.007)',
  T1110: 'Brute Force (T1110)',
  T1190: 'Web Exploit (T1190)',
  T1083: 'File Discovery (T1083)',
  T1071: 'C2 Network (T1071)',
  T1046: 'Port Scan (T1046)',
  T1486: 'Ransomware (T1486)',
  T1068: 'Privilege Escalation (T1068)',
  T1555: 'Credential Access (T1555)',
};

export function formatTechnique(tech = '') {
  return TECHNIQUE_NAMES[tech] || tech;
}

/**
 * Converts threat status into human-friendly badges.
 */
export function getHumanStatus(status = 'new') {
  switch (status.toLowerCase()) {
    case 'new':
      return { label: 'Needs Review', color: 'text-amber-400 bg-amber-400/10 border-amber-400/30' };
    case 'acknowledged':
      return { label: 'Under Review', color: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30' };
    case 'dismissed':
      return { label: 'Resolved / Safe', color: 'text-slate-500 bg-slate-500/10 border-slate-500/30' };
    default:
      return { label: status, color: 'text-slate-400 bg-slate-400/10 border-slate-400/30' };
  }
}
