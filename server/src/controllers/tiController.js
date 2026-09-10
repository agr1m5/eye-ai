/**
 * tiController.js — Threat Intelligence lookups.
 *
 * Supports:
 *   1. VirusTotal IP reputation lookup (if VIRUSTOTAL_API_KEY configured)
 *   2. NVD CVE information lookup
 *   3. MITRE ATT&CK technique details (static knowledge base)
 *   4. OWASP Top 10 category mapping (static)
 *
 * Routes:
 *   GET /api/ti/ip/:ip
 *   GET /api/ti/cve/:cveId
 *   GET /api/ti/mitre/:techniqueId
 *   GET /api/ti/owasp/:category
 */
import { config } from '../config/env.js';

/* ── MITRE ATT&CK Static Knowledge Base ─────────────────────── */
const MITRE_TECHNIQUES = {
  'T1059': {
    id:          'T1059',
    name:        'Command and Scripting Interpreter',
    tactic:      'Execution',
    tacticId:    'TA0002',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.',
    subtechniques: ['T1059.001 (PowerShell)', 'T1059.002 (AppleScript)', 'T1059.003 (Windows Command Shell)', 'T1059.004 (Unix Shell)', 'T1059.006 (Python)'],
    mitigations: ['M1038 (Execution Prevention)', 'M1026 (Privileged Account Management)', 'M1049 (Antivirus/Antimalware)'],
    detection:   'Monitor for process creation events with suspicious parent-child relationships (e.g., web server spawning cmd.exe or powershell.exe).',
    severity:    'high',
    url:         'https://attack.mitre.org/techniques/T1059/',
  },
  'T1190': {
    id:          'T1190',
    name:        'Exploit Public-Facing Application',
    tactic:      'Initial Access',
    tacticId:    'TA0001',
    description: 'Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
    subtechniques: [],
    mitigations: ['M1048 (Application Isolation and Sandboxing)', 'M1050 (Exploit Protection)', 'M1030 (Network Segmentation)', 'M1016 (Vulnerability Scanning)'],
    detection:   'Monitor application logs for anomalous traffic. Correlate with CVE intelligence for known exploits.',
    severity:    'critical',
    url:         'https://attack.mitre.org/techniques/T1190/',
  },
  'T1046': {
    id:          'T1046',
    name:        'Network Service Discovery',
    tactic:      'Discovery',
    tacticId:    'TA0007',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices including IPs, ports, and running services. Techniques include port scans and service version detection.',
    subtechniques: [],
    mitigations: ['M1042 (Disable or Remove Feature or Program)', 'M1031 (Network Intrusion Prevention)'],
    detection:   'System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Monitor for process use of network packets.',
    severity:    'medium',
    url:         'https://attack.mitre.org/techniques/T1046/',
  },
  'T1110': {
    id:          'T1110',
    name:        'Brute Force',
    tactic:      'Credential Access',
    tacticId:    'TA0006',
    description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.',
    subtechniques: ['T1110.001 (Password Guessing)', 'T1110.002 (Password Cracking)', 'T1110.003 (Password Spraying)', 'T1110.004 (Credential Stuffing)'],
    mitigations: ['M1036 (Account Use Policies)', 'M1032 (Multi-factor Authentication)', 'M1027 (Password Policies)'],
    detection:   'Monitor authentication logs for failed login attempts. Alert on X failures within N minutes from same source.',
    severity:    'high',
    url:         'https://attack.mitre.org/techniques/T1110/',
  },
  'T1486': {
    id:          'T1486',
    name:        'Data Encrypted for Impact',
    tactic:      'Impact',
    tacticId:    'TA0040',
    description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives.',
    subtechniques: [],
    mitigations: ['M1053 (Data Backup)', 'M1040 (Behavior Prevention on Endpoint)'],
    detection:   'Monitor for unusual file system activity (mass file renames, extension changes). Watch for shadow copy deletion commands.',
    severity:    'critical',
    url:         'https://attack.mitre.org/techniques/T1486/',
  },
  'T1071': {
    id:          'T1071',
    name:        'Application Layer Protocol',
    tactic:      'Command and Control',
    tacticId:    'TA0011',
    description: 'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
    subtechniques: ['T1071.001 (Web Protocols)', 'T1071.002 (File Transfer Protocols)', 'T1071.003 (Mail Protocols)', 'T1071.004 (DNS)'],
    mitigations: ['M1031 (Network Intrusion Prevention)', 'M1037 (Filter Network Traffic)'],
    detection:   'Analyze network data for uncommon patterns. Monitor DNS requests for anomalous patterns (long subdomains, high frequency).',
    severity:    'high',
    url:         'https://attack.mitre.org/techniques/T1071/',
  },
  'T1003': {
    id:          'T1003',
    name:        'OS Credential Dumping',
    tactic:      'Credential Access',
    tacticId:    'TA0006',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can then be used to perform lateral movement.',
    subtechniques: ['T1003.001 (LSASS Memory)', 'T1003.002 (Security Account Manager)', 'T1003.008 (/etc/passwd and /etc/shadow)'],
    mitigations: ['M1043 (Credential Access Protection)', 'M1026 (Privileged Account Management)', 'M1017 (User Training)'],
    detection:   'Monitor for access to LSASS, registry hives (SAM/SYSTEM/SECURITY), or /etc/shadow. Alert on Mimikatz signatures.',
    severity:    'critical',
    url:         'https://attack.mitre.org/techniques/T1003/',
  },
};

/* ── OWASP Top 10 Static Mapping ─────────────────────────────── */
const OWASP_TOP10 = {
  'A01': {
    id:          'A01:2021',
    name:        'Broken Access Control',
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction.',
    impact:      'Critical',
    prevalence:  'Common',
    mitigations: ['Deny by default except for public resources', 'Implement access control once and reuse it throughout the application', 'Invalidate session tokens after logout', 'Log access control failures and alert admins', 'Rate limit API and controller access to minimize harm from automated attack tooling'],
  },
  'A02': {
    id:          'A02:2021',
    name:        'Cryptographic Failures',
    description: 'Failures related to cryptography (or lack thereof), which often lead to exposure of sensitive data. Focus on which data requires extra protection.',
    impact:      'Critical',
    prevalence:  'Common',
    mitigations: ['Do not store sensitive data unnecessarily', 'Ensure up-to-date and strong standard algorithms are used', 'Encrypt all data in transit with TLS', 'Disable caching for responses containing sensitive data'],
  },
  'A03': {
    id:          'A03:2021',
    name:        'Injection',
    description: 'Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.',
    impact:      'Critical',
    prevalence:  'Very Common',
    mitigations: ['Use a safe API that avoids using the interpreter entirely or provides a parameterized interface', 'Use positive server-side input validation', 'Escape special characters using the specific escape syntax for that interpreter'],
  },
  'A04': {
    id:          'A04:2021',
    name:        'Insecure Design',
    description: 'Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design.',
    impact:      'High',
    prevalence:  'Moderate',
    mitigations: ['Establish and use a secure development lifecycle', 'Use threat modeling for critical authentication, access control, business logic, and key flows', 'Integrate plausibility checks at each tier'],
  },
  'A05': {
    id:          'A05:2021',
    name:        'Security Misconfiguration',
    description: 'Missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services.',
    impact:      'High',
    prevalence:  'Very Common',
    mitigations: ['A repeatable hardening process that makes it fast and easy to deploy a properly locked-down environment', 'Remove or do not install unused features', 'Review and update configurations as part of the patch management process'],
  },
};

/* ── GET /api/ti/ip/:ip ──────────────────────────────────────── */
export async function lookupIP(req, res, next) {
  try {
    const { ip } = req.params;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({ status: 'error', message: 'Invalid IP address format.' });
    }

    // Try VirusTotal if key configured
    if (config.virusTotalApiKey) {
      try {
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
          headers: { 'x-apikey': config.virusTotalApiKey },
          signal:  AbortSignal.timeout(5000),
        });

        if (vtRes.ok) {
          const vtData = await vtRes.json();
          const attrs  = vtData?.data?.attributes;
          return res.status(200).json({
            status: 'success',
            source: 'virustotal',
            data: {
              ip,
              malicious:       attrs?.last_analysis_stats?.malicious || 0,
              suspicious:      attrs?.last_analysis_stats?.suspicious || 0,
              undetected:      attrs?.last_analysis_stats?.undetected || 0,
              harmless:        attrs?.last_analysis_stats?.harmless || 0,
              country:         attrs?.country || null,
              asOwner:         attrs?.as_owner || null,
              reputation:      attrs?.reputation || 0,
              tags:            attrs?.tags || [],
              lastAnalysis:    attrs?.last_analysis_date || null,
            },
          });
        }
      } catch (_err) {
        // Fall through to mock response
      }
    }

    // Mock/heuristic response (no API key or VT failed)
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
    ];
    const isPrivate = privateRanges.some((r) => r.test(ip));

    return res.status(200).json({
      status: 'success',
      source: 'heuristic',
      data: {
        ip,
        malicious:  0,
        suspicious: 0,
        reputation: isPrivate ? 50 : 0,
        country:    null,
        asOwner:    isPrivate ? 'Private Network' : 'Unknown',
        tags:       isPrivate ? ['private'] : [],
        note:       'Configure VIRUSTOTAL_API_KEY for real threat intelligence.',
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/ti/cve/:cveId ──────────────────────────────────── */
export async function lookupCVE(req, res, next) {
  try {
    const { cveId } = req.params;
    const cveRegex = /^CVE-\d{4}-\d{4,}$/i;
    if (!cveRegex.test(cveId)) {
      return res.status(400).json({ status: 'error', message: 'Invalid CVE ID format (expected CVE-YYYY-NNNNN).' });
    }

    try {
      const nvdRes = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId.toUpperCase()}`,
        { signal: AbortSignal.timeout(6000) }
      );

      if (nvdRes.ok) {
        const nvdData = await nvdRes.json();
        const vuln    = nvdData?.vulnerabilities?.[0]?.cve;

        if (vuln) {
          const cvssV3 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData ||
                         vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
          return res.status(200).json({
            status: 'success',
            source: 'nvd',
            data: {
              id:           vuln.id,
              description:  vuln.descriptions?.find((d) => d.lang === 'en')?.value || '',
              cvssScore:    cvssV3?.baseScore || null,
              cvssVector:   cvssV3?.vectorString || null,
              cvssRating:   cvssV3?.baseSeverity || null,
              published:    vuln.published,
              lastModified: vuln.lastModified,
              references:   vuln.references?.slice(0, 5).map((r) => r.url) || [],
            },
          });
        }
      }
    } catch (_) {
      // Fall through
    }

    return res.status(200).json({
      status: 'success',
      source: 'offline',
      data: {
        id:          cveId.toUpperCase(),
        description: 'CVE data temporarily unavailable. Check https://nvd.nist.gov for details.',
        cvssScore:   null,
        references:  [`https://nvd.nist.gov/vuln/detail/${cveId.toUpperCase()}`],
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/ti/mitre/:techniqueId ──────────────────────────── */
export async function lookupMITRE(req, res, next) {
  try {
    const id  = req.params.techniqueId.toUpperCase();
    const base = id.split('.')[0];  // e.g. T1059.001 → T1059

    const technique = MITRE_TECHNIQUES[base] || MITRE_TECHNIQUES[id];
    if (!technique) {
      return res.status(404).json({
        status:  'error',
        message: `MITRE technique ${id} not in local knowledge base. Visit https://attack.mitre.org/techniques/${id}/`,
        url:     `https://attack.mitre.org/techniques/${base}/`,
      });
    }

    return res.status(200).json({ status: 'success', source: 'mitre-kb', data: technique });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/ti/owasp/:category ─────────────────────────────── */
export async function lookupOWASP(req, res, next) {
  try {
    const cat = req.params.category.toUpperCase().replace('A0', 'A').replace(/^A(\d)$/, 'A0$1');
    const key = cat.replace('A0', 'A').substring(0, 3);

    const entry = OWASP_TOP10[key];
    if (!entry) {
      return res.status(404).json({
        status:  'error',
        message: `OWASP category ${cat} not found. Valid values: A01–A10.`,
      });
    }

    return res.status(200).json({ status: 'success', source: 'owasp-kb', data: entry });
  } catch (err) {
    next(err);
  }
}
