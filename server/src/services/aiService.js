/**
 * aiService.js — Multi-provider AI Cybersecurity Reasoning Engine.
 *
 * Supports:
 *  1. Local Ollama LLM (default: llama3 / http://localhost:11434)
 *  2. OpenAI API (if configured with API key)
 *  3. Embedded Expert Cybersecurity Knowledge Engine (offline SOC analyst fallback)
 */
import { config } from '../config/env.js';

const SYSTEM_PROMPT = `You are Eye AI, an elite Tier-3 Autonomous SOC Analyst and Active Defense Command Assistant.
You provide precise, actionable, and technically rigorous security guidance.
Format your responses with clear markdown headings, bullet points, and code snippets when helpful.
Include relevant MITRE ATT&CK technique IDs (e.g. T1059), severity ratings, and concrete mitigation steps.

ACTIVE DEFENSE CAPABILITIES:
When investigating threats or when an analyst requests containment, you can suggest executable countermeasure cards using this tag format:
[ACTION:block_ip:TARGET_IP] — Block an offending IP at the firewall
[ACTION:kill_process:TARGET_PID] — Terminate a compromised process PID via SIGKILL
[ACTION:isolate_host:HOST_NAME] — Isolate the host endpoint from external egress

The Eye interface renders interactive one-click SOAR execution buttons for these action tags.`;

/**
 * Embedded Knowledge Engine for offline or fallback SOC guidance.
 */
function getExpertKnowledgeResponse(query, messages = []) {
  let q = (query || '').toLowerCase().trim();

  // If follow-up query like "more", "why", "continue", merge with preceding user message
  if ((q === 'more' || q.includes('more') || q === 'why' || q === 'continue' || q === 'how' || q.length < 6) && messages.length > 1) {
    for (let i = messages.length - 2; i >= 0; i--) {
      if (messages[i].role === 'user' && messages[i].content && messages[i].content.length > 3) {
        q = `${messages[i].content.toLowerCase()} ${q}`;
        break;
      }
    }
  }

  if (q.includes('sql injection') || q.includes('sqli')) {
    return `### 🛡️ SQL Injection (SQLi) — Threat & Mitigation Analysis

**CWE**: CWE-89 | **OWASP**: A03:2021-Injection | **MITRE**: T1190 (Exploit Public-Facing Application)

#### 1. Overview
SQL Injection occurs when untrusted user input is directly concatenated into dynamic SQL queries without parameterized controls, allowing adversaries to bypass authentication, read sensitive data, or execute arbitrary database commands.

#### 2. Attack Vectors
- **In-band SQLi**: Error-based and UNION-based data extraction.
- **Blind SQLi**: Boolean-based and Time-based inference techniques.
- **Out-of-band SQLi**: DNS or HTTP requests triggered by the database server.

#### 3. Recommended Remediation
\`\`\`sql
-- Vulnerable:
SELECT * FROM users WHERE username = '' OR '1'='1';

-- Secure (Parameterized Prepared Statement in Node.js / pg):
const query = 'SELECT * FROM users WHERE username = $1 AND active = true';
const result = await db.query(query, [sanitizedUsername]);
\`\`\`

#### 4. Hardening Checklist
- [x] Utilize ORM / Prepared Statements everywhere.
- [x] Enforce Principle of Least Privilege on database connection users.
- [x] Enable Web Application Firewall (WAF) SQLi inspection rulesets.`;
  }

  if (q.includes('mitre') || q.includes('attack') || q.includes('t1059') || q.includes('technique')) {
    return `### ⚔️ MITRE ATT&CK Framework Guidance

**Framework**: MITRE ATT&CK Enterprise Matrix | **Tactic**: Execution & Defense Evasion

#### Key Tactics Reference:
1. **Initial Access (TA0001)**: Spearphishing, Exploit Public-Facing App (T1190).
2. **Execution (TA0002)**: Command and Scripting Interpreter (T1059 - PowerShell, Bash, Python).
3. **Persistence (TA0003)**: Scheduled Task/Job (T1053), Boot or Logon Autostart (T1547).
4. **Privilege Escalation (TA0004)**: Exploitation for Privilege Escalation (T1068).
5. **Credential Access (TA0006)**: OS Credential Dumping (T1003 - LSASS, /etc/shadow).
6. **Lateral Movement (TA0008)**: Remote Services (T1021 - SSH, RDP, SMB).
7. **Exfiltration (TA0010)**: Exfiltration Over C2 Channel (T1041).

#### Actionable SOC Workflow:
- Map observed telemetry (event IDs, sysmon logs, process command lines) to standard technique IDs.
- Correlate child processes spawned from web servers or script hosts (e.g. \`w3wp.exe\` spawning \`powershell.exe\`).`;
  }

  if (q.includes('xss') || q.includes('cross-site scripting')) {
    return `### 🌐 Cross-Site Scripting (XSS) Analysis & Prevention

**CWE**: CWE-79 | **OWASP**: A03:2021-Injection | **MITRE**: T1189 (Drive-by Compromise)

#### Types:
- **Stored XSS**: Malicious payload is permanently saved in the database (e.g. user profile / comments).
- **Reflected XSS**: Payload is reflected off the web server in an immediate HTTP response (e.g. search query).
- **DOM-based XSS**: Payload executed directly on the client side via unsafe DOM manipulation (e.g. \`innerHTML\`, \`eval()\`).

#### Mitigation:
\`\`\`javascript
// 1. Context-Aware Output Encoding (React automatically escapes JSX attributes and text):
<div>{untrustedUserInput}</div>

// 2. Strict Content Security Policy (CSP) header:
Content-Security-Policy: default-src 'self'; script-src 'self' https://trustedscripts.com; object-src 'none';
\`\`\`

#### Protective Controls:
- Set \`HttpOnly\` and \`SameSite=Strict\` flags on all session cookies to prevent cookie theft.
- Sanitize HTML using libraries like DOMPurify when rich text input is strictly required.`;
  }

  if (q.includes('port scan') || q.includes('nmap') || q.includes('reconnaissance')) {
    return `### 🔍 Port Scan & Network Reconnaissance Triage

**MITRE**: T1046 (Network Service Discovery) | **Severity**: Medium/Informational

#### Indicators of Port Scans:
- Sudden burst of SYN packets across incremental destination ports (SYN stealth scan \`-sS\`).
- High volume of TCP RST packets received from closed ports.
- Sequential probes across common management ports (22, 80, 443, 3389, 8080).

#### SOC Incident Response Steps:
1. **Source Attribution**: Verify if the source IP is internal (vulnerability scanner, IT audit) or external unauthorized IP.
2. **Target Assessment**: Determine whether probed ports are open and running vulnerable service versions.
3. **Automated Blocking**: If external adversary, apply firewall/iptables drop rules for the source IP:
\`\`\`bash
sudo iptables -A INPUT -s <OFFENDING_IP> -j DROP
\`\`\`
4. **Log Review**: Check authentication logs on target hosts for follow-up brute force attempts.`;
  }

  if (q.includes('ransomware') || q.includes('malware') || q.includes('incident response')) {
    return `### 🚨 Ransomware / Malware Incident Response Playbook

**Severity**: Critical | **MITRE**: T1486 (Data Encrypted for Impact)

#### Phase 1: Immediate Containment (Minutes 0–15)
- [ ] **Isolate Host**: Disconnect the infected system from the network immediately (physically or disable NIC). Do not power off (preserve volatile memory/RAM).
- [ ] **Block C2 Indicators**: Null-route malicious domains and IPs on border firewalls/DNS resolvers.
- [ ] **Revoke Credentials**: Force credential resets for compromised service accounts and domain admins.

#### Phase 2: Eradication & Investigation
- Capture memory snapshot with FTK Imager or \`dd\` for forensic analysis.
- Identify the Patient Zero entry vector (Phishing, RDP brute force, unpatched CVE).
- Review shadow copies, backup immutability, and lateral movement logs.

#### Phase 3: Recovery
- Rebuild affected hosts from trusted gold images.
- Restore data strictly from offline, verified-clean backups.
- Implement endpoint detection and response (EDR) agents before reconnecting to the production network.`;
  }

  // Default intelligent SOC guidance
  return `### 🛡️ SOC Security Analysis: ${query.slice(0, 50)}

Thank you for consulting Eye AI. Here is the technical security assessment:

#### 1. Security Overview
Your inquiry regarding "${query}" involves security posture, threat mitigation, or defensive operations. When evaluating this scenario:
- Identify the potential threat actor motive and access vectors.
- Validate telemetry and log sources (Syslog, Windows Event Logs, NetFlow, EDR).
- Cross-reference with NIST SP 800-61 Rev 2 Computer Security Incident Handling guidelines.

#### 2. Key Defensive Recommendations
- **Telemetry Verification**: Ensure audit logging captures both successful and anomalous events with synchronized NTP timestamps.
- **Least Privilege**: Enforce strict RBAC and multi-factor authentication (MFA) on all access vectors.
- **Continuous Monitoring**: Track indicators of compromise (IoCs) and correlate event frequency.

Feel free to ask follow-up questions regarding specific CVEs, MITRE techniques, or mitigation playbooks!`;
}

/**
 * Generate security assistant response using configured AI provider or fallback.
 */
export async function generateSecurityResponse({ messages = [], contextThreats = [], contextIncident = null }) {
  const latestMessage = messages[messages.length - 1]?.content || 'Security inquiry';

  // 1. Try Ollama if configured
  if (config.aiProvider === 'ollama' && config.ollamaBaseUrl) {
    try {
      let modelToUse = config.ollamaModel || 'llama3.2:latest';

      // Auto-detect installed model if configured model isn't found
      try {
        const tagsRes = await fetch(`${config.ollamaBaseUrl}/api/tags`, { signal: AbortSignal.timeout(2000) });
        if (tagsRes.ok) {
          const tagsData = await tagsRes.json();
          const availableModels = (tagsData?.models || []).map((m) => m.name);
          if (availableModels.length > 0 && !availableModels.includes(modelToUse)) {
            const matched = availableModels.find((m) => m.includes('llama') || m.includes('mistral') || m.includes('phi')) || availableModels[0];
            if (matched) modelToUse = matched;
          }
        }
      } catch {}

      const response = await fetch(`${config.ollamaBaseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelToUse,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            ...messages.map((m) => ({ role: m.role, content: m.content })),
          ],
          options: {
            num_predict: 350,
            temperature: 0.6,
          },
          stream: false,
        }),
        signal: AbortSignal.timeout(60000), // 60s timeout for local LLM inference
      });

      if (response.ok) {
        const data = await response.json();
        if (data?.message?.content) {
          return {
            content: data.message.content,
            provider: 'ollama',
            model: modelToUse,
          };
        }
      }
    } catch (err) {
      console.warn(`[AIService] Ollama query failed (${err.message}). Using Expert Knowledge Engine.`);
    }
  }

  // 2. Try OpenAI if API key provided
  if (config.aiProvider === 'openai' && config.openaiApiKey) {
    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.openaiApiKey}`,
        },
        body: JSON.stringify({
          model: config.openaiModel || 'gpt-4o',
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            ...messages.map((m) => ({ role: m.role, content: m.content })),
          ],
        }),
        signal: AbortSignal.timeout(8000),
      });

      if (response.ok) {
        const data = await response.json();
        const content = data?.choices?.[0]?.message?.content;
        if (content) {
          return {
            content,
            provider: 'openai',
            model: config.openaiModel || 'gpt-4o',
          };
        }
      }
    } catch (err) {
      console.warn(`[AIService] OpenAI error (${err.message}). Using Expert Knowledge Engine.`);
    }
  }

  // 3. Fallback to Embedded Expert Cybersecurity Knowledge Engine
  return {
    content: getExpertKnowledgeResponse(latestMessage, messages),
    provider: 'eye-expert-engine',
    model: 'soc-analyst-v2',
  };
}

/**
 * Generate contextual security suggestions and assistance for a host activity event.
 */
export async function generateActivitySuggestions({ activity }) {
  if (!activity) {
    return {
      safetyVerdict: 'safe',
      badgeText: 'Standard Activity',
      summary: 'No activity details provided.',
      explanation: 'General system background activity.',
      recommendations: ['Maintain regular security updates.'],
      remediationCommands: [],
    };
  }

  const { source, action = '', description = '', actor = 'system', ip, isThreat, severity, metadata = {} } = activity;
  const descLower = description.toLowerCase();
  const pid = metadata.pid || metadata.PID || null;
  const command = metadata.command || description;

  // 1. If already flagged as threat
  if (isThreat || (severity && severity !== 'none' && severity !== 'low')) {
    const sevUpper = (severity || 'high').toUpperCase();
    return {
      safetyVerdict: 'threat',
      badgeText: `Security Threat (${sevUpper})`,
      summary: `This activity triggered a security alert for "${activity.threatType || 'suspicious activity'}".`,
      explanation: `Eye detected an anomalous pattern: ${description}. This may indicate unauthorized execution, remote injection, or privilege escalation.`,
      attackImpact: {
        severity: sevUpper,
        blastRadius: 'Host Subsystem & User Workspace',
        containmentUrgency: 'Immediate Isolation Required',
        mitreTactic: 'Execution (TA0002) / Defense Evasion (TA0005)',
        cia: {
          confidentiality: { level: 'High', description: 'Severe risk of memory scraping, token exfiltration, or unauthorized file access.' },
          integrity: { level: 'High', description: 'Potential for arbitrary binary modification, unauthorized script execution, or persistent backdoors.' },
          availability: { level: 'Medium', description: 'Risk of host disruption, killed security daemons, or resource starvation.' },
        },
        potentialConsequences: [
          'Arbitrary Code Execution (RCE) bypassing standard endpoint security policies.',
          'Credential scraping and session token hijacking from memory or environment files.',
          'Establishment of persistent reverse shell or unauthorized background worker.',
          'Lateral movement toward connected internal subnet and peer devices.',
        ],
        businessRisk: 'Critical risk of data compromise, compliance breach (SOC2/GDPR), and host downtime.',
      },
      recommendations: [
        'Isolate the host or suspend the active process immediately.',
        pid ? `Inspect child/parent processes associated with PID ${pid}.` : 'Investigate the initiating executable.',
        ip ? `Block external IP ${ip} on host and border firewalls.` : 'Review authentication logs for unauthorized sessions.',
        'Preserve system audit logs and generate an incident report.',
      ],
      remediationCommands: [
        pid ? `sudo kill -9 ${pid}` : null,
        ip ? `sudo ufw deny from ${ip} to any` : null,
        pid ? `lsof -p ${pid}` : null,
      ].filter(Boolean),
    };
  }

  // 2. Network connection analysis
  if (source === 'network' || action.startsWith('connection')) {
    const isLocal = !ip || ip.startsWith('127.') || ip === '::1' || ip === 'localhost';
    const isPrivate = ip && (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip));

    if (isLocal) {
      return {
        safetyVerdict: 'safe',
        badgeText: 'Internal Loopback (Safe)',
        summary: `Local inter-process communication on loopback address (${ip || '127.0.0.1'}).`,
        explanation: `Application "${metadata.command || 'process'}" is communicating with a local service on your machine. Localhost socket traffic is standard for browsers, development servers, and desktop software.`,
        attackImpact: {
          severity: 'NEGLIGIBLE',
          blastRadius: 'Loopback Interface (127.0.0.1)',
          containmentUrgency: 'None / Normal Operation',
          mitreTactic: 'Inter-Process Communication (IPC)',
          cia: {
            confidentiality: { level: 'None', description: 'Traffic does not traverse external network wires; confined to local kernel socket queues.' },
            integrity: { level: 'None', description: 'Standard message delivery between authorized local processes.' },
            availability: { level: 'None', description: 'Negligible socket overhead on host stack.' },
          },
          potentialConsequences: [
            'No external attack surface exposed.',
            'Worst-case risk limited to unauthenticated local service querying if an SSRF bug exists in another process.',
          ],
          businessRisk: 'Zero business impact. Essential for standard developer and OS workflows.',
        },
        recommendations: [
          'No defensive action required; this is standard internal system operation.',
          pid ? `Verify application identity: run 'ps -fp ${pid}' to confirm binary origin.` : 'Verify application path if unfamiliar.',
        ],
        remediationCommands: [
          pid ? `ps -fp ${pid}` : null,
          metadata.localPort ? `lsof -i :${metadata.localPort}` : null,
        ].filter(Boolean),
      };
    }

    if (isPrivate) {
      return {
        safetyVerdict: 'low-risk',
        badgeText: 'Local Network (LAN)',
        summary: `Connection to local private subnet device (${ip}).`,
        explanation: `Application is interacting with a device inside your local area network (router, printer, or local subnet peer).`,
        attackImpact: {
          severity: 'LOW',
          blastRadius: 'Local Area Subnet (LAN)',
          containmentUrgency: 'Periodic Review',
          mitreTactic: 'Internal Network Discovery / Traffic',
          cia: {
            confidentiality: { level: 'Low', description: 'Confined to internal subnet; data is not routed over the public internet.' },
            integrity: { level: 'Low', description: 'Relies on local network perimeter security; potential risk if rogue devices are on Wi-Fi.' },
            availability: { level: 'None', description: 'Standard private network utilization.' },
          },
          potentialConsequences: [
            'Lateral discovery of shared internal services and network shares.',
            'Potential MITM vulnerability if internal subnet is untrusted or unencrypted.',
          ],
          businessRisk: 'Low operational risk when operating on secure, authenticated corporate or home subnets.',
        },
        recommendations: [
          'Confirm that the destination IP belongs to an authorized internal subnet resource.',
          'Ensure local network services require password authentication.',
        ],
        remediationCommands: [
          `ping -c 3 ${ip}`,
          pid ? `lsof -p ${pid}` : null,
        ].filter(Boolean),
      };
    }

    // External Internet IP
    const isStandardWeb = metadata.remotePort === '443' || metadata.remotePort === '80';
    return {
      safetyVerdict: isStandardWeb ? 'safe' : 'caution',
      badgeText: isStandardWeb ? 'Outbound HTTPS (Standard)' : 'External Connection (Inspect)',
      summary: `Application "${metadata.command || 'process'}" connected to remote internet IP ${ip}:${metadata.remotePort || '443'}.`,
      explanation: `Outbound internet socket established over ${isStandardWeb ? 'secure TLS/HTTPS' : `port ${metadata.remotePort}`}. Typical for cloud APIs, web browsing, package downloads, and background telemetry.`,
      attackImpact: {
        severity: isStandardWeb ? 'LOW' : 'MEDIUM',
        blastRadius: isStandardWeb ? 'Encrypted Web Gateway' : 'Untrusted Remote Internet Port',
        containmentUrgency: isStandardWeb ? 'Standard Egress' : 'Verify Destination Domain / IP',
        mitreTactic: 'Command & Control (TA0011) / Exfiltration (TA0010)',
        cia: {
          confidentiality: {
            level: isStandardWeb ? 'Low' : 'Medium',
            description: isStandardWeb ? 'Payload encrypted in-transit with TLS 1.3.' : 'Non-standard port may transmit unencrypted telemetry or credentials.'
          },
          integrity: {
            level: 'Low',
            description: 'Remote payload must be inspected and validated before execution by the application.'
          },
          availability: {
            level: 'None',
            description: 'Egress socket consumption within standard OS limits.'
          },
        },
        potentialConsequences: [
          isStandardWeb ? 'Legitimate cloud API synchronization or software update verification.' : 'Potential data exfiltration to unauthorized remote host or C2 beaconing.',
          'Covert channel communication if initiating binary is unverified.',
        ],
        businessRisk: isStandardWeb ? 'Standard operational SaaS connectivity.' : 'Potential data leakage risk and compliance notification if sensitive records are transmitted.',
      },
      recommendations: [
        `Verify destination host identity using reverse DNS or WHOIS lookup.`,
        `If this connection was not user-initiated, verify the initiating process binary with 'which ${metadata.command || 'app'}'.`,
        !isStandardWeb ? `Port ${metadata.remotePort} is non-standard for web traffic — verify why this application uses it.` : 'Check if TLS certificates are valid and uncompromised.',
      ],
      remediationCommands: [
        `whois ${ip}`,
        pid ? `lsof -i @${ip}` : null,
        `sudo ufw deny out to ${ip}`,
      ].filter(Boolean),
    };
  }

  // 3. Process execution analysis
  if (source === 'process' || action.startsWith('process')) {
    const isDevTool = descLower.includes('node') || descLower.includes('npm') || descLower.includes('vite') || descLower.includes('python');
    const isBrowser = descLower.includes('brave') || descLower.includes('chrome') || descLower.includes('safari') || descLower.includes('firefox') || descLower.includes('electron');

    if (isDevTool) {
      return {
        safetyVerdict: 'safe',
        badgeText: 'Developer Runtime (Safe)',
        summary: `Active development runtime process: ${command.slice(0, 60)}.`,
        explanation: `This process was spawned as part of your Node.js, Python, or local project environment. It is normal development activity.`,
        attackImpact: {
          severity: 'LOW',
          blastRadius: 'Project Workspace & Node Environment',
          containmentUrgency: 'Dependency Hygiene',
          mitreTactic: 'Execution: User Execution (T1204)',
          cia: {
            confidentiality: { level: 'Low', description: 'Process possesses read access to project files, .env configurations, and source code.' },
            integrity: { level: 'Low', description: 'Can write artifacts, bundle builds, and edit workspace files.' },
            availability: { level: 'Low', description: 'Local CPU and RAM consumption during compilation or watch mode.' },
          },
          potentialConsequences: [
            'Supply-chain vulnerability if an untrusted third-party npm package executes malicious install scripts.',
            'Local dev server binding to 0.0.0.0 exposing internal development routes to LAN.',
          ],
          businessRisk: 'Low direct impact; requires code review and periodic dependency audits.',
        },
        recommendations: [
          'Verify project dependencies in package.json to prevent typosquatting attacks.',
          'Run audits periodically using `npm audit` or `pip check`.',
        ],
        remediationCommands: [
          pid ? `ps -fp ${pid}` : null,
          pid ? `kill -9 ${pid}` : null,
        ].filter(Boolean),
      };
    }

    if (isBrowser) {
      return {
        safetyVerdict: 'safe',
        badgeText: 'Web Browser Process (Safe)',
        summary: `Web browser execution: ${command.slice(0, 60)}.`,
        explanation: `Modern browsers use multi-process architectures (rendering tabs, GPU acceleration, and extensions in isolated helper sandboxes).`,
        attackImpact: {
          severity: 'LOW',
          blastRadius: 'Chromium/WebKit Sandbox Isolation',
          containmentUrgency: 'Keep Browser Updated',
          mitreTactic: 'User Execution: Malicious Link (T1204.001)',
          cia: {
            confidentiality: { level: 'Low', description: 'Tabs run in separate memory spaces; cannot read OS files without sandbox escape.' },
            integrity: { level: 'None', description: 'Browser renderer cannot modify system files directly.' },
            availability: { level: 'Low', description: 'High memory utilization across active tabs and hardware GPU acceleration.' },
          },
          potentialConsequences: [
            'Untrusted web content could trigger client-side XSS or phishing within the browser tab.',
            'Malicious extensions could request excessive DOM permissions.',
          ],
          businessRisk: 'Low system risk due to OS-level sandboxing, provided software is patched.',
        },
        recommendations: [
          'Keep your web browser updated to the latest version to patch zero-day vulnerabilities.',
          'Review installed browser extensions for excessive permission requests.',
        ],
        remediationCommands: [
          pid ? `ps -fp ${pid}` : null,
        ].filter(Boolean),
      };
    }

    return {
      safetyVerdict: 'safe',
      badgeText: 'Verified Endpoint Process',
      summary: `Standard host process execution: ${command.slice(0, 60)}.`,
      explanation: `Process is running under user "${actor}". System utilities and background daemons run continuously to support OS features and active desktop software.`,
      attackImpact: {
        severity: 'LOW',
        blastRadius: 'Local Process Space (POSIX Sandboxed)',
        containmentUrgency: 'Continuous Baseline',
        mitreTactic: 'Discovery: System Information (T1082)',
        cia: {
          confidentiality: { level: 'Low', description: 'Subject to standard user access rights; cannot view other user files.' },
          integrity: { level: 'None', description: 'Cannot alter system-protected /usr or /System roots without administrative escalation.' },
          availability: { level: 'None', description: 'Controlled process memory usage.' },
        },
        potentialConsequences: [
          'Legitimate OS operation or background helper service.',
          'If process binary is replaced or hijacked, potential unauthorized background execution.',
        ],
        businessRisk: 'Nominal baseline activity. Zero operational interruption.',
      },
      recommendations: [
        'Confirm process executable originates from standard directories (/usr/bin, /Applications, /usr/local/bin).',
        'Verify running user matches appropriate privilege boundaries.',
      ],
      remediationCommands: [
        pid ? `ps -fp ${pid}` : null,
        pid ? `lsof -p ${pid}` : null,
      ].filter(Boolean),
    };
  }

  // 4. System logs / fallback
  return {
    safetyVerdict: 'safe',
    badgeText: 'System Event (Normal)',
    summary: `Host operating system log event: ${description.slice(0, 60)}.`,
    explanation: `Recorded by host security auditing subsystem. Periodic authentication status checks and daemon health checks are expected.`,
    attackImpact: {
      severity: 'NEGLIGIBLE',
      blastRadius: 'Audit Subsystem / Syslog',
      containmentUrgency: 'Log Retention',
      mitreTactic: 'Defense Evasion: Indicator Removal (T1070)',
      cia: {
        confidentiality: { level: 'None', description: 'Log contains telemetry metadata only.' },
        integrity: { level: 'None', description: 'Append-only system security logs.' },
        availability: { level: 'None', description: 'Minimal log rotation footprint.' },
      },
      potentialConsequences: [
        'Standard auditing records routine system state.',
        'If adversary modifies log files, potential log tampering or evasion.',
      ],
      businessRisk: 'Zero threat. Essential for compliance and forensic audit trails.',
    },
    recommendations: [
      'Ensure sudo sessions and administrative elevations are monitored.',
      'Check system log integrity regularly.',
    ],
    remediationCommands: [],
  };
}

/**
 * Generate a concise chat title from user query.
 */
export function generateChatTitle(query) {
  if (!query) return 'Security Consultation';
  const clean = query.replace(/[#*`_]/g, '').trim();
  return clean.length > 40 ? `${clean.substring(0, 37)}...` : clean;
}
