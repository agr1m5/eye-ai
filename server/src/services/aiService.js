/**
 * aiService.js — Multi-provider AI Cybersecurity Reasoning Engine.
 *
 * Supports:
 *  1. Local Ollama LLM (default: llama3 / http://localhost:11434)
 *  2. OpenAI API (if configured with API key)
 *  3. Embedded Expert Cybersecurity Knowledge Engine (offline SOC analyst fallback)
 */
import { config } from '../config/env.js';

const SYSTEM_PROMPT = `You are Rakshak AI, an elite Tier-3 SOC Analyst and Threat Hunting Assistant.
You provide precise, actionable, and technically rigorous security guidance.
Format your responses with clear markdown headings, bullet points, and code snippets when helpful.
Include relevant MITRE ATT&CK technique IDs (e.g. T1059), severity ratings, and concrete mitigation steps.`;

/**
 * Embedded Knowledge Engine for offline or fallback SOC guidance.
 */
function getExpertKnowledgeResponse(query) {
  const q = query.toLowerCase();

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

Thank you for consulting Rakshak AI. Here is the technical security assessment:

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
      const response = await fetch(`${config.ollamaBaseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: config.ollamaModel || 'llama3',
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            ...messages.map((m) => ({ role: m.role, content: m.content })),
          ],
          stream: false,
        }),
        signal: AbortSignal.timeout(6000), // 6s timeout before fallback
      });

      if (response.ok) {
        const data = await response.json();
        if (data?.message?.content) {
          return {
            content: data.message.content,
            provider: 'ollama',
            model: config.ollamaModel || 'llama3',
          };
        }
      }
    } catch (err) {
      console.warn(`[AIService] Ollama unreachable (${err.message}). Using Expert Knowledge Engine.`);
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
    content: getExpertKnowledgeResponse(latestMessage),
    provider: 'rakshak-expert-engine',
    model: 'soc-analyst-v2',
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
