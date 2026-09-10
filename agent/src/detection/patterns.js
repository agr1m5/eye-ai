// IPv4 — deliberately loose (doesn't validate 0-255 ranges) since log
// data is the input, not user-facing validation; good enough to extract
// candidates from free-form text.
export const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

export const FAILED_LOGIN_KEYWORDS =
  /failed login|failed password|authentication failed|authentication failure|invalid password|login failure|unauthorized|auth failure/i;

// Lightweight, descriptive tags only — not a severity/attack classification.
// classify.js turns a subset of these into real threat candidates.
export const SUSPICIOUS_PATTERNS = [
  { pattern: /\bunion\b.*\bselect\b|\bor\b\s*'?\d+'?\s*=\s*'?\d+|;--|\bdrop\s+table\b/i, tag: "sql-like" },
  { pattern: /<script|onerror=|javascript:/i, tag: "xss-like" },
  { pattern: /\.\.\/|\.\.\\|%2e%2e%2f/i, tag: "path-traversal-like" },
  {
    pattern: /(?:[;&|`$]\s*(?:cat|ls|wget|curl|nc|bash|sh|zsh|rm|chmod|whoami|id|uname)\b|\b(?:cat|ls|wget|curl|nc|bash|sh|zsh|rm|chmod|whoami|id|uname)\b\s*[;&|`$]|\b(?:bash|sh|zsh)\s+-c\s+["'][^"']*[;&|`$])/i,
    tag: "command-injection-like",
  },
  {
    pattern: /\b(?:nmap|hydra|nikto|sqlmap|masscan|tcpdump|wireshark|metasploit|gobuster)\b/i,
    tag: "recon-tool-like",
  },
  {
    pattern: /\/etc\/(?:passwd|shadow|sudoers)|\.ssh\/id_|\.aws\/credentials|\.env\b/i,
    tag: "sensitive-file-like",
  },
  {
    pattern: /:(?:4444|1337|6667|8888|9001|31337|5555)\b/i,
    tag: "c2-beacon-like",
  },
];
