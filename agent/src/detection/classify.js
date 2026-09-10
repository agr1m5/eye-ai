import { SUSPICIOUS_PATTERNS, FAILED_LOGIN_KEYWORDS } from "./patterns.js";
import { config } from "../config.js";

const TAG_TO_TYPE = {
  "sql-like": "sql_injection",
  "xss-like": "xss",
  "path-traversal-like": "directory_traversal",
  "command-injection-like": "command_injection",
  "c2-beacon-like": "c2_beacon",
  "recon-tool-like": "recon_scanner",
  "sensitive-file-like": "sensitive_data_access",
};

const BASE_SEVERITY = {
  sql_injection: "high",
  command_injection: "critical",
  directory_traversal: "high",
  xss: "medium",
  c2_beacon: "critical",
  recon_scanner: "medium",
  sensitive_data_access: "high",
};

const BRUTE_FORCE_THRESHOLD = 5;
const BRUTE_FORCE_HIGH_THRESHOLD = 10;

function bruteForceSeverity(count) {
  return count >= BRUTE_FORCE_HIGH_THRESHOLD ? "high" : "medium";
}

// Stateful — tracks failed-login timestamps per IP in a rolling window,
// since (unlike the file-based server pipeline) there's no natural
// "end of log" moment to count against. State lives only in memory here
// and is never itself transmitted — only the resulting findings are.
export class ThreatClassifier {
  constructor({
    bruteForceWindowMs = config.bruteForceWindowMinutes * 60_000,
  } = {}) {
    this.bruteForceWindowMs = bruteForceWindowMs;
    this.failedLoginsByIp = new Map(); // ip -> timestamp[]
    this.lastBruteForceFlaggedAt = new Map(); // ip -> timestamp, cooldown so we don't re-fire every single subsequent failure
  }

  _pruneOld(timestamps, now) {
    return timestamps.filter((t) => now - t <= this.bruteForceWindowMs);
  }

  // Call for every event that represents an authentication attempt
  // failure. Returns a brute_force candidate if the IP just crossed the
  // threshold and isn't in cooldown, otherwise null.
  _trackFailedLogin(ip, timestampMs) {
    if (!ip) return null;

    const existing = this._pruneOld(this.failedLoginsByIp.get(ip) || [], timestampMs);
    existing.push(timestampMs);
    this.failedLoginsByIp.set(ip, existing);

    const count = existing.length;
    if (count < BRUTE_FORCE_THRESHOLD) return null;

    const lastFlagged = this.lastBruteForceFlaggedAt.get(ip) || 0;
    if (timestampMs - lastFlagged < this.bruteForceWindowMs) {
      return null; // already flagged this IP recently, don't spam
    }

    this.lastBruteForceFlaggedAt.set(ip, timestampMs);
    return {
      type: "brute_force",
      severity: bruteForceSeverity(count),
      sourceIp: ip,
      evidence: [`${count} failed login attempts from ${ip} within ${this.bruteForceWindowMs / 60_000} minutes`],
    };
  }

  // event: { ip, message, raw, timestamp }
  // Returns an array of 0+ threat candidates (rarely more than one per event).
  classifyEvent(event) {
    const candidates = [];

    // Instant Critical trigger for honeytoken canary deception
    if (event.source === 'honeytoken') {
      candidates.push({
        type: 'honeytoken_breached',
        severity: 'critical',
        sourceIp: event.ip || null,
        evidence: [event.message || 'Decoy canary credential accessed'],
      });
      return candidates;
    }

    const timestampMs = event.timestamp ? new Date(event.timestamp).getTime() : Date.now();
    const searchable = [event.message, event.raw].filter(Boolean).join(" ");

    if (FAILED_LOGIN_KEYWORDS.test(searchable)) {
      const bruteForce = this._trackFailedLogin(event.ip, timestampMs);
      if (bruteForce) candidates.push(bruteForce);
    }

const BENIGN_PROCESS_REGEX = /(?:Chrome Helper|Safari|WebKit|Firefox|Spotify Helper|Slack Helper|Discord Helper|Code Helper)/i;

    for (const { pattern, tag } of SUSPICIOUS_PATTERNS) {
      if (tag === "command-injection-like" && BENIGN_PROCESS_REGEX.test(searchable)) {
        continue;
      }
      if (pattern.test(searchable)) {
        const type = TAG_TO_TYPE[tag];
        candidates.push({
          type,
          severity: BASE_SEVERITY[type],
          sourceIp: event.ip || null,
          evidence: [(event.raw || event.message || "").slice(0, 300)],
        });
        break; // one pattern match per event is enough, same reasoning as the server pipeline
      }
    }

    return candidates;
  }
}
