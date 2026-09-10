import { config } from "../config.js";

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function worseSeverity(a, b) {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

// Correlates a batch of recent threat findings by shared source IP within
// a rolling window. A cluster of 2+ findings becomes an incident finding;
// an isolated finding just stays a plain threat — it doesn't need
// "correlating" with nothing.
//
// This is intentionally simple and explainable (entity + time window,
// not a black-box model) — every correlation traces back to "these
// findings shared this IP within this time window," which matters for
// trust in a security tool. See eye-live-architecture.md Section 6.
export class CorrelationEngine {
  constructor({ windowMs = config.correlationWindowMinutes * 60_000 } = {}) {
    this.windowMs = windowMs;
    this.recentByIp = new Map(); // ip -> finding[]
  }

  _pruneOld(findings, now) {
    return findings.filter((f) => now - f._recordedAt <= this.windowMs);
  }

  // Feed each new threat finding in. Returns null if it doesn't (yet)
  // correlate with anything, or an incident-shaped finding once 2+
  // findings sharing this IP land within the window.
  ingest(finding) {
    if (!finding.sourceIp) return null;

    const now = Date.now();
    const existing = this._pruneOld(this.recentByIp.get(finding.sourceIp) || [], now);
    existing.push({ ...finding, _recordedAt: now });
    this.recentByIp.set(finding.sourceIp, existing);

    if (existing.length < 2) return null;

    const severity = existing.reduce((worst, f) => worseSeverity(worst, f.severity), "low");
    const types = [...new Set(existing.map((f) => f.type))];

    return {
      kind: "incident",
      title: `Multiple threats from ${finding.sourceIp} (${types.join(", ")})`,
      severity,
      entities: { ips: [finding.sourceIp], processes: [], users: [] },
      timeline: existing.map((f) => ({
        label: `${f.severity} ${f.type.replace(/_/g, " ")}`,
        timestamp: new Date(f._recordedAt).toISOString(),
      })),
      // explanation intentionally left for the caller to fill in via AI —
      // this engine's job is grouping, not narrative generation.
      explanation: null,
    };
  }
}
