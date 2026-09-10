# Rakshak agent

The local monitoring agent — runs on your Mac, collects system logs,
process activity, and network connections, classifies threats **entirely
locally**, and sends only the resulting findings (never raw activity) to
your Rakshak backend. See `rakshak-live-architecture.md` for the full
design and `rakshak-live-prompt.md` for the project brief this was built
from.

## Setup

```bash
cd agent
npm install
cp .env.example .env
```

Pair this device first: in the Rakshak dashboard, go to **Agent pairing**
in the sidebar, click **Pair this device**, and paste the token into
`.env` as `AGENT_TOKEN`.

```bash
npm start
```

## What it collects, and why

| Collector | Source | Method |
|---|---|---|
| System logs | macOS unified log | `log stream --style ndjson`, filtered to auth/sudo/sshd/login-window subsystems |
| Processes | Running processes | Polls `ps`, diffs against the previous snapshot, emits only started/stopped |
| Network | Active connections | Polls `lsof -i -P -n`, diffs the same way |

**Full Disk Access** is required for complete `log stream` visibility on
modern macOS — grant it to your terminal (or the packaged app, once Phase
4 wraps this in Electron) under System Settings > Privacy & Security >
Full Disk Access. Without it, log collection will be limited or fail —
the agent will surface a clear error rather than silently collecting
nothing.

## How detection works

Every event from any collector flows through the same pipeline:

```
event -> classify (regex patterns + rolling-window brute-force detection)
       -> correlate (group by shared IP within a time window)
       -> enqueue -> batched send to backend every few seconds
```

- `src/detection/classify.js` — pattern matching for SQL injection, XSS,
  directory traversal, command injection, plus stateful brute-force
  detection (N failed logins from one IP within a rolling window).
- `src/correlation/correlate.js` — groups findings sharing a source IP
  within a rolling window into one incident, rather than sending many
  disconnected alerts for what's really one attack.
- `src/transport/client.js` — batches and sends over Socket.IO,
  authenticated with the paired agent token (never your login
  credentials). Buffers locally (bounded) during a backend outage and
  automatically reconnects — including after a server-initiated
  disconnect, which Socket.IO's built-in reconnection does **not**
  cover by default (see the comment in `client.js` — this was a real
  bug caught during testing, not a hypothetical).

## What's verified vs. what needs your Mac

This was built and tested from a Linux sandbox, so:

- **Fully tested for real**: the process collector (spawned real `ps`,
  detected a real process starting and stopping), classification logic
  (including a real bug found and fixed — the brute-force keyword list
  didn't originally match OpenSSH's actual `"Failed password for..."`
  log format), correlation logic, and the entire transport layer
  (connect, batch send, disconnect buffering, bounded eviction, and
  reconnection after both client- and server-initiated disconnects) —
  against a real running Socket.IO server.
- **Parsing logic tested against realistic synthetic data, not live
  commands**: the system log collector's NDJSON parsing and the network
  collector's `lsof` output parsing are verified against sample data
  modeled on real Apple/lsof output formats, since `log stream` and
  `lsof` don't exist outside macOS.
- **Only verifiable on your actual Mac**: that `log stream` and `lsof`
  themselves spawn correctly and produce the format this code expects —
  that's the one thing that genuinely needs your machine to confirm.

## Environment variables

See `.env.example` for the full list — poll intervals, batch/heartbeat
timing, buffer size, and the brute-force/correlation time windows are
all configurable.
