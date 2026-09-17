import { spawn } from "child_process";
import { config } from "../config.js";

export function extractProcessName(command) {
  if (!command) return 'unknown';
  const appMatch = command.match(/\/([^\/]+)\.app(?:\/|$)/i);
  if (appMatch) return appMatch[1];
  const firstToken = command.split(/\s+/)[0];
  const parts = firstToken.split('/');
  return parts[parts.length - 1] || firstToken;
}

// `ps -Ao pid,user,comm` works identically on macOS and Linux (both are
// BSD-style ps implementations for this flag set) — tested against the
// real command in this environment; only the *meaning* of "this machine"
// differs, not the parsing.
function parsePsOutput(output) {
  const lines = output.trim().split("\n").slice(1); // drop the header row
  const processes = new Map(); // pid -> { pid, user, command, processName }

  for (const line of lines) {
    const match = line.trim().match(/^(\d+)\s+(\S+)\s+(.+)$/);
    if (!match) continue;
    const [, pid, user, command] = match;

    // Strict non-root filtering — do not monitor root or system daemon accounts
    if (user === 'root' || user.startsWith('_')) continue;

    const cmdClean = command.trim();
    const cmdLower = cmdClean.toLowerCase();

    // Filter out internal telemetry & collector subprocesses
    if (
      cmdLower.startsWith('ps ') || cmdLower === 'ps' ||
      cmdLower.startsWith('lsof ') || cmdLower === 'lsof' ||
      cmdLower.startsWith('ss ') || cmdLower === 'ss' ||
      cmdLower.includes('node src/index.js') ||
      cmdLower.includes('nodemon') ||
      cmdLower.includes('sh -c ps')
    ) {
      continue;
    }

    const processName = extractProcessName(cmdClean);
    processes.set(pid, { pid, user, command: cmdClean, processName });
  }

  return processes;
}

function diffSnapshots(previous, current) {
  const events = [];

  for (const [pid, proc] of current) {
    if (!previous.has(pid)) {
      events.push({ changeType: "started", ...proc });
    }
  }
  for (const [pid, proc] of previous) {
    if (!current.has(pid)) {
      events.push({ changeType: "stopped", ...proc });
    }
  }

  return events;
}

function takeSnapshot() {
  return new Promise((resolve, reject) => {
    const ps = spawn("ps", ["-Ao", "pid,user,command"]);
    let output = "";
    let errorOutput = "";

    ps.stdout.on("data", (chunk) => (output += chunk));
    ps.stderr.on("data", (chunk) => (errorOutput += chunk));

    ps.on("close", (code) => {
      if (code !== 0) return reject(new Error(`ps exited with code ${code}: ${errorOutput}`));
      resolve(parsePsOutput(output));
    });
    ps.on("error", reject);
  });
}

// onEvent receives a normalized event: { source: "process", timestamp, ip: null, message, raw }
export function startProcessCollector(onEvent, onError) {
  let previousSnapshot = new Map();
  let stopped = false;
  let isInitialized = false;

  async function poll() {
    if (stopped) return;
    try {
      const snapshot = await takeSnapshot();

      // Initial baseline poll — save state without dumping 100s of pre-existing processes
      if (!isInitialized) {
        previousSnapshot = snapshot;
        isInitialized = true;
        if (!stopped) setTimeout(poll, config.processPollIntervalMs);
        return;
      }

      const changes = diffSnapshots(previousSnapshot, snapshot);
      previousSnapshot = snapshot;

      for (const change of changes) {
        const displayName = change.processName ? `${change.processName} (${change.command})` : change.command;
        onEvent({
          source: "process",
          timestamp: new Date().toISOString(),
          ip: null,
          message: `Process ${change.changeType}: ${displayName} (pid ${change.pid}, user ${change.user})`,
          raw: JSON.stringify(change),
        });
      }
    } catch (err) {
      onError?.(err);
    }

    if (!stopped) setTimeout(poll, config.processPollIntervalMs);
  }

  poll();
  return () => {
    stopped = true;
  };
}

export { parsePsOutput, diffSnapshots }; // exported for testing
