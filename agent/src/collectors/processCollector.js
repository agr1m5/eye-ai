import { spawn } from "child_process";
import { config } from "../config.js";

// `ps -Ao pid,user,comm` works identically on macOS and Linux (both are
// BSD-style ps implementations for this flag set) — tested against the
// real command in this environment; only the *meaning* of "this machine"
// differs, not the parsing.
function parsePsOutput(output) {
  const lines = output.trim().split("\n").slice(1); // drop the header row
  const processes = new Map(); // pid -> { pid, user, command }

  for (const line of lines) {
    const match = line.trim().match(/^(\d+)\s+(\S+)\s+(.+)$/);
    if (!match) continue;
    const [, pid, user, command] = match;
    processes.set(pid, { pid, user, command: command.trim() });
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

  async function poll() {
    if (stopped) return;
    try {
      const snapshot = await takeSnapshot();
      const changes = diffSnapshots(previousSnapshot, snapshot);
      previousSnapshot = snapshot;

      for (const change of changes) {
        onEvent({
          source: "process",
          timestamp: new Date().toISOString(),
          ip: null,
          message: `Process ${change.changeType}: ${change.command} (pid ${change.pid}, user ${change.user})`,
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
