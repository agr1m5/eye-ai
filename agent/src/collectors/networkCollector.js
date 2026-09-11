import { spawn } from "child_process";
import { config } from "../config.js";

// `lsof -i -P -n` regex
const LSOF_REGEX =
  /^(\S+)\s+(\d+)\s+(\S+).*?TCP\s+(\S+):(\d+)->(\S+):(\d+)\s+\((\S+)\)/;

// `ss -ntp` regex for Linux
const SS_REGEX =
  /^(?:tcp\s+)?(\S+)\s+\d+\s+\d+\s+(\S+):(\d+)\s+(\S+):(\d+)(?:\s+users:\(\("([^"]+)",pid=(\d+))?/;

function parseLsofOutput(output) {
  const lines = output.trim().split("\n").slice(1);
  const connections = new Map();

  for (const line of lines) {
    const match = line.match(LSOF_REGEX);
    if (!match) continue;

    const [, command, pid, user, localIp, localPort, remoteIp, remotePort, state] = match;

    // Strict non-root filtering
    if (user === 'root' || user.startsWith('_')) continue;

    // Filter out internal infrastructure connections
    if (
      remotePort === '5050' || remotePort === '5180' ||
      remotePort === '27017' || remotePort === '11434' ||
      command === 'lsof' || command === 'ps'
    ) {
      continue;
    }

    const key = `${pid}:${localIp}:${localPort}->${remoteIp}:${remotePort}`;
    connections.set(key, { command, pid, user, localIp, localPort, remoteIp, remotePort, state });
  }

  return connections;
}

function parseSsOutput(output) {
  const lines = output.trim().split("\n").slice(1);
  const connections = new Map();

  for (const line of lines) {
    const match = line.match(SS_REGEX);
    if (!match) continue;

    const [, state, localIp, localPort, remoteIp, remotePort, command = "process", pid = "0"] = match;
    if (state !== "ESTAB" && state !== "ESTABLISHED") continue;

    const key = `${pid}:${localIp}:${localPort}->${remoteIp}:${remotePort}`;
    connections.set(key, {
      command,
      pid,
      user: "unknown",
      localIp,
      localPort,
      remoteIp,
      remotePort,
      state: "ESTABLISHED",
    });
  }

  return connections;
}

function diffSnapshots(previous, current) {
  const events = [];
  for (const [key, conn] of current) {
    if (!previous.has(key)) events.push({ changeType: "new", ...conn });
  }
  for (const [key, conn] of previous) {
    if (!current.has(key)) events.push({ changeType: "closed", ...conn });
  }
  return events;
}

function takeSnapshotLsof() {
  return new Promise((resolve, reject) => {
    const lsof = spawn("lsof", ["-i", "-P", "-n"]);
    let output = "";
    let errorOutput = "";

    lsof.stdout.on("data", (chunk) => (output += chunk));
    lsof.stderr.on("data", (chunk) => (errorOutput += chunk));

    lsof.on("close", (code) => {
      if (code !== 0 && code !== 1) {
        return reject(new Error(`lsof exited with code ${code}: ${errorOutput}`));
      }
      resolve(parseLsofOutput(output));
    });
    lsof.on("error", reject);
  });
}

function takeSnapshotSs() {
  return new Promise((resolve, reject) => {
    const ss = spawn("ss", ["-ntp"]);
    let output = "";
    let errorOutput = "";

    ss.stdout.on("data", (chunk) => (output += chunk));
    ss.stderr.on("data", (chunk) => (errorOutput += chunk));

    ss.on("close", (code) => {
      if (code !== 0) return reject(new Error(`ss exited with code ${code}: ${errorOutput}`));
      resolve(parseSsOutput(output));
    });
    ss.on("error", reject);
  });
}

async function takeSnapshot() {
  try {
    return await takeSnapshotLsof();
  } catch (err) {
    // If lsof is missing or failed on Linux, try `ss` fallback
    if (process.platform === "linux") {
      try {
        return await takeSnapshotSs();
      } catch (ssErr) {
        throw new Error(`Neither lsof nor ss available: ${err.message}; ${ssErr.message}`);
      }
    }
    throw err;
  }
}

export function startNetworkCollector(onEvent, onError) {
  let previousSnapshot = new Map();
  let stopped = false;
  let isInitialized = false;

  async function poll() {
    if (stopped) return;
    try {
      const snapshot = await takeSnapshot();

      // Initial baseline poll — save state without dumping pre-existing sockets
      if (!isInitialized) {
        previousSnapshot = snapshot;
        isInitialized = true;
        if (!stopped) setTimeout(poll, config.networkPollIntervalMs);
        return;
      }

      const changes = diffSnapshots(previousSnapshot, snapshot);
      previousSnapshot = snapshot;

      for (const change of changes) {
        onEvent({
          source: "network",
          timestamp: new Date().toISOString(),
          ip: change.remoteIp,
          message: `Connection ${change.changeType}: ${change.command} -> ${change.remoteIp}:${change.remotePort} (${change.state})`,
          raw: JSON.stringify(change),
        });
      }
    } catch (err) {
      onError?.(err);
    }

    if (!stopped) setTimeout(poll, config.networkPollIntervalMs);
  }

  poll();
  return () => {
    stopped = true;
  };
}

export { parseLsofOutput, parseSsOutput, diffSnapshots };
