import { spawn } from "child_process";
import readline from "readline";
import fs from "fs";
import { IP_REGEX } from "../detection/patterns.js";

// macOS Unified Log predicate: security-relevant subsystems
const LOG_PREDICATE =
  'subsystem CONTAINS "authd" OR subsystem CONTAINS "sshd" OR eventMessage CONTAINS "sudo" OR subsystem CONTAINS "loginwindow"';

// Common Linux authentication log paths for non-journalctl fallbacks
const LINUX_LOG_PATHS = [
  "/var/log/auth.log",
  "/var/log/secure",
  "/var/log/syslog",
  "/var/log/messages",
];

function extractIp(text) {
  if (!text || typeof text !== "string") return null;
  const match = text.match(IP_REGEX);
  return match ? match[0] : null;
}

/**
 * Starts the macOS Unified Log collector using `log stream`
 */
function startDarwinLogCollector(onEvent, onError) {
  const logProcess = spawn("log", [
    "stream",
    "--style",
    "ndjson",
    "--predicate",
    LOG_PREDICATE,
  ]);

  const rl = readline.createInterface({ input: logProcess.stdout });

  rl.on("line", (line) => {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      return; // preamble or non-JSON line
    }

    const message = parsed.eventMessage || "";
    if (!message) return;

    onEvent({
      source: "log",
      timestamp: parsed.timestamp || new Date().toISOString(),
      ip: extractIp(message),
      message,
      raw: line,
    });
  });

  logProcess.stderr.on("data", (chunk) => {
    onError?.(new Error(`macOS log stream stderr: ${chunk.toString().trim()}`));
  });

  logProcess.on("error", (err) => {
    onError?.(
      new Error(
        `Could not start "log stream": ${err.message}. On macOS, Full Disk Access may be required.`
      )
    );
  });

  logProcess.on("close", (code) => {
    if (code !== 0) onError?.(new Error(`log stream exited unexpectedly with code ${code}`));
  });

  return () => {
    rl.close();
    try { logProcess.kill(); } catch {}
  };
}

/**
 * Starts the Linux system log collector.
 * Tries `journalctl -f -o json` first; falls back to tailing /var/log/auth.log or /var/log/secure.
 */
function startLinuxLogCollector(onEvent, onError) {
  let activeProcess = null;
  let activeRl = null;

  function tryJournalctl() {
    const proc = spawn("journalctl", ["-f", "-o", "json", "-n", "0"]);

    proc.on("error", (err) => {
      // If journalctl is not installed or permissions denied, try file fallback
      tryFileTail();
    });

    const rl = readline.createInterface({ input: proc.stdout });

    rl.on("line", (line) => {
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        return;
      }

      const message = parsed.MESSAGE || parsed._SYSTEMD_UNIT || "";
      if (!message) return;

      // Calculate timestamp from microsecond realtime timestamp if available
      let timestamp = new Date().toISOString();
      if (parsed.__REALTIME_TIMESTAMP) {
        const ms = Math.floor(parseInt(parsed.__REALTIME_TIMESTAMP, 10) / 1000);
        if (!isNaN(ms)) timestamp = new Date(ms).toISOString();
      }

      onEvent({
        source: "log",
        timestamp,
        ip: extractIp(message),
        message: typeof message === "string" ? message : JSON.stringify(message),
        raw: line,
      });
    });

    proc.on("close", (code) => {
      if (code !== 0 && !activeProcess) {
        tryFileTail();
      }
    });

    activeProcess = proc;
    activeRl = rl;
  }

  function tryFileTail() {
    // Find the first readable security log file
    const targetFile = LINUX_LOG_PATHS.find((p) => {
      try {
        return fs.existsSync(p) && fs.statSync(p).isFile();
      } catch {
        return false;
      }
    });

    if (!targetFile) {
      onError?.(
        new Error(
          `Linux log collector: Neither 'journalctl' nor readable auth logs (${LINUX_LOG_PATHS.join(", ")}) were accessible. Run as root/sudo or grant read access.`
        )
      );
      return;
    }

    const tailProc = spawn("tail", ["-n", "0", "-F", targetFile]);

    tailProc.on("error", (err) => {
      onError?.(new Error(`Failed to tail ${targetFile}: ${err.message}`));
    });

    const rl = readline.createInterface({ input: tailProc.stdout });

    rl.on("line", (line) => {
      if (!line.trim()) return;
      onEvent({
        source: "log",
        timestamp: new Date().toISOString(),
        ip: extractIp(line),
        message: line.trim(),
        raw: line,
      });
    });

    activeProcess = tailProc;
    activeRl = rl;
  }

  tryJournalctl();

  return () => {
    try { activeRl?.close(); } catch {}
    try { activeProcess?.kill(); } catch {}
  };
}

/**
 * Cross-platform entrypoint: delegates to macOS or Linux collectors automatically.
 */
export function startSystemLogCollector(onEvent, onError) {
  if (process.platform === "linux") {
    return startLinuxLogCollector(onEvent, onError);
  }
  return startDarwinLogCollector(onEvent, onError);
}

export { extractIp, LOG_PREDICATE }; // exported for testing
