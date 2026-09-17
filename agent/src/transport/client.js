import { io } from "socket.io-client";
import { config } from "../config.js";
import { isolateHost, releaseHost } from "../enforcement/isolation.js";
import { quarantineFile, releaseFile } from "../enforcement/quarantine.js";

export class AgentTransport {
  constructor({ onLog = console.log } = {}) {
    this.onLog = onLog;
    this.buffer = [];
    this.activityBuffer = [];
    this.connected = false;
    this.socket = null;
  }

  connect() {
    // Connect to the /agent namespace on the SOC backend
    const rawUrl = (config.backendUrl || "http://localhost:5050").replace(/\/$/, "");
    const agentNamespaceUrl = rawUrl.endsWith("/agent") ? rawUrl : `${rawUrl}/agent`;

    this.socket = io(agentNamespaceUrl, {
      auth: {
        token: config.agentToken,
        agentToken: config.agentToken,
        userId: config.userId,
        role: "agent",
      },
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionDelay: 2000,
      reconnectionDelayMax: 30000,
    });

    this.socket.on("connect", () => {
      this.connected = true;
      this.onLog(`Connected to Eye SOC at ${agentNamespaceUrl}`);
      this._flushBuffer();
      this._flushActivities();
    });

    this.socket.on("disconnect", (reason) => {
      this.connected = false;
      this.onLog(`Disconnected (${reason}) — buffering findings locally until reconnected`);

      if (reason === "io server disconnect") {
        this.socket.connect();
      }
    });

    this.socket.on("connect_error", (err) => {
      this.onLog(`Connection error: ${err.message}`);
    });

    // Send heartbeat
    this._heartbeatTimer = setInterval(() => {
      if (this.connected) {
        this.socket.emit("agent:heartbeat", {
          metrics: {
            uptime: process.uptime(),
            memory: process.memoryUsage().rss,
          },
        });
      }
    }, config.heartbeatIntervalMs);

    // Setup SOAR active defense command listeners
    this._setupDefenseHandlers();

    return this;
  }

  _setupDefenseHandlers() {
    if (!this.socket) return;

    this.blockedIps = new Set();
    this.hostIsolated = false;

    this.socket.on("agent:command:contain", async (cmd) => {
      this.onLog(`[SOAR Containment] Received: ${cmd.actionType} for target: ${cmd.target}`);
      const receipt = {
        actionId: cmd.actionId,
        actionType: cmd.actionType,
        target: cmd.target,
        timestamp: new Date().toISOString(),
        success: false,
        output: '',
      };

      try {
        if (cmd.actionType === 'kill_process') {
          const match = String(cmd.target).match(/\d+/);
          if (match) {
            const pid = parseInt(match[0], 10);
            try {
              process.kill(pid, 'SIGKILL');
              receipt.success = true;
              receipt.output = `Process PID ${pid} terminated via SIGKILL.`;
            } catch (kErr) {
              receipt.output = `Process PID ${pid} not active or permission denied (${kErr.message})`;
              receipt.success = kErr.code === 'ESRCH'; // ESRCH means process already gone (contained)
            }
          } else {
            receipt.output = `Could not parse PID from target: ${cmd.target}`;
          }
        } else if (cmd.actionType === 'block_ip') {
          const ip = String(cmd.target).trim();
          this.blockedIps?.add(ip);
          receipt.success = true;
          receipt.output = `Firewall block active for IP: ${ip} (simulation)`;
        } else if (cmd.actionType === 'isolate_host') {
          const res = await isolateHost();
          receipt.success = res.success;
          receipt.output = res.output;
          if (res.success) {
            this.hostIsolated = true;
          }
        } else if (cmd.actionType === 'quarantine_file') {
          const filePath = cmd.filePath || cmd.target;
          const res = await quarantineFile(filePath, cmd.actionId);
          receipt.success = res.success;
          receipt.output = res.output;
          receipt.hash = res.hash || null;
        }

        this.onLog(`[SOAR Containment] Status: ${receipt.output} (success: ${receipt.success})`);
        this.socket.emit("agent:contain:receipt", receipt);
      } catch (err) {
        receipt.output = `Containment error: ${err.message}`;
        receipt.success = false;
        this.onLog(`[SOAR Containment] Exception: ${err.message}`);
        this.socket.emit("agent:contain:receipt", receipt);
      }
    });

    this.socket.on("agent:command:release", async (cmd) => {
      this.onLog(`[SOAR Release] Releasing: ${cmd.actionType} on ${cmd.target}`);
      if (cmd.actionType === 'block_ip') {
        const ip = String(cmd.target).trim();
        this.blockedIps?.delete(ip);
        this.onLog(`[SOAR Release] block_ip release: unblocked ${ip} in local table.`);
      } else if (cmd.actionType === 'isolate_host') {
        const res = await releaseHost();
        this.hostIsolated = false;
        this.onLog(`[SOAR Release] isolate_host release result: ${res.output}`);
      } else if (cmd.actionType === 'quarantine_file') {
        const res = await releaseFile(cmd.actionId || cmd.target);
        this.onLog(`[SOAR Release] quarantine_file release result: ${res.output}`);
      }
    });
  }

  enqueue(finding) {
    this.buffer.push(finding);
    if (this.buffer.length > config.maxBufferedFindings) {
      this.buffer.shift();
    }
  }

  enqueueActivity(activity) {
    if (this.connected && this.socket) {
      this.socket.emit("activity:single", activity);
    } else {
      this.activityBuffer.push(activity);
      if (this.activityBuffer.length > 500) {
        this.activityBuffer.shift();
      }
    }
  }

  _flushBuffer() {
    if (!this.connected || this.buffer.length === 0) return;

    const toSend = this.buffer;
    this.buffer = [];

    this.socket.emit("findings:batch", { findings: toSend }, (ack) => {
      if (!ack?.success) {
        this.onLog(`Batch send failed: ${ack?.error || "unknown error"} — re-queuing`);
        this.buffer = [...toSend, ...this.buffer];
      } else {
        this.onLog(`Sent ${ack.count} finding(s) to SOC`);
      }
    });
  }

  _flushActivities() {
    if (!this.connected || this.activityBuffer.length === 0 || !this.socket) return;

    const toSend = this.activityBuffer.splice(0, 10);
    for (const act of toSend) {
      this.socket.emit("activity:single", act);
    }
  }

  flush() {
    this._flushBuffer();
    this._flushActivities();
  }

  stop() {
    clearInterval(this._heartbeatTimer);
    this.socket?.disconnect();
  }
}
