# 📡 Eye Endpoint Monitoring Agent

The lightweight, autonomous endpoint telemetry agent for Eye. Runs locally on **Linux** and **macOS** hosts to collect system logs, process events, and network sockets, classify threats **entirely on the edge**, and stream high-fidelity findings to your Eye SOC Server.

---

## 🚀 Key Highlights

- 🔒 **Privacy-First & Zero Raw Data Leakage**: Raw system logs and private process arguments remain strictly on the host. Only cryptographically verified security findings and statistical metadata are transmitted.
- ⚡ **Cross-Platform Telemetry**:
  - **Linux**: `journalctl` / `/var/log/auth.log` log streaming, `ss` network socket inspection, `ps` process differential tracking.
  - **macOS**: `log stream --style ndjson` unified logging, `lsof -i -P -n` socket tracing, POSIX process table auditing.
- 🍯 **Honeytoken File Tripwire**: Monitors deceptive canary credential files for unauthorized access or tampering attempts.
- 🛡️ **SOAR Endpoint Containment Enforcement**: Real-time OS-level response actions verified before reporting success: `kill_process` (SIGKILL on suspicious process trees), `isolate_host` (packet filtering isolation restricting egress while keeping SOC telemetry connected), and `quarantine_file` (secure binary vault with permissions stripped to 0400).
- 🛡️ **Edge Correlation & Brute Force Detection**: Correlates multiple events sharing an origin entity within sliding time windows to prevent alert fatigue.
- 🔄 **Resilient Bounded Transport**: Buffers findings locally during network interruptions or backend maintenance and automatically re-synchronizes with exponential backoff.

---

## 🛠️ Setup & Execution

### 1. Pairing the Agent
1. Open the Eye Web Dashboard ([http://localhost:5180](http://localhost:5180)).
2. Navigate to **Agent Pairing** in the sidebar.
3. Click **Pair this device** to generate a signed pairing token.
4. Copy the token into your `agent/.env` file:
   ```bash
   cp .env.example .env
   ```
   Set `AGENT_TOKEN=<your_token_here>`

### 2. Running in Development / Foreground
```bash
npm install
npm start
```

### 3. Linux 24/7 Daemon (`systemd` Service)
To install and run the agent as a background daemon on Linux:
```bash
sudo ./start-linux.sh --install-service
```

Service management commands:
```bash
# Check service status
sudo systemctl status eye-agent

# View live agent logs
sudo journalctl -u eye-agent -f

# Restart daemon
sudo systemctl restart eye-agent
```

---

## 📊 Telemetry Collectors

| Collector | Source (Linux) | Source (macOS) | Description |
|---|---|---|---|
| **System Logs** | `journalctl` / `auth.log` | `log stream --style ndjson` | Real-time authentication, sudo, SSH, and privilege escalation auditing |
| **Processes** | `ps -eo pid,ppid,user,args` | `ps -eo pid,ppid,user,command` | Continuous snapshot diffing for suspicious binaries, reverse shells, and malicious interpreters |
| **Network Sockets** | `ss -tulpn` | `lsof -i -P -n` | Detects unauthorized listening ports, unusual outbound beacons, and abnormal socket states |
| **Honeytokens** | Filesystem Watcher | Filesystem Watcher | Alerts on read/write access to deployed honeytoken files |

---

## ⚙️ Configuration Reference (`.env`)

| Variable | Default | Description |
|---|---|---|
| `AGENT_TOKEN` | *Required* | Signed JWT authentication token from the SOC dashboard |
| `BACKEND_URL` | `http://localhost:5050` | SOC Backend Socket.IO address |
| `PROCESS_POLL_INTERVAL_MS` | `10000` | Process table diff interval (ms) |
| `NETWORK_POLL_INTERVAL_MS` | `15000` | Network socket diff interval (ms) |
| `BATCH_INTERVAL_MS` | `5000` | Interval for dispatching finding batches to backend |
| `HEARTBEAT_INTERVAL_MS` | `30000` | Health and telemetry heartbeat cadence |
| `MAX_BUFFERED_FINDINGS` | `500` | Maximum offline queue capacity before FIFO eviction |
| `BRUTE_FORCE_WINDOW_MINUTES` | `10` | Rolling time window for failed authentication grouping |
| `CORRELATION_WINDOW_MINUTES` | `10` | Window for binding related findings into an incident |
