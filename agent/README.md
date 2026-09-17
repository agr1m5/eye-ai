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

---

## 🧪 Testing & Verification

### Standard Unit Tests (Unprivileged / CI Safe)
To execute the automated unit test suite covering process control, isolation resolution, quarantine vault operations, and server receipts:
```bash
npm test
```

### Root-Privileged Firewall Integration Test (`isolate_host`)
Because real `iptables` and `pfctl` rule insertion requires administrator/root privileges, an independent kernel integration test is available at `test/integration/isolation.root.test.js`.

> [!CAUTION]
> **SAFETY PRECAUTIONS**:
> 1. **DEDICATED VM OR CONTAINER ONLY**: Never execute this test on production hosts or machines you are logged into remotely over SSH (packet filtering containment could sever your administrative session).
> 2. **ENVIRONMENT VARIABLE GUARD**: The script strictly refuses to execute unless `EYE_ALLOW_FIREWALL_INTEGRATION_TEST=1` is explicitly provided.
> 3. **EMERGENCY RESTORATION**: The test takes pre-test firewall snapshots and registers emergency signal and exception cleanup handlers to ensure the host firewall is restored upon exit.

To execute the root integration test:
```bash
sudo EYE_ALLOW_FIREWALL_INTEGRATION_TEST=1 node test/integration/isolation.root.test.js
```
or via the npm script alias:
```bash
sudo EYE_ALLOW_FIREWALL_INTEGRATION_TEST=1 npm run test:integration:root
```

The test validates:
- [x] Correct kernel rule structure and default egress `DROP` insertion.
- [x] Real socket packet drops on non-whitelisted outbound destinations (e.g. `1.1.1.1:80`).
- [x] Functional outbound connectivity to the SOC backend control channel during isolation.
- [x] Independent post-release absence of isolation rules (`iptables` / `pfctl`).
- [x] Clean restoration of outbound network traffic to baseline.
