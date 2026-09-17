# 🛡️ Eye AI — Autonomous Security Operations Center (SOC)

<p align="center">
  <img src="client/public/vite.svg" width="80" height="80" alt="Eye AI Logo" />
</p>

<p align="center">
  <b>Next-Generation Real-Time Threat Detection, Cross-Correlation, Active SOAR Containment & Local AI Copilot for Modern Cyber Defense.</b>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=for-the-badge&logo=linux" alt="Platform" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-18%2B%20%7C%2020%2B%20LTS-green?style=for-the-badge&logo=node.js" alt="Node.js" /></a>
  <a href="https://react.dev"><img src="https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react" alt="React" /></a>
  <a href="https://www.mongodb.com"><img src="https://img.shields.io/badge/MongoDB-7.0%2B-47A248?style=for-the-badge&logo=mongodb" alt="MongoDB" /></a>
  <a href="https://socket.io"><img src="https://img.shields.io/badge/Socket.IO-4.7%2B-010101?style=for-the-badge&logo=socket.io" alt="Socket.IO" /></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker" alt="Docker" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License" /></a>
</p>

---

## 📖 Overview

**Eye AI** is an enterprise-grade, real-time Security Operations Center (SOC) platform designed to defend infrastructure and endpoints against emerging threats. It combines lightweight, edge-native telemetry collectors with backend correlation engines, interactive threat visualizers, and a private, local or cloud-powered **AI SOC Analyst Copilot**.

Whether monitoring a standalone workstation or a fleet of Linux and macOS servers, Eye AI delivers zero-overhead log processing, instant alert translation, automated incident grouping, verified SOAR countermeasures, and executive compliance reporting.

---

## ✨ Key Capabilities

| Feature | Description |
|---|---|
| ⚡ **Live Telemetry Gateway** | Bi-directional WebSocket pipeline streaming events, process diffs, network connections, and system authentication logs in real time. |
| 🧠 **AI SOC Analyst Copilot** | Multi-turn conversational AI (powered by local **Ollama / Llama 3.2** or OpenAI) providing threat explanations, mitigation guidance, and log forensics. |
| 🎯 **Automated MITRE ATT&CK Mapping** | Automatically classifies threats against MITRE tactics, techniques, and severity scoring (Critical, High, Medium, Low). |
| ⚡ **Live Kill-Chain Attack Graph** | 6-stage Lockheed Martin & MITRE ATT&CK visualizer with **independent, decoupled stage actions** for surgical defense execution. |
| 🛡️ **Active SOAR Containment** | Verified endpoint enforcement with zero false reporting: `kill_process` (SIGKILL process tree), `isolate_host` (firewall containment preserving SOC management socket), and `quarantine_file` (safe binary vaulting restricted to 0400). |
| 🚨 **Incident Correlation & Timeline** | Automatically correlates related security events sharing an entity, PID, or IP into unified incident cases with full audit trails. |
| 📁 **Forensic Log Importer** | Ingests and extracts indicators of compromise (IoCs) from raw uploads (`auth.log`, `access.log`, `syslog`, JSON). |
| 🍯 **Honeytoken Deception Defense** | Canary credential tripwires in `~/.eye/canary.env` detecting unauthorized file access and credential tampering with automated SOAR alerting. |
| 📑 **Multi-Tiered Analyst Navigation** | Reorganized hierarchy separating primary daily workflows (Dashboard, Threats, Incidents, Active Defense) from secondary analytical tools. |
| 📄 **Executive PDF Reporting** | Generates professional, printable compliance and incident summary reports on demand. |
| 🐧 **Native Linux & macOS Support** | Out-of-the-box shell launchers, Docker Compose stack, and native Linux `systemd` daemon automation. |

---

## ⛓️ 6-Stage Lockheed Martin Cyber Kill-Chain Grid

Eye AI models attacks across the full cyber kill-chain with independent countermeasure controls for each stage:

```
[01 Recon & Ingress] ➔ [02 Weaponization] ➔ [03 Host Execution] ➔ [04 Priv Escalation] ➔ [05 Defense Evasion] ➔ [06 C2 & Exfiltration]
```

- **Stage 01 — Recon & Ingress**: Ingress IP tracing, ASN fingerprinting, and threat intelligence geofencing (`trace_ip`).
- **Stage 02 — Weaponization**: Web attack vector inspection and WAF exploit signature quarantine (`analyze_payload`).
- **Stage 03 — Host Execution**: Active OS process tree termination via verified SIGKILL (`kill_process`).
- **Stage 04 — Privilege Escalation**: Sudo session token invalidation and PAM elevation lockouts (`lock_elevation`).
- **Stage 05 — Defense Evasion**: AWS honeytoken canary tripwire surveillance and binary vaulting (`rearm_honeytoken` / `quarantine_file`).
- **Stage 06 — C2 & Exfiltration**: Outbound egress restriction isolating the host while preserving the SOC control channel (`isolate_host`).

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Eye Web SOC Client                              │
│       React 18 • Vite • Tailwind CSS • Lucide • Chart.js • Leaflet          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP REST / WebSocket (Port 5180 ➔ 5050)
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                           Eye SOC Server Engine                             │
│       Node.js • Express • Socket.IO • Mongoose • PDFKit • Security Rules    │
├──────────────────────────────┬───────────────────────────────┬──────────────┤
│                              │                               │              │
│  ┌────────────────────────┐  │  ┌─────────────────────────┐  │  ┌─────────┐ │
│  │   MongoDB Database     │  │  │   AI Copilot Engine     │  │  │ GeoIP   │ │
│  │   Threats / Incidents  │  │  │   (Ollama / OpenAI)     │  │  │ Intel   │ │
│  └────────────────────────┘  │  └─────────────────────────┘  │  └─────────┘ │
└──────────────────────────────▲───────────────────────────────┴──────────────┘
                               │ Authenticated Agent Protocol (HMAC Token)
┌──────────────────────────────┴──────────────────────────────────────────────┐
│                    Eye Autonomous Endpoint Agent                            │
│  • Linux: journalctl / auth.log • ss socket audit • ps process tree         │
│  • macOS: Unified Log stream • lsof socket audit • POSIX process snapshot   │
│  • Edge Classifiers: SQLi, XSS, Path Traversal, Brute-Force, Honeytokens   │
│  • SOAR Enforcers: Real SIGKILL, iptables/pfctl host isolation, quarantine  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option 1: Automated Launcher (Recommended)

Clone the repository and run the interactive launcher:

```bash
git clone https://github.com/agr1m5/eye-ai.git
cd eye-ai

# Launch full Web SOC + Agent
./start.sh

# Or launch as native Desktop Electron application:
./start.sh desktop
```

*For Linux-specific environments and systemd daemon management, run `./start-linux.sh`.*

---

### Option 2: Docker Compose (Containerized Stack)

Spin up MongoDB, the Backend Server, and the Nginx-optimized Frontend Client:

```bash
docker compose up -d
```
- **Web Dashboard**: [http://localhost:5180](http://localhost:5180)
- **API Server**: [http://localhost:5050](http://localhost:5050)
- **MongoDB**: `localhost:27017`

---

### Option 3: Manual Monorepo Setup

#### 1. Install Dependencies
```bash
npm install
```

#### 2. Configure Environment Variables
```bash
# Server configuration
cp server/.env.example server/.env

# Agent configuration
cp agent/.env.example agent/.env
```

Ensure `server/.env` contains your database and JWT configurations:
```env
PORT=5050
MONGO_URI=mongodb://localhost:27017/eye-ai
JWT_SECRET=your_jwt_secret_key_here
AGENT_SHARED_TOKEN=your_secure_agent_token_here
```

#### 3. Run Development Services
```bash
# Start Client (Port 5180) and Server (Port 5050) concurrently
npm run dev

# Start all three: Client, Server, and Endpoint Agent
npm run all

# Or start the Endpoint Agent individually (requires root/sudo for firewall isolation)
npm run agent
```

Access the dashboard in your browser at **[http://localhost:5180](http://localhost:5180)**.

---

## 🤖 Local AI Copilot Setup (Ollama)

Eye AI supports **100% offline, private AI threat intelligence** powered by Ollama:

1. Install [Ollama](https://ollama.com):
   ```bash
   # macOS: Download from ollama.com or brew install ollama
   # Linux:
   curl -fsSL https://ollama.com/install.sh | sh
   ```
2. Pull the recommended security analyst model:
   ```bash
   ollama pull llama3.2:latest
   ```
3. Start the Ollama server:
   ```bash
   ollama serve
   ```
4. Verify `server/.env` contains:
   ```env
   AI_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=llama3.2:latest
   ```

*(Alternatively, set `AI_PROVIDER=openai` and specify `OPENAI_API_KEY` in `server/.env` to use cloud models).*

---

## 📡 Agent Pairing & Sensor Connection

1. Open the Eye AI Dashboard at [http://localhost:5180](http://localhost:5180).
2. Go to **Agent Pairing** (or **Host Activity**) in the navigation sidebar.
3. Click **Pair this device** to generate a cryptographically signed registration token.
4. Set the generated token in `agent/.env`:
   ```env
   AGENT_TOKEN=your_generated_token_here
   ```
5. Start or restart the agent (`npm run agent` or `sudo systemctl restart eye-agent`). The live agent status indicator will illuminate green.

---

## 🧪 Testing & Quality Assurance

Run test suites across the monorepo:

```bash
# Verify agent enforcement mechanisms (SIGKILL verification, iptables/pfctl isolation, quarantine vault)
npm test --workspace=agent

# Run root-level firewall integration tests (requires root/sudo)
sudo npm run test:root --workspace=agent

# Verify frontend build and bundle optimization
npm run build --workspace=client
```

---

## 📂 Repository Structure

```
.
├── .github/                # GitHub Actions CI workflows & templates
├── agent/                  # Endpoint telemetry agent (Linux & macOS sensors)
│   ├── src/collectors/     # System log, network, process & honeytoken collectors
│   ├── src/enforcement/    # Real SOAR enforcement (kill_process, isolation, quarantine)
│   ├── src/detection/      # Regex signature classifiers & brute-force trackers
│   ├── src/correlation/    # Sliding-window incident correlation engine
│   └── src/transport/      # Resilient Socket.IO transport client with offline queue
├── client/                 # React 18 + Vite SOC frontend dashboard
│   ├── src/components/     # Modular SOC UI components (threats, incidents, charts, chat)
│   ├── src/context/        # Auth & real-time Socket providers
│   ├── src/services/       # Unified API client layer
│   └── src/pages/          # Top-level view routes & investigation rooms
├── electron/               # Native Electron desktop wrapper and preload bridge
├── server/                 # Express + Socket.IO backend REST API
│   ├── src/controllers/    # Auth, threat, incident, defense, report & chat handlers
│   ├── src/models/         # Mongoose database schemas
│   ├── src/services/       # AI LLM service, GeoIP service, PDF generator
│   └── src/routes/         # Protected API route endpoints
├── docker-compose.yml      # Multi-container orchestration stack
├── start.sh                # Universal startup and bootstrap script
└── start-linux.sh          # Linux environment manager & systemd installer
```

---

## 🛡️ Default Testing Credentials

For local development and initial verification:
- **Email**: `testsoc@eye.local`
- **Password**: `Eye@123`

---

## 🤝 Contributing

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming conventions, core engineering rules, and pull request guidelines.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
