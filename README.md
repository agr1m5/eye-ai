# 🛡️ Eye — AI-Augmented Autonomous Security Operations Center (SOC)

<p align="center">
  <img src="client/public/vite.svg" width="80" height="80" alt="Eye Logo" />
</p>

<p align="center">
  <b>Next-Generation Real-Time Threat Detection, Cross-Correlation, Forensic Analysis & AI Copilot for Modern Cyber Defense.</b>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=for-the-badge&logo=linux" alt="Platform" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/Node.js-18%2B%20%7C%2020%2B%20LTS-green?style=for-the-badge&logo=node.js" alt="Node.js" /></a>
  <a href="https://react.dev"><img src="https://img.shields.io/badge/React-18.3-61DAFB?style=for-the-badge&logo=react" alt="React" /></a>
  <a href="https://www.mongodb.com"><img src="https://img.shields.io/badge/MongoDB-7.0%2B-47A248?style=for-the-badge&logo=mongodb" alt="MongoDB" /></a>
  <a href="https://socket.io"><img src="https://img.shields.io/badge/Socket.IO-4.7%2B-010101?style=for-the-badge&logo=socket.io" alt="Socket.IO" /></a>
  <a href="https://www.docker.com"><img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker" alt="Docker" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License" /></a>
</p>

---

## 📖 Overview

**Eye** is an enterprise-grade, real-time Security Operations Center (SOC) platform designed to defend infrastructure and endpoints against emerging threats. It combines lightweight, edge-native telemetry collectors with backend correlation engines, interactive threat visualizers, and a local or cloud-powered **AI SOC Analyst Copilot**.

Whether monitoring a standalone workstation or a fleet of Linux/macOS servers, Eye provides zero-overhead log processing, instant alert translation, automated incident grouping, and compliance reporting.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| ⚡ **Live Telemetry Gateway** | Bi-directional WebSocket pipeline streaming events, process diffs, network connections, and system auth logs in real time. |
| 🧠 **AI SOC Analyst Copilot** | Multi-turn conversational AI (powered by **Ollama / Llama 3.2** locally or OpenAI) that explains complex threats, suggests remediation, and analyzes logs. |
| 🎯 **Automated MITRE ATT&CK Mapping** | Automatically tags detected threats with standard MITRE tactics, techniques, and severity scoring (Critical, High, Medium, Low). |
| ⚡ **Live Kill-Chain Attack Graph** | 6-stage Lockheed Martin & MITRE ATT&CK progression visualizer with one-click active SOAR countermeasures. |
| 🚨 **Incident Correlation & Timeline** | Automatically correlates related security events sharing an entity or IP into unified incident cases with full audit notes. |
| 📁 **Forensic Log Importer** | Ingests and extracts indicators of compromise (IoCs) from raw uploads (`auth.log`, `access.log`, `syslog`, JSON). |
| 📄 **Executive PDF Reporting** | Generates professional, printable compliance and incident summary reports on demand. |
| 🍯 **Honeytoken Deception Defense** | Embedded canary file tripwires detecting unauthorized file access and credential tampering. |
| 🐧 **Native Linux & macOS Support** | Out-of-the-box launchers, Docker Compose support, and native `systemd` daemon automation. |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Eye Web SOC Client                                │
│       React 18 • Vite • Tailwind CSS • Lucide • Chart.js • Leaflet          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP REST / WebSocket (Port 5180 ➔ 5050)
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                       Eye SOC Server Engine                             │
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
│                    Eye Autonomous Endpoint Agent                        │
│  • Linux: journalctl / auth.log • ss socket audit • ps process tree         │
│  • macOS: Unified Log stream • lsof socket audit • POSIX process snapshot   │
│  • Edge Classifiers: SQLi, XSS, Path Traversal, Brute-Force, Honeytokens   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option 1: One-Command Automated Launcher (Recommended)

Clone the repository and run the interactive launcher:
```bash
git clone https://github.com/agr1m5/log-sage.git
cd log-sage

# Launch full Web SOC + Agent
./start.sh

# Or for Native Desktop Electron Window:
./start.sh desktop
```

*For Linux-specific environments, you can also use `./start-linux.sh`.*

---

### Option 2: Docker Compose (Zero-Config Container Stack)

Run MongoDB, the Backend Server, and the Nginx-optimized Frontend Client via Docker:
```bash
docker compose up -d
```
- **Web Dashboard**: [http://localhost:5180](http://localhost:5180)
- **API Server**: [http://localhost:5000](http://localhost:5000)
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

#### 3. Start Development Services
```bash
# Terminal 1: Start Client and Server concurrently
npm run dev

# Terminal 2: Start Endpoint Telemetry Agent
npm run agent
```

Access the dashboard at **[http://localhost:5180](http://localhost:5180)**.

---

## 🤖 Local AI Copilot Setup (Ollama)

Eye includes native support for running **100% private, local AI models** via Ollama:

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
3. Start the Ollama server (if not already running as a service):
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

## 📡 Agent Pairing Flow

1. Open the Eye Dashboard at [http://localhost:5180](http://localhost:5180).
2. Navigate to **Agent Pairing** in the navigation sidebar.
3. Click **Pair this device** to generate a cryptographically signed registration token.
4. Copy the generated token into `agent/.env`:
   ```env
   AGENT_TOKEN=your_generated_token_here
   ```
5. Start or restart the agent (`npm run agent` or `sudo systemctl restart eye-agent`).

---

## 📂 Repository Structure

```
.
├── .github/                # GitHub Actions CI workflows & issue templates
├── agent/                  # Endpoint telemetry agent (Linux & macOS collectors)
│   ├── src/collectors/     # System log, network, process & honeytoken collectors
│   ├── src/detection/      # Regex signature classifiers & brute-force trackers
│   ├── src/correlation/    # Sliding-window incident correlation engine
│   └── src/transport/      # Resilient Socket.IO transport client with offline queue
├── client/                 # React 18 + Vite SOC frontend dashboard
│   ├── src/components/     # Modular SOC UI components (threats, incidents, charts, chat)
│   ├── src/context/        # Auth & real-time Socket providers
│   └── src/pages/          # Top-level view routes & investigation rooms
├── electron/               # Native Electron desktop wrapper and preload bridge
├── server/                 # Express + Socket.IO backend REST API
│   ├── src/controllers/    # Auth, threat, incident, report & chat handlers
│   ├── src/models/         # Mongoose database schemas
│   ├── src/services/       # AI LLM service, GeoIP service, PDF generator
│   └── src/routes/         # Protected API route endpoints
├── docker-compose.yml      # Multi-container orchestration stack
├── start.sh                # Universal startup and bootstrap script
└── start-linux.sh          # Linux-tailored environment manager & systemd installer
```

---

## 🛡️ Default Testing Credentials

For local testing, pre-seeded administrator access:
- **Email**: `testsoc@eye.local`
- **Password**: `Eye@123`

---

## 🤝 Contributing

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming standards, commit conventions, and pull request procedures.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
