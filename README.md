# 🛡️ Rakshak 2.0 — AI-Augmented Security Operations Center (SOC)

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue)](https://github.com/agr1m5/log-sage)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B%20%7C%2020%2B-green)](https://nodejs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-purple)](#)

Rakshak 2.0 is a modern, real-time Security Operations Center (SOC) platform with automated threat detection, cross-correlation of endpoint events, human-readable threat translation, live geographic IP intelligence mapping, and incident management.

---

## ✨ Features

- ⚡ **Live Telemetry & Endpoint Monitoring:** Streams real-time system logs (`journalctl` / `auth.log` on Linux, Unified Log on macOS), network connections (`ss` / `lsof`), and process execution (`ps`).
- 🧠 **Smart Translation Layer:** Translates complex MITRE ATT&CK techniques, raw audit logs, and technical telemetry into plain, human-readable explanations with recommended remediation steps.
- 🌍 **Interactive Global Threat Map:** Visualizes origin countries, cities, and coordinates of external threat IPs in real time with Leaflet.
- 🔍 **Incident Management & Correlation:** Correlates multiple related findings into cohesive incident timelines with state tracking (Open, Investigating, Remediated).
- 📜 **Analyst Audit Trail:** Tracks all investigator actions (status updates, notes, manual incident triggers) for compliance and accountability.
- 🐧 **Native Linux Support:** Zero-config Docker Compose stack, executable shell launcher (`start-linux.sh`), and background `systemd` service for continuous monitoring.

---

## 🚀 Quick Start on Linux

### Option A: 1-Click Launch with Docker (Fastest)
```bash
docker compose up -d
```
- **Web Dashboard:** [http://localhost:5180](http://localhost:5180)
- **API Server:** [http://localhost:5000](http://localhost:5000)

### Option B: Native Host Execution
```bash
chmod +x start-linux.sh
./start-linux.sh
```

### Option C: Run Local Telemetry Agent
```bash
# Foreground
./start-linux.sh --agent

# Or install as a 24/7 background systemd daemon
sudo ./start-linux.sh --install-service
```

📖 **Detailed Linux instructions:** Read [LINUX_GUIDE.md](file:///Users/agrimgupta/Desktop/Rakshak2.0/LINUX_GUIDE.md).

---

## 🍏 Quick Start on macOS

```bash
# Install dependencies
npm install

# Start development client & server
npm run dev

# In another terminal, start the local endpoint agent
npm run agent
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Rakshak SOC Client                       │
│     React 18 + Vite + Tailwind CSS + Lucide Icons + Leaflet  │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket (Socket.io) / REST
┌──────────────────────────────▼──────────────────────────────┐
│                    Rakshak SOC Server                       │
│     Node.js + Express + MongoDB + GeoIP + JWT Auth          │
└──────────────────────────────▲──────────────────────────────┘
                               │ Agent Socket.io Protocol
┌──────────────────────────────┴──────────────────────────────┐
│                  Rakshak Endpoint Agent                     │
│  - System Logs (journalctl / auth.log / macOS Unified Log)  │
│  - Network Sockets (ss / lsof)                              │
│  - Processes (ps POSIX snapshots)                           │
│  - Local Regex Classifier & Correlation Engine              │
└─────────────────────────────────────────────────────────────┘
```

---

## 📄 License
MIT License. Built for proactive security operations.
