# 💻 Rakshak 2.0 Client (SOC Frontend Dashboard)

The frontend interface for the Rakshak 2.0 Security Operations Center platform. Built with **React 18**, **Vite**, **Tailwind CSS**, **Lucide Icons**, **Chart.js**, and **Socket.IO Client**.

---

## ✨ Features & Interface Modules

- 📊 **Real-Time SOC Command Dashboard**:
  - Live metric KPI counters (Active Incidents, Critical Threats, Agents Online, Events/min).
  - Dynamic severity distribution doughnut charts and event velocity line graphs.
  - Interactive live event ticker with auto-scroll and severity-based color coding.
- ⚡ **Interactive Kill-Chain Attack Graph**:
  - Real-time 6-stage MITRE ATT&CK progression tracking with one-click SOAR countermeasures.
- 🚨 **Incident Investigation Room**:
  - View correlated attack chains, affected assets, and timeline of events.
  - Interactive status controls (`Open`, `Investigating`, `Contained`, `Resolved`) with audit log persistence.
  - Add analyst investigation notes in real time.
- 🤖 **AI Copilot Chat (SOC Analyst)**:
  - Conversational investigation assistant with multi-turn chat history.
  - Ask questions about MITRE tactics, log anomalies, and step-by-step remediation procedures.
  - Markdown code syntax highlighting and quick-prompt suggestions.
- 📁 **Forensic Log Importer**:
  - Drag-and-drop log ingestion (`auth.log`, `access.log`, `syslog`, JSON).
  - Instant client-side parsing summary and backend threat correlation.
- 📄 **Compliance & Executive Reports**:
  - Automated PDF report preview and instant download.
- 🔗 **Agent Pairing Manager**:
  - One-click pairing token generator for enrolling Linux and macOS endpoint agents.

---

## 🛠️ Getting Started

### 1. Installation
```bash
npm install
```

### 2. Development Server
Starts the Vite development server with Hot Module Replacement (HMR) and automatic API proxying to `http://localhost:5050`:
```bash
npm run dev
```
Open [http://localhost:5180](http://localhost:5180) in your browser.

### 3. Production Build
```bash
npm run build
```
The compiled, optimized static assets will be output to `client/dist/`.

### 4. Preview Production Build
```bash
npm run preview
```

---

## 📁 Directory Structure

```
client/src/
├── api/          # Axios HTTP client, interceptors, and API service functions
├── assets/       # Static branding assets and images
├── components/   # Reusable UI component library
│   ├── auth/     # Login, registration, and protected route wrappers
│   ├── chat/     # AI Copilot message bubbles, input bar, and conversation drawer
│   ├── common/   # Modals, badges, stat cards, loading skeletons
│   ├── dashboard/# Live event feed, severity charts, KPI overview
│   ├── incidents/# Incident cards, filter bars, audit note forms
│   ├── layout/   # Top navbar, sidebar navigation, responsive layout shell
│   └── threats/  # Threat tables, inspection drawers, MITRE badges
├── context/      # React contexts (AuthContext, SocketContext, ThemeContext)
├── hooks/        # Custom React hooks (useLiveStats, useSocket, useThreats)
├── pages/        # Top-level view routes (Dashboard, Threats, Incidents, Chat, Logs, Reports)
└── utils/        # Formatters, timestamp helpers, severity theme mappings
```
