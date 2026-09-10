# 🚀 Rakshak 2.0 Server (Backend SOC Engine)

The backend SOC engine for Rakshak 2.0. Built with **Node.js**, **Express**, **MongoDB (Mongoose)**, and **Socket.IO** to handle high-throughput event ingestion, live threat correlation, AI copilot intelligence, and forensic log analysis.

---

## 🏗️ Core Architecture & Responsibilities

- **Live Telemetry Gateway (`Socket.IO`)**: Ingests real-time batches of findings and heartbeat signals from authorized endpoint agents.
- **Threat & Incident Correlation Engine**: Groups correlated security events, deduplicates threat signals, and orchestrates incident lifecycle transitions.
- **AI SOC Analyst Copilot (`aiService`)**: Interfaces with local LLMs (via **Ollama** e.g., Llama 3.2) or cloud providers (**OpenAI**) with multi-turn security context awareness and prompt guardrails.
- **Forensic Log Importer**: Parses and analyzes raw uploaded log formats (`auth.log`, `access.log`, `syslog`, JSON) for security anomalies.
- **Automated PDF Report Generator**: Compiles executive and technical compliance reports using `pdfkit`.
- **JWT & Agent Token Authentication**: Provides secure analyst authentication with Argon2/Bcrypt password hashing and HMAC-signed agent pairing tokens.

---

## 🛠️ Getting Started

### 1. Environment Configuration
Create a `.env` file from the provided template:
```bash
cp .env.example .env
```

Key environment variables:
| Variable | Default | Description |
|---|---|---|
| `PORT` | `5050` | Server listening port |
| `NODE_ENV` | `development` | Environment mode (`development` / `production`) |
| `MONGODB_URI` | `mongodb://localhost:27017/rakshak_live` | MongoDB connection URI |
| `JWT_SECRET` | *(random 32+ char key)* | Secret key for analyst JWT tokens |
| `AGENT_TOKEN_SECRET` | *(random 32+ char key)* | Secret key for signing endpoint agent tokens |
| `AI_PROVIDER` | `ollama` | AI Provider (`ollama` or `openai`) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama service endpoint |
| `OLLAMA_MODEL` | `llama3.2:latest` | Local LLM model tag |
| `CLIENT_ORIGIN` | `http://localhost:5180` | Allowed CORS origin for web client |

### 2. Install & Run
```bash
npm install
npm run dev     # Runs with nodemon for auto-reload
npm start       # Runs in production mode
```

---

## 📡 REST API Summary

### Authentication (`/api/auth`)
- `POST /api/auth/register` — Register a new analyst account.
- `POST /api/auth/login` — Authenticate analyst and receive JWT.
- `GET /api/auth/me` — Retrieve authenticated analyst profile.

### Threats & Telemetry (`/api/threats`)
- `GET /api/threats` — Query filtered, paginated threat events.
- `GET /api/threats/stats` — Aggregate metrics (severity counts, top attack types, 24h trends).
- `GET /api/threats/:id` — Retrieve detailed threat metadata with MITRE mapping.

### Incidents & Response (`/api/incidents`)
- `GET /api/incidents` — List correlated security incidents.
- `PATCH /api/incidents/:id/status` — Transition status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`).
- `POST /api/incidents/:id/notes` — Append analyst investigation note to audit timeline.

### AI Copilot (`/api/chat`)
- `GET /api/chat/conversations` — List analyst conversation threads.
- `POST /api/chat/conversations` — Start a new investigation thread.
- `POST /api/chat/conversations/:id/messages` — Send inquiry to AI SOC Analyst.

### Forensics & Log Ingestion (`/api/logs`)
- `POST /api/logs/upload` — Upload raw log files for automated threat extraction.
- `GET /api/logs/history` — Review past log analysis results.

### Compliance Reports (`/api/reports`)
- `POST /api/reports/generate` — Generate SOC executive PDF report.
- `GET /api/reports/download/:id` — Download compiled PDF document.

### Agent Pairing (`/api/agent`)
- `POST /api/agent/pair` — Issue signed agent registration token.
- `GET /api/agent/status` — Query connected agent count and heartbeat states.

---

## ⚡ Real-Time Socket.IO Channels

| Event Name | Direction | Payload Description |
|---|---|---|
| `agent:finding` | Agent ➔ Server | Live batch of classified threat findings |
| `agent:heartbeat` | Agent ➔ Server | System health, memory, and CPU metrics |
| `threat:new` | Server ➔ Client | Broadcast newly classified threat event |
| `incident:updated` | Server ➔ Client | Real-time incident status / note update |
| `stats:update` | Server ➔ Client | Live dashboard metric refreshes |
