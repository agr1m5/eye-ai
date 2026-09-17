# Contributing to Eye AI 🛡️

Thank you for your interest in contributing to **Eye AI**! We welcome contributions from developers, security researchers, and DevOps engineers to improve our real-time SOC monitoring, detection rules, AI copilot capabilities, SOAR automation, and analyst UI/UX.

---

## 📋 Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors. Please be respectful, constructive, and collaborative in all discussions and code reviews.

---

## 🏗️ Repository Architecture

Eye AI is organized as an enterprise npm workspaces monorepo:

```
eye-ai/
├── client/          # Frontend React 18 SPA (Vite, Tailwind CSS, Chart.js, Lucide)
├── server/          # Backend REST & WebSocket Engine (Express, Socket.IO, Mongoose)
├── agent/           # Endpoint Telemetry Sensor & SOAR Containment Daemon
├── electron/        # Cross-platform Desktop App Shell (Electron)
├── docker-compose.yml # Containerized full-stack deployment
└── start.sh         # Interactive setup & multi-service orchestrator
```

- **`client/`**: Modern cyber defense web console with real-time kill-chain graphs, interactive MITRE ATT&CK matrix, live telemetry streaming, and conversational AI copilot.
- **`server/`**: Event correlation engine, threat intelligence aggregator, incident manager, and SOAR action dispatcher.
- **`agent/`**: Lightweight endpoint daemon for Linux/macOS that tracks active processes, inspects socket connections, trips honeytokens, and enforces real system containment.

---

## 🛠️ Development Setup

### 1. Prerequisites
- **Node.js**: `v18.0.0+` or `v20.0.0+ LTS`
- **MongoDB**: `v6.0+` or `v7.0+` (running locally on port `27017` or via Docker)
- **Git**: `v2.30+`
- **Ollama** *(Optional)*: For running local AI analyst models (e.g. `llama3.2`)

### 2. Fork and Clone
```bash
git clone https://github.com/agr1m5/eye-ai.git
cd eye-ai
```

### 3. Install Dependencies
Install all workspace dependencies from the root:
```bash
npm install
```

### 4. Configure Environment Files
Copy the example environment configurations:
```bash
cp server/.env.example server/.env
cp agent/.env.example agent/.env
```

Ensure `server/.env` contains your preferred MongoDB connection string and security keys:
```env
PORT=5050
MONGO_URI=mongodb://localhost:27017/eye-ai
JWT_SECRET=your_jwt_secret_key_here
AGENT_SHARED_TOKEN=your_secure_agent_token_here
```

### 5. Running the Application

You can start the full stack using any of the following methods:

#### Method A: NPM Workspaces (Recommended for Development)
```bash
# Start Client (Port 5180) and Server (Port 5050) concurrently
npm run dev

# Start all three: Client, Server, and Endpoint Agent
npm run all

# Or run the Endpoint Agent individually (requires root/sudo for firewall isolation)
npm run agent
```

#### Method B: Automated Shell Launchers
```bash
# macOS / Linux interactive runner
./start.sh

# Linux systemd / daemon runner
./start-linux.sh
```

---

## 🛡️ Core Engineering Guidelines

When contributing to Eye AI, please adhere to these core principles:

### 1. Verified Containment (No Fake Successes)
- Endpoint containment actions (`kill_process`, `isolate_host`, `quarantine_file`) must interact with the operating system and verify real state change before reporting success.
- Never add stubbed, simulated, or silent "always-succeed" containment handlers. If an enforcement fails or permission is denied, the agent and server must report the exact error to the analyst.

### 2. Independent Stage Actions in Visualizers
- Visual attack graphs and SOAR grids must decouple actions per stage. Clicking an action on one node must only execute that specific stage's countermeasure and update that stage's state.

### 3. Centralized API Communication
- All HTTP requests in the frontend must go through the centralized Axios client located in [`client/src/services/api.js`](client/src/services/api.js).
- Endpoints should support robust error handling and clear toast notifications (`react-hot-toast`).

### 4. Cybersecurity Design Aesthetics
- Follow the established Cyber SOC UI aesthetic: deep slate/zinc backdrops, glassmorphic card containers, vivid severity indicators (Critical = Red, High = Amber, Medium = Yellow, Safe = Cyan/Emerald), and tactical audio feedback cues.

---

## 🌿 Branching & Commit Guidelines

### Branch Naming
- `feat/<feature-name>` for new features or capabilities
- `fix/<bug-description>` for bug fixes and patches
- `docs/<topic>` for documentation improvements
- `refactor/<module>` for non-breaking code refactoring
- `test/<suite>` for test additions or fixtures

### Commit Messages
We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) standard:

```bash
feat(dashboard): add threat timeline filtering by severity
fix(agent): verify process termination with kill(pid, 0)
docs(contributing): update workspace setup and architecture guide
perf(socket): optimize telemetry payload compression
style(client): align kill-chain button padding and glow states
```

---

## 🧪 Testing & Verification

Always verify your changes before submitting a pull request:

```bash
# 1. Verify frontend build and bundling
npm run build --workspace=client

# 2. Run backend and agent test suites
npm test --workspace=server
npm test --workspace=agent

# 3. Check code formatting and clean git status
git status
```

---

## 🔒 Security Vulnerability Reporting

If you identify a security vulnerability in Eye AI:
- **Do NOT** open a public issue on GitHub.
- Submit a confidential report through GitHub Security Advisories or contact the maintainers directly via repository security contacts.
- Provide a clear Proof of Concept (PoC) and details on affected versions and environments.

---

## 📜 Pull Request Checklist

Before submitting your PR, ensure:
- [ ] Code follows monorepo conventions and existing patterns.
- [ ] No `.env` files, API keys, or production secrets are committed.
- [ ] Frontend builds cleanly (`npm run build --workspace=client`).
- [ ] New endpoints or configuration variables are documented in the respective README.
- [ ] Commit history is clean and follows Conventional Commits.

Thank you for helping make **Eye AI** safer, faster, and more powerful! 🚀
