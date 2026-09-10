# 🛡️ Eye — Linux Deployment & Operation Guide

Eye provides enterprise-grade SOC threat detection, investigation, live telemetry streaming, and automated correlation. It is fully cross-platform with first-class support for **Linux** (Ubuntu, Debian, Fedora, RHEL, CentOS, Arch, openSUSE).

---

## ⚡ Option 1: Docker Compose (Fastest — 1-Click Launch)

Runs the entire stack (React Client, Express Backend, and MongoDB) in isolated, production-ready containers.

### Prerequisites
- [Docker Engine & Docker Compose](https://docs.docker.com/engine/install/)

### Launch
```bash
# Clone the repository
git clone https://github.com/agr1m5/log-sage.git Eye2.0
cd Eye2.0

# Start all containers in the background
docker compose up -d
```

### Accessing Services
- **SOC Web Dashboard:** [http://localhost:5180](http://localhost:5180)
- **REST API & Socket.io:** [http://localhost:5000](http://localhost:5000)
- **MongoDB Database:** `localhost:27017`

### Useful Docker Commands
```bash
# View live container logs
docker compose logs -f

# Stop the stack
docker compose down

# Rebuild after updates
docker compose up -d --build
```

---

## 💻 Option 2: Native Linux Host (Developer / Standalone)

Run natively on your Linux distribution using Node.js.

### Prerequisites
1. **Node.js (v18 or v20+):**
   ```bash
   # Ubuntu / Debian
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt-get install -y nodejs

   # Fedora / RHEL
   sudo dnf install -y nodejs
   ```

2. **MongoDB:**
   ```bash
   # Ubuntu / Debian
   sudo apt-get install -y mongodb-org || sudo apt-get install -y mongodb
   sudo systemctl start mongod
   sudo systemctl enable mongod

   # Or run MongoDB in a single Docker container:
   docker run -d -p 27017:27017 --name eye-mongo mongo:7
   ```

### Quick Start with `start-linux.sh`
```bash
chmod +x start-linux.sh
./start-linux.sh
```
This script will automatically:
- Verify Node.js and MongoDB
- Create `server/.env` from `.env.example` if not present
- Install all workspace dependencies
- Start both the SOC Backend API (`:5050`) and Vite Web Client (`:5180`)

---

## 📡 Option 3: Running the Linux Telemetry Agent

The Eye Telemetry Agent monitors Linux system events, network connections, and processes in real-time.

### How it monitors Linux:
- **System Logs:** Automatically hooks into `journalctl -f -o json` (systemd journal). Falls back to `/var/log/auth.log` or `/var/log/secure` for SSH logins, `sudo` elevation, and brute-force attempts.
- **Network Connections:** Collects live TCP sockets via `ss -ntp` or `lsof -i -P -n`.
- **Processes:** Inspects active and newly spawned processes using POSIX-compliant `ps -Ao pid,user,command`.

### Step 1: Pair the Agent
1. Open the dashboard at [http://localhost:5180](http://localhost:5180).
2. Go to **Settings** → **Local SOC Agent Pairing**.
3. Click **Pair This Device** and copy your generated `AGENT_TOKEN`.
4. Put the token in `agent/.env`:
   ```bash
   cp agent/.env.example agent/.env
   nano agent/.env
   ```
   Set:
   ```env
   AGENT_TOKEN=your_token_here
   BACKEND_URL=http://localhost:5050
   ```

### Step 2A: Run the Agent in Terminal (Foreground)
```bash
./start-linux.sh --agent
```

### Step 2B: Install as a Persistent Linux `systemd` Daemon
For 24/7 background telemetry monitoring:
```bash
sudo ./start-linux.sh --install-service
```
This creates and activates `/etc/systemd/system/eye-agent.service`.

#### Managing the systemd service:
```bash
# Check service status
sudo systemctl status eye-agent

# View real-time agent telemetry stream
sudo journalctl -u eye-agent -f

# Restart or stop the agent
sudo systemctl restart eye-agent
sudo systemctl stop eye-agent
```

---

## 🔒 Linux Permissions & Troubleshooting

### Log Access Permissions
Reading `journalctl` or `/var/log/auth.log` requires elevated permissions on most Linux distributions.
- Run the agent as `root` or with `sudo`, OR
- Add your agent user to the `systemd-journal` and `adm` groups:
  ```bash
  sudo usermod -aG systemd-journal,adm $USER
  ```

### Port Conflicts
- Default client port: `5180`
- Default server port: `5050` (or `5000` in Docker)
- To change ports, edit `server/.env` and `client/vite.config.js`.
