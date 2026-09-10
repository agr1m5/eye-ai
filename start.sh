#!/usr/bin/env bash

# ==============================================================================
# 🛡️ RAKSHAK LIVE SOC 2.0 — ONE-COMMAND DEPLOYMENT & LAUNCH SCRIPT
# ==============================================================================
# Handles environment checks, .env creation, dependency installation,
# and brings up the full SOC stack (Client + Server + Agent Daemon).
#
# Usage:
#   ./start.sh          # Starts full Web SOC stack on http://localhost:5180
#   ./start.sh desktop  # Starts Web SOC + Agent + Native Electron Desktop Window
# ==============================================================================

set -e

# Color definitions
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "===================================================================="
echo "    🛡️  RAKSHAK 2.0 — AUTONOMOUS CYBER DEFENSE GRID (ADG)           "
echo "    One-Command Deployment & Operations Stack                       "
echo "===================================================================="
echo -e "${NC}"

# 1. Check Node.js & npm
echo -e "${CYAN}[1/5] Checking Runtime Prerequisites...${NC}"
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js is not installed.${NC} Please install Node.js (v18 or v20 LTS) and re-run."
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo -e "${RED}[ERROR] npm is not installed.${NC} Please install npm and re-run."
    exit 1
fi

NODE_VER=$(node -v | tr -d 'v' | cut -d'.' -f1)
echo -e "  ✓ Node.js $(node -v) detected"

# 2. Check MongoDB
echo -e "${CYAN}[2/5] Checking MongoDB Database Service...${NC}"
MONGO_UP=0
if nc -z localhost 27017 2>/dev/null; then
    MONGO_UP=1
elif (echo > /dev/tcp/127.0.0.1/27017) &>/dev/null; then
    MONGO_UP=1
fi

if [ $MONGO_UP -eq 1 ]; then
    echo -e "  ✓ MongoDB is active and accepting connections on port 27017"
else
    echo -e "${YELLOW}  ⚠ MongoDB not detected on port 27017. Attempting to start service...${NC}"
    if command -v systemctl &> /dev/null; then
        sudo systemctl start mongod 2>/dev/null || sudo systemctl start mongodb 2>/dev/null || true
    elif command -v service &> /dev/null; then
        sudo service mongod start 2>/dev/null || sudo service mongodb start 2>/dev/null || true
    elif command -v brew &> /dev/null; then
        brew services start mongodb-community 2>/dev/null || true
    fi
    echo -e "  Tip: Ensure MongoDB is running (e.g., 'sudo systemctl start mongod' or Docker)"
fi

# 3. Environment files creation
echo -e "${CYAN}[3/5] Verifying Environment Configurations...${NC}"
if [ ! -f "server/.env" ]; then
    echo -e "${GREEN}  + Generated server/.env from template${NC}"
    cp server/.env.example server/.env
else
    echo -e "  ✓ server/.env verified"
fi

if [ ! -f "agent/.env" ]; then
    echo -e "${GREEN}  + Generated agent/.env from template${NC}"
    cp agent/.env.example agent/.env
else
    echo -e "  ✓ agent/.env verified"
fi

# 4. Monorepo dependencies installation
echo -e "${CYAN}[4/5] Checking Workspace Dependencies...${NC}"
if [ ! -d "node_modules" ] || [ ! -d "client/node_modules" ] || [ ! -d "server/node_modules" ]; then
    echo -e "  Installing packages across all workspaces (client, server, agent)..."
    npm install
    echo -e "  ✓ Packages successfully installed"
else
    echo -e "  ✓ Dependencies already satisfied"
fi

# 5. Check Optional Ollama AI Server
echo -e "${CYAN}[5/5] Checking Ollama Local AI Copilot Status...${NC}"
OLLAMA_UP=0
if nc -z localhost 11434 2>/dev/null || (echo > /dev/tcp/127.0.0.1/11434) &>/dev/null; then
    OLLAMA_UP=1
fi

if [ $OLLAMA_UP -eq 1 ]; then
    echo -e "  ✓ Ollama local LLM server is online (:11434)"
else
    echo -e "${YELLOW}  ℹ Ollama server is offline. AI Chat will run with fallback responses.${NC}"
    echo -e "    (Optional: run 'ollama serve' in another terminal for local Llama 3.2)"
fi

echo ""
echo -e "${GREEN}${BOLD}===================================================================="
echo "    🚀 SYSTEM READY — LAUNCHING DEFENSE GRID                        "
echo "====================================================================${NC}"

TARGET_MODE="${1:-web}"

if [ "$TARGET_MODE" = "desktop" ] || [ "$TARGET_MODE" = "app" ]; then
    echo -e "${CYAN}Starting Native Desktop Mode (Web SOC + Agent + Electron Window)...${NC}"
    npm run app:all
else
    echo -e "${CYAN}Starting Web SOC Mode (Client + Server + Agent Daemon)...${NC}"
    echo -e "${BOLD}Dashboard URL : http://localhost:5180${NC}"
    echo -e "${BOLD}Backend API   : http://localhost:5050${NC}"
    echo -e "${BOLD}Test Login    : testsoc@rakshak.local / Rakshak@123${NC}"
    echo ""
    npx concurrently -n "CLIENT,SERVER,AGENT" -c "cyan,magenta,green" \
        "npm run client" \
        "npm run server" \
        "npm run agent"
fi
