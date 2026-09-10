#!/usr/bin/env bash
# ==============================================================================
# Rakshak 2.0 — Linux Startup & Management Script
# ==============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=================================================="
echo "🛡️  Rakshak 2.0 — Linux ($(uname -s) $(uname -m))"
echo "=================================================="

# Check for desktop app option
if [ "$1" == "--app" ]; then
    echo "🖥️  Launching Rakshak 2.0 Desktop Application..."
    cd "$PROJECT_DIR"
    exec npm run app
fi

# Check for Docker option
if [ "$1" == "--docker" ]; then
    echo "🐳 Launching Rakshak via Docker Compose..."
    cd "$PROJECT_DIR"
    docker compose up -d
    echo ""
    echo "✓ Rakshak is running in containers:"
    echo "  - Frontend Web UI:  http://localhost:5180"
    echo "  - Backend API:      http://localhost:5000"
    echo "  - MongoDB:          localhost:27017"
    echo "To view logs: docker compose logs -f"
    exit 0
fi

# Check for systemd service install option
if [ "$1" == "--install-service" ]; then
    echo "⚙️  Installing Rakshak Telemetry Agent as a systemd service..."
    if [ "$EUID" -ne 0 ]; then
        echo "❌ Please run with sudo: sudo ./start-linux.sh --install-service"
        exit 1
    fi
    mkdir -p /opt/rakshak/agent
    cp -r "$PROJECT_DIR/agent/"* /opt/rakshak/agent/
    if [ -f "$PROJECT_DIR/agent/.env" ]; then
        cp "$PROJECT_DIR/agent/.env" /opt/rakshak/agent/.env
    fi
    cp "$PROJECT_DIR/agent/rakshak-agent.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable rakshak-agent
    systemctl start rakshak-agent
    echo "✓ Service installed and started!"
    echo "  Status: sudo systemctl status rakshak-agent"
    echo "  Logs:   sudo journalctl -u rakshak-agent -f"
    exit 0
fi

# Check for standalone agent option
if [ "$1" == "--agent" ]; then
    echo "📡 Starting Rakshak Telemetry Agent on Linux..."
    cd "$PROJECT_DIR/agent"
    if [ ! -f ".env" ]; then
        echo "⚠️  agent/.env not found. Copying from .env.example..."
        cp .env.example .env
        echo "⚠️  Please configure your AGENT_TOKEN in agent/.env before running."
    fi
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing agent dependencies..."
        npm install
    fi
    exec npm start
fi

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ (https://nodejs.org)."
    exit 1
fi

NODE_VERSION=$(node -v)
echo "✓ Node.js detected: $NODE_VERSION"

# Setup server/.env if missing
if [ ! -f "$PROJECT_DIR/server/.env" ]; then
    echo "📝 Creating server/.env from .env.example..."
    cp "$PROJECT_DIR/server/.env.example" "$PROJECT_DIR/server/.env"
fi

# Check for MongoDB
if ! pgrep -x mongod > /dev/null 2>&1; then
    echo "⚠️  MongoDB does not seem to be running locally on port 27017."
    echo "   If using systemd: sudo systemctl start mongod"
    echo "   Or run MongoDB via Docker: docker run -d -p 27017:27017 --name mongo mongo:7"
fi

# 1. Install root dependencies if needed
if [ ! -d "$PROJECT_DIR/node_modules" ]; then
    echo "📦 Installing root dependencies..."
    cd "$PROJECT_DIR" && npm install
fi

# 2. Install server dependencies if needed
if [ ! -d "$PROJECT_DIR/server/node_modules" ]; then
    echo "📦 Installing server dependencies..."
    cd "$PROJECT_DIR/server" && npm install
fi

# 3. Install client dependencies if needed
if [ ! -d "$PROJECT_DIR/client/node_modules" ]; then
    echo "📦 Installing client dependencies..."
    cd "$PROJECT_DIR/client" && npm install
fi

# 4. Install agent dependencies if needed
if [ ! -d "$PROJECT_DIR/agent/node_modules" ]; then
    echo "📦 Installing agent dependencies..."
    cd "$PROJECT_DIR/agent" && npm install
fi

cd "$PROJECT_DIR"
echo ""
echo "🚀 Launching Rakshak SOC Server & Web Client..."
echo "   Dashboard: http://localhost:5180"
echo "   API:       http://localhost:5050"
echo "   Press Ctrl+C to stop."
echo "=================================================="

# Run concurrently dev
npm run dev
