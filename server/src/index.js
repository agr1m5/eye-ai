/**
 * Server Entrypoint.
 *
 * Bootstraps DB connection, HTTP server, and Socket.IO server.
 */
import http from 'http';
import app from './app.js';
import { config } from './config/env.js';
import { connectDB } from './config/db.js';
import { initSocketServer } from './config/socket.js';

async function startServer() {
  // Connect to MongoDB
  await connectDB();

  // Background enrich any legacy threats lacking coordinates
  import('./services/geoService.js').then(({ enrichExistingThreats }) => {
    enrichExistingThreats().catch(() => {});
  });

  // Create HTTP Server
  const server = http.createServer(app);

  // Initialize Socket.IO
  initSocketServer(server);

  // Start listening
  server.listen(config.port, () => {
    console.log(`
==================================================
  🛡️  RAKSHAK LIVE SOC BACKEND RUNNING
==================================================
  Environment : ${config.env}
  HTTP Server : http://localhost:${config.port}
  Health Check: http://localhost:${config.port}/api/health
  Socket.IO   : wss://localhost:${config.port} (or ws:// in dev)
==================================================
    `);
  });
}

startServer();
