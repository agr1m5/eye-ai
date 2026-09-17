/**
 * Express Application Configuration.
 *
 * Configures security, logging, body parsers, routes, and error handling.
 */
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

import { config } from './config/env.js';
import { apiLimiter } from './middleware/rateLimiter.js';
import { errorHandler } from './middleware/errorHandler.js';

import authRoutes from './routes/authRoutes.js';
import threatRoutes from './routes/threatRoutes.js';
import incidentRoutes from './routes/incidentRoutes.js';
import chatRoutes from './routes/chatRoutes.js';
import reportRoutes from './routes/reportRoutes.js';
import agentRoutes from './routes/agentRoutes.js';
import tiRoutes from './routes/tiRoutes.js';
import logImportRoutes from './routes/logImportRoutes.js';
import auditRoutes from './routes/auditRoutes.js';
import activityRoutes from './routes/activityRoutes.js';
import defenseRoutes from './routes/defenseRoutes.js';

const app = express();

// Security Middlewares
app.use(helmet());
app.use(cors({
  origin: [config.clientOrigin, 'http://localhost:5180'],
  credentials: true,
}));

// Request Logging
if (config.env !== 'test') {
  app.use(morgan(config.env === 'development' ? 'dev' : 'combined'));
}

// Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Global Rate Limiting for API routes
app.use('/api', apiLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Eye Live SOC Backend',
    timestamp: new Date().toISOString(),
    env: config.env,
  });
});

// Root endpoint — redirect browser clients to the frontend dashboard
app.get('/', (req, res) => {
  if (req.accepts('html')) {
    return res.redirect('http://localhost:5180');
  }
  res.json({
    status: 'ok',
    service: 'Eye Live SOC Backend',
    dashboard: 'http://localhost:5180',
    health: '/api/health',
  });
});


// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/threats', threatRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/chat', chatRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/agent', agentRoutes);
app.use('/api/ti', tiRoutes);
app.use('/api/logs', logImportRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/activities', activityRoutes);
app.use('/api/defense', defenseRoutes);

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: `Cannot ${req.method} ${req.originalUrl}`,
  });
});

// Centralized Error Handler
app.use(errorHandler);

export default app;
