/**
 * Rate Limiting middleware using express-rate-limit.
 */
import rateLimit from 'express-rate-limit';
import { config } from '../config/env.js';

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.env === 'development' ? 100_000 : 5_000, // High ceiling for live SOC telemetry & dashboards
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again after 15 minutes.',
  },
  skip: (req) => {
    // Never rate limit loopback/localhost dev traffic or local agent polling
    if (config.env === 'development') return true;
    const ip = req.ip || req.connection?.remoteAddress || '';
    return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  },
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.env === 'development' ? 10_000 : 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again after 15 minutes.',
  },
  skip: (req) => {
    if (config.env === 'development') return true;
    const ip = req.ip || req.connection?.remoteAddress || '';
    return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  },
});
