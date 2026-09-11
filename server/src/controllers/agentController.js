/**
 * agentController.js — Local agent pairing and revocation.
 *
 * Security model:
 *   - A cryptographically random 32-byte token is generated with crypto.
 *   - Only the bcrypt hash is persisted in user.agentTokenHash.
 *   - The plain token is returned ONCE in the API response and is
 *     never retrievable again — the analyst copies it into the agent's
 *     config file on their machine.
 *   - Tokens expire after 365 days (configurable via AGENT_TOKEN_TTL_DAYS).
 *   - The agent presents this token in the Socket.IO handshake auth
 *     (Step 6), where it is verified against the stored hash.
 *
 * Routes:
 *   POST   /api/agent/pair    — generate & store a new pairing token
 *   DELETE /api/agent/pair    — revoke the current pairing token
 *   GET    /api/agent/status  — return pairing status for the current user
 *
 * All routes require the `protect` middleware.
 */
import crypto   from 'crypto';
import bcrypt   from 'bcryptjs';
import { body, validationResult } from 'express-validator';

import User from '../models/User.js';
import { createAuditEntry } from '../services/auditService.js';

const SALT_ROUNDS       = 12;
const TOKEN_BYTES       = 32;
const TOKEN_TTL_DAYS    = 365;

/* ── Validation ──────────────────────────────────────────────── */
export const pairValidation = [
  body('label')
    .optional()
    .trim()
    .isLength({ max: 80 }).withMessage('Agent label must be 80 characters or fewer.'),
];

/* ── POST /api/agent/pair ────────────────────────────────────── */
export async function pairAgent(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        status:  'error',
        message: 'Validation failed',
        errors:  errors.array().map(e => ({ field: e.path, message: e.msg })),
      });
    }

    const { label } = req.body;

    // Generate a secure random token
    const plainToken  = crypto.randomBytes(TOKEN_BYTES).toString('hex'); // 64-char hex
    const tokenHash   = await bcrypt.hash(plainToken, SALT_ROUNDS);
    const expiresAt   = new Date(Date.now() + TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

    // Persist the hash (select agentTokenHash explicitly — it's select:false)
    await User.findByIdAndUpdate(req.user._id, {
      agentTokenHash:      tokenHash,
      agentTokenExpiresAt: expiresAt,
      agentLabel:          label || 'Local Agent',
    });

    // Return the plain token ONCE — it cannot be recovered after this response
    createAuditEntry({
      userId:     req.user._id,
      action:     'agent.paired',
      targetType: 'User',
      targetId:   req.user._id,
      metadata:   { label: label || 'Local Agent' },
      ip:         req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: 'Agent pairing token generated. Save this token — it will not be shown again.',
      token:   plainToken,
      label:   label || 'Local Agent',
      expiresAt,
    });
  } catch (err) {
    next(err);
  }
}

/* ── DELETE /api/agent/pair ──────────────────────────────────── */
export async function revokeAgent(req, res, next) {
  try {
    await User.findByIdAndUpdate(req.user._id, {
      agentTokenHash:      null,
      agentTokenExpiresAt: null,
      agentLabel:          null,
    });

    createAuditEntry({
      userId:     req.user._id,
      action:     'agent.revoked',
      targetType: 'User',
      targetId:   req.user._id,
      metadata:   {},
      ip:         req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: 'Agent token revoked. The agent will disconnect on its next heartbeat.',
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/agent/status ───────────────────────────────────── */
export async function getAgentStatus(req, res) {
  const { agentLabel, agentTokenExpiresAt } = req.user;

  // agentTokenHash is select:false — check via a separate lean query
  const userWithToken = await User
    .findById(req.user._id)
    .select('+agentTokenHash')
    .lean();

  const paired  = !!userWithToken?.agentTokenHash;
  const expired = agentTokenExpiresAt ? agentTokenExpiresAt < new Date() : false;

  return res.status(200).json({
    status: 'success',
    data: {
      paired,
      expired,
      label:     paired ? agentLabel : null,
      expiresAt: paired ? agentTokenExpiresAt : null,
    },
  });
}

/* ── GET /api/agent/consent ──────────────────────────────────── */
import fs   from 'fs';
import path from 'path';
import os   from 'os';

const CONSENT_DIR  = path.join(os.homedir(), '.eye');
const CONSENT_FILE = path.join(CONSENT_DIR,  'device_consent.json');
const AGENT_ENV    = path.join(process.cwd(), '..', 'agent', '.env');

function readConsentFile() {
  try {
    if (fs.existsSync(CONSENT_FILE)) {
      return JSON.parse(fs.readFileSync(CONSENT_FILE, 'utf8'));
    }
  } catch {}
  return null;
}

export async function getConsent(req, res) {
  try {
    const data    = readConsentFile();
    const granted = data?.status === 'granted';
    return res.status(200).json({
      status: 'success',
      data: {
        granted,
        timestamp: data?.timestamp || null,
        scopes:    data?.scopes    || [],
        hostname:  data?.hostname  || null,
      },
    });
  } catch (err) {
    return res.status(500).json({ status: 'error', message: err.message });
  }
}

/* ── PATCH /api/agent/consent ────────────────────────────────── */
export async function setConsent(req, res) {
  try {
    const { granted } = req.body;
    if (typeof granted !== 'boolean') {
      return res.status(400).json({ status: 'error', message: '`granted` must be a boolean.' });
    }

    // 1. Write ~/.eye/device_consent.json
    if (!fs.existsSync(CONSENT_DIR)) fs.mkdirSync(CONSENT_DIR, { recursive: true });
    const payload = {
      status:    granted ? 'granted' : 'denied',
      timestamp: new Date().toISOString(),
      hostname:  os.hostname(),
      platform:  os.platform(),
      arch:      os.arch(),
      user:      os.userInfo().username,
      scopes: ['process_monitoring', 'network_socket_audit', 'system_auth_log_stream', 'honeytoken_canary_trap'],
    };
    fs.writeFileSync(CONSENT_FILE, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });

    // 2. Update DEVICE_ACCESS_GRANTED in agent/.env (if file exists)
    try {
      if (fs.existsSync(AGENT_ENV)) {
        let envContent = fs.readFileSync(AGENT_ENV, 'utf8');
        if (envContent.includes('DEVICE_ACCESS_GRANTED=')) {
          envContent = envContent.replace(
            /DEVICE_ACCESS_GRANTED=.*/,
            `DEVICE_ACCESS_GRANTED=${granted}`
          );
        } else {
          envContent += `\nDEVICE_ACCESS_GRANTED=${granted}\n`;
        }
        fs.writeFileSync(AGENT_ENV, envContent, 'utf8');
      }
    } catch (envErr) {
      console.warn('[Consent] Could not update agent/.env:', envErr.message);
    }

    createAuditEntry({
      userId:     req.user._id,
      action:     granted ? 'consent.granted' : 'consent.revoked',
      targetType: 'System',
      targetId:   req.user._id,
      metadata:   { hostname: os.hostname() },
      ip:         req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: granted ? 'Device access permission granted.' : 'Device access permission revoked.',
      data:    payload,
    });
  } catch (err) {
    return res.status(500).json({ status: 'error', message: err.message });
  }
}
