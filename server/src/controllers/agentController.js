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
