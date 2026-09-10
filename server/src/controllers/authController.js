/**
 * authController.js — Signup, Login, Logout, GetMe
 *
 * All handlers use express-validator for input validation.
 * Validation rules are exported alongside handlers so routes
 * can compose them as middleware arrays.
 *
 * Steps that use this controller:
 *   Step 5  — wired into authRoutes.js
 *   Step 6  — Socket.IO uses the same JWT / User model
 */
import { body, validationResult } from 'express-validator';
import User      from '../models/User.js';
import { signToken } from '../utils/jwt.js';
import { createAuditEntry } from '../services/auditService.js';

/* ── Shared validation helper ────────────────────────────────── */
function handleValidationErrors(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      status:  'error',
      message: 'Validation failed',
      errors:  errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
    return true; // signals that a response was already sent
  }
  return false;
}

/* ── Validation rule sets ────────────────────────────────────── */
export const signupValidation = [
  body('email')
    .trim()
    .isEmail().withMessage('A valid email address is required.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
    .matches(/[0-9]/).withMessage('Password must contain at least one number.'),
];

export const loginValidation = [
  body('email')
    .trim()
    .isEmail().withMessage('A valid email address is required.')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('Password is required.'),
];

/* ── POST /api/auth/signup ───────────────────────────────────── */
export async function signup(req, res, next) {
  try {
    if (handleValidationErrors(req, res)) return;

    const { email, password } = req.body;

    // Check for existing account
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({
        status:  'error',
        message: 'An account with this email already exists.',
      });
    }

    // Create user — password virtual triggers bcrypt hash on pre('save')
    const user = new User({ email });
    user.password = password;
    await user.save();

    const token = signToken(user._id.toString());

    return res.status(201).json({
      status: 'success',
      token,
      user:   user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/auth/login ────────────────────────────────────── */
export async function login(req, res, next) {
  try {
    if (handleValidationErrors(req, res)) return;

    const { email, password } = req.body;

    // Explicitly select passwordHash (field has select:false)
    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user) {
      // Generic message — don't reveal whether email exists
      return res.status(401).json({
        status:  'error',
        message: 'Invalid email or password.',
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        status:  'error',
        message: 'Invalid email or password.',
      });
    }

    const token = signToken(user._id.toString());

    return res.status(200).json({
      status: 'success',
      token,
      user:   user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/auth/logout ───────────────────────────────────── */
// Stateless JWT — the token lives in client memory.
// Logout is a client-side action; we just confirm success.
export async function logout(req, res) {
  return res.status(200).json({
    status:  'success',
    message: 'Logged out successfully.',
  });
}

/* ── GET /api/auth/me ────────────────────────────────────────── */
// Protected by the `protect` middleware — req.user is already loaded.
export async function getMe(req, res) {
  return res.status(200).json({
    status: 'success',
    user:   req.user.toSafeObject(),
  });
}

/* ── PATCH /api/auth/preferences ────────────────────────────── */
export async function updatePreferences(req, res, next) {
  try {
    const { correlationWindowMs, minFindingsThreshold } = req.body;

    const update = {};

    if (correlationWindowMs !== undefined) {
      const val = parseInt(correlationWindowMs, 10);
      if (isNaN(val) || val < 5 * 60 * 1000 || val > 60 * 60 * 1000) {
        return res.status(400).json({
          status:  'error',
          message: 'correlationWindowMs must be between 300000 (5 min) and 3600000 (60 min).',
        });
      }
      update['preferences.correlationWindowMs'] = val;
    }

    if (minFindingsThreshold !== undefined) {
      const val = parseInt(minFindingsThreshold, 10);
      if (isNaN(val) || val < 2 || val > 10) {
        return res.status(400).json({
          status:  'error',
          message: 'minFindingsThreshold must be between 2 and 10.',
        });
      }
      update['preferences.minFindingsThreshold'] = val;
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ status: 'error', message: 'No valid preferences provided.' });
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: update },
      { new: true, runValidators: true }
    );

    createAuditEntry({
      userId:     req.user._id,
      action:     'settings.updated',
      targetType: 'User',
      targetId:   req.user._id,
      metadata:   update,
      ip:         req.ip,
    });

    return res.status(200).json({
      status:  'success',
      message: 'Preferences updated.',
      user:    user.toSafeObject(),
    });
  } catch (err) {
    next(err);
  }
}
