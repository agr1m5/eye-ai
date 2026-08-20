/**
 * auth.js — JWT authentication middleware.
 *
 * Usage:
 *   import { protect } from '../middleware/auth.js';
 *   router.get('/me', protect, handler);
 *
 * Flow:
 *   1. Extract Bearer token from Authorization header.
 *   2. Verify the JWT signature and expiry.
 *   3. Load the user document from DB (without passwordHash).
 *   4. Attach user to req.user and call next().
 *
 * Errors:
 *   401 — missing, malformed, or expired token
 *   403 — token valid but user no longer exists in DB
 */
import { verifyToken } from '../utils/jwt.js';
import User from '../models/User.js';

export async function protect(req, res, next) {
  try {
    /* ── 1. Extract token ─────────────────────────────────── */
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status:  'error',
        message: 'Authentication required. Please log in.',
      });
    }

    const token = authHeader.slice(7); // strip 'Bearer '

    /* ── 2. Verify JWT ────────────────────────────────────── */
    let payload;
    try {
      payload = verifyToken(token);
    } catch (err) {
      const message = err.name === 'TokenExpiredError'
        ? 'Your session has expired. Please log in again.'
        : 'Invalid authentication token.';
      return res.status(401).json({ status: 'error', message });
    }

    /* ── 3. Load user (no passwordHash in response) ───────── */
    const user = await User.findById(payload.sub).select('-passwordHash -agentTokenHash');
    if (!user) {
      return res.status(403).json({
        status:  'error',
        message: 'The user associated with this token no longer exists.',
      });
    }

    /* ── 4. Attach and continue ───────────────────────────── */
    req.user = user;
    next();
  } catch (err) {
    next(err); // pass unexpected errors to the global error handler
  }
}
