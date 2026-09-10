/**
 * Auth Routes — Step 5
 *
 * POST   /api/auth/signup  — create account
 * POST   /api/auth/login   — authenticate
 * POST   /api/auth/logout  — clear session (stateless)
 * GET    /api/auth/me      — return current user (protected)
 */
import { Router } from 'express';
import { authLimiter }            from '../middleware/rateLimiter.js';
import { protect }                from '../middleware/auth.js';
import {
  signup,
  login,
  logout,
  getMe,
  updatePreferences,
  signupValidation,
  loginValidation,
} from '../controllers/authController.js';

const router = Router();

router.post('/signup', authLimiter, signupValidation, signup);
router.post('/login',  authLimiter, loginValidation,  login);
router.post('/logout',                                logout);
router.get( '/me',     protect,                       getMe);
router.patch('/preferences', protect,                 updatePreferences);

export default router;
