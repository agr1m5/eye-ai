/**
 * jwt.js — JWT signing and verification helpers.
 *
 * Centralises all JWT logic so the secret and options are never
 * scattered across controllers.
 */
import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';

/**
 * signToken — create a signed JWT for a given user ID.
 * @param {string} userId — MongoDB ObjectId as string
 * @returns {string} signed JWT
 */
export function signToken(userId) {
  return jwt.sign(
    { sub: userId },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

/**
 * verifyToken — verify and decode a JWT.
 * Throws JsonWebTokenError / TokenExpiredError on failure.
 * @param {string} token
 * @returns {{ sub: string, iat: number, exp: number }}
 */
export function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret);
}
