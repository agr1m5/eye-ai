/**
 * User Model — Eye Live SOC
 *
 * Represents an analyst or admin account.
 *
 * Security design decisions:
 *  - Raw password is NEVER stored. A virtual setter hashes via bcrypt
 *    and stores only the hash in `passwordHash`.
 *  - The agentToken field stores a bcrypt hash of the one-time pairing
 *    secret (plain token is returned once, never re-readable).
 *  - toSafeObject() strips all sensitive fields before sending to client.
 *
 * Steps that use this model:
 *   Step 5  — auth controller (signup/login/logout)
 *   Step 5  — agent pairing controller (pairAgent/revokeAgent)
 *   Step 6  — Socket.IO JWT verification middleware
 */
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 12;

/* ── Schema ─────────────────────────────────────────────────── */
const userSchema = new mongoose.Schema(
  {
    email: {
      type:      String,
      required:  [true, 'Email is required'],
      unique:    true,
      lowercase: true,
      trim:      true,
      match:     [/^\S+@\S+\.\S+$/, 'Invalid email format'],
      index:     true,
    },

    passwordHash: {
      type:     String,
      required: true,
      select:   false,   // Never returned by default in queries
    },

    role: {
      type:    String,
      enum:    ['analyst', 'admin'],
      default: 'analyst',
    },

    // Agent pairing — stores a bcrypt hash of the one-time token
    agentTokenHash: {
      type:    String,
      default: null,
      select:  false,
    },
    agentTokenExpiresAt: {
      type:    Date,
      default: null,
    },

    // Friendly label so the analyst knows which machine is paired
    agentLabel: {
      type:    String,
      default: null,
      trim:    true,
    },

    // SOC configuration preferences — editable from the Settings page
    preferences: {
      // Rolling window (ms) within which findings cluster into an Incident
      correlationWindowMs: {
        type:    Number,
        default: 15 * 60 * 1000,  // 15 minutes
        min:     5  * 60 * 1000,  // 5 minutes minimum
        max:     60 * 60 * 1000,  // 60 minutes maximum
      },
      // Minimum number of findings required to auto-open an Incident
      minFindingsThreshold: {
        type:    Number,
        default: 2,
        min:     2,
        max:     10,
      },
    },
  },
  { timestamps: true }
);

/* ── Virtual: password (write-only) ─────────────────────────── */
// Allows: user.password = 'plaintext'  →  auto-hashes on save
userSchema.virtual('password').set(function (plain) {
  this._plainPassword = plain;
});

/* ── Pre-validate hook: hash password if set ─────────────────── */
// Must run before 'validate' so the required check on passwordHash passes.
userSchema.pre('validate', async function (next) {
  if (!this._plainPassword) return next();
  this.passwordHash = await bcrypt.hash(this._plainPassword, SALT_ROUNDS);
  this._plainPassword = undefined;
  next();
});

/* ── Instance methods ────────────────────────────────────────── */

/**
 * comparePassword — verify a plaintext password against the stored hash.
 * Requires the document to have been fetched with `+passwordHash`.
 */
userSchema.methods.comparePassword = async function (plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

/**
 * compareAgentToken — verify a plaintext agent token against the stored hash.
 * Requires the document to have been fetched with `+agentTokenHash`.
 */
userSchema.methods.compareAgentToken = async function (plain) {
  if (!this.agentTokenHash) return false;
  if (this.agentTokenExpiresAt && this.agentTokenExpiresAt < new Date()) {
    return false;
  }
  return bcrypt.compare(plain, this.agentTokenHash);
};

/**
 * toSafeObject — returns a plain object safe to send to the client.
 * Strips passwordHash, agentTokenHash, and internal Mongoose fields.
 */
userSchema.methods.toSafeObject = function () {
  return {
    _id:                 this._id,
    email:               this.email,
    role:                this.role,
    agentLabel:          this.agentLabel,
    agentTokenExpiresAt: this.agentTokenExpiresAt,
    agentPaired:         !!this.agentTokenHash || false,
    preferences:         this.preferences,
    createdAt:           this.createdAt,
    updatedAt:           this.updatedAt,
  };
};

const User = mongoose.model('User', userSchema);
export default User;
