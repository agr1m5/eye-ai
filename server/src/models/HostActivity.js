/**
 * HostActivity Model — Rakshak Live SOC
 *
 * Records continuous endpoint and user activity (processes, network connections,
 * system authentication, and terminal commands) streamed by the local agent.
 *
 * Includes automatic 7-day TTL index so that large volumes of benign activity
 * do not exhaust database storage.
 */
import mongoose from 'mongoose';

const hostActivitySchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    // Source domain of the activity
    source: {
      type:     String,
      enum:     ['process', 'network', 'log', 'shell'],
      required: true,
      index:    true,
    },

    // Action verb, e.g. 'process.started', 'process.stopped', 'connection.new', 'connection.closed', 'log.event'
    action: {
      type:     String,
      required: true,
      index:    true,
    },

    // Concise human-readable description of the activity
    description: {
      type:     String,
      required: true,
    },

    // Username / actor who executed or owns the action (e.g. 'root', 'agrim', 'nobody')
    actor: {
      type:    String,
      default: 'system',
    },

    // Key subject entity (e.g. process name, PID, destination IP, or service)
    entity: {
      type:    String,
      default: '',
    },

    // Remote IP address (for network or remote SSH events)
    ip: {
      type:    String,
      default: null,
    },

    // Whether this activity also triggered an alert/threat
    isThreat: {
      type:    Boolean,
      default: false,
      index:   true,
    },

    // Threat severity if flagged
    severity: {
      type:    String,
      enum:    ['critical', 'high', 'medium', 'low', 'info', 'none'],
      default: 'none',
    },

    // Threat classification type if flagged
    threatType: {
      type:    String,
      default: null,
    },

    // Raw payload or structured attributes (PID, CLI arguments, ports, state)
    metadata: {
      type:    mongoose.Schema.Types.Mixed,
      default: {},
    },

    timestamp: {
      type:    Date,
      default: Date.now,
      index:   true,
    },
  },
  {
    timestamps: true,
  }
);

// Compound indexes for fast filtered timeline queries
hostActivitySchema.index({ userId: 1, createdAt: -1 });
hostActivitySchema.index({ userId: 1, source: 1, createdAt: -1 });
hostActivitySchema.index({ userId: 1, isThreat: 1, createdAt: -1 });

// Automatic 7-day TTL index (604800 seconds)
hostActivitySchema.index({ createdAt: 1 }, { expireAfterSeconds: 604800 });

const HostActivity = mongoose.model('HostActivity', hostActivitySchema);
export default HostActivity;
