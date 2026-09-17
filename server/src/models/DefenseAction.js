/**
 * DefenseAction Model — Eye Live SOAR & Active Defense
 *
 * Tracks all executed containment actions: process termination,
 * firewall IP blocks, host isolation, and file quarantine.
 */
import mongoose from 'mongoose';

const defenseActionSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    actionType: {
      type:     String,
      // 'block_ip' retained in schema enum solely for read compatibility with historical
      // audit documents; new containment requests are strictly rejected with 400 at controller.
      enum:     ['kill_process', 'block_ip', 'isolate_host', 'quarantine_file'],
      required: true,
      index:    true,
    },

    // Target identifier (e.g. "PID: 4921", "198.51.100.9", "hostname", "/tmp/malware.sh")
    target: {
      type:     String,
      required: true,
      index:    true,
    },

    filePath: {
      type:    String,
      default: null,
    },

    pid: {
      type:    Number,
      default: null,
    },

    expectedProcessName: {
      type:    String,
      default: null,
    },

    status: {
      type:    String,
      enum:    ['active', 'released', 'failed'],
      default: 'active',
      index:   true,
    },

    reason: {
      type:    String,
      default: 'Manual analyst containment countermeasure',
    },

    threatId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'Threat',
      default: null,
    },

    incidentId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'Incident',
      default: null,
    },

    executedBy: {
      type:    String,
      enum:    ['analyst', 'autonomous_ai', 'automation'],
      default: 'analyst',
    },

    receipt: {
      type:    mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

defenseActionSchema.index({ userId: 1, status: 1, createdAt: -1 });

const DefenseAction = mongoose.model('DefenseAction', defenseActionSchema);
export default DefenseAction;
