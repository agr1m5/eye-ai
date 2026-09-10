/**
 * Chat Model — Eye Live SOC
 *
 * Represents a single AI analyst chat session.
 * Each document holds the full conversation history as an embedded
 * sub-document array (messages). This avoids a separate Message
 * collection for a feature where threads are short (< ~200 turns).
 *
 * Context seeding:
 *   When the analyst opens chat from a Threat or Incident detail view,
 *   the frontend passes contextThreatIds / contextIncidentId so the
 *   AI controller can pre-load relevant data into the system prompt.
 *
 * Steps that use this model:
 *   Step 7  — chatController list / create / get / delete
 *   Step 8  — AI message handler (Ollama / OpenAI)
 */
import mongoose from 'mongoose';

/* ── Sub-schema: individual message ─────────────────────────── */
const messageSchema = new mongoose.Schema(
  {
    role: {
      type:     String,
      enum:     ['user', 'assistant', 'system'],
      required: true,
    },
    content: {
      type:     String,
      required: true,
    },
    // Token count for rough context-window budget tracking
    tokenEstimate: {
      type:    Number,
      default: null,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

/* ── Main Schema ─────────────────────────────────────────────── */
const chatSchema = new mongoose.Schema(
  {
    userId: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      'User',
      required: true,
      index:    true,
    },

    // Short title shown in the sidebar — generated from the first user message
    title: {
      type:    String,
      default: 'New Chat',
      trim:    true,
      maxlength: 120,
    },

    messages: {
      type:    [messageSchema],
      default: [],
    },

    // Optional: threats that seeded this conversation
    contextThreatIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref:  'Threat',
      },
    ],

    // Optional: incident that seeded this conversation
    contextIncidentId: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     'Incident',
      default: null,
    },

    // Track which AI provider/model was used
    aiProvider: {
      type:    String,
      default: null,
    },
    aiModel: {
      type:    String,
      default: null,
    },
  },
  { timestamps: true }
);

/* ── Indexes ─────────────────────────────────────────────────── */
// Sort by most recently updated for sidebar list
chatSchema.index({ userId: 1, updatedAt: -1 });

const Chat = mongoose.model('Chat', chatSchema);
export default Chat;
