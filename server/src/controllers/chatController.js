/**
 * chatController.js — AI SOC Analyst conversation controller.
 *
 * Handles:
 *   - Listing user chat conversations
 *   - Creating new chat sessions
 *   - Fetching message history
 *   - Submitting analyst queries & generating AI responses
 *   - Deleting chat threads
 */
import Chat from '../models/Chat.js';
import { generateSecurityResponse, generateChatTitle } from '../services/aiService.js';

/* ── GET /api/chat ───────────────────────────────────────────── */
export async function listChats(req, res, next) {
  try {
    const chats = await Chat.find({ userId: req.user._id })
      .select('title createdAt updatedAt contextIncidentId')
      .sort({ updatedAt: -1 })
      .lean();

    return res.status(200).json({
      status: 'success',
      data: chats,
    });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/chat ──────────────────────────────────────────── */
export async function createChat(req, res, next) {
  try {
    const { title, contextThreatIds, contextIncidentId } = req.body;

    const chat = new Chat({
      userId: req.user._id,
      title: title || 'New Security Thread',
      messages: [],
      contextThreatIds: contextThreatIds || [],
      contextIncidentId: contextIncidentId || null,
    });

    await chat.save();

    return res.status(201).json({
      status: 'success',
      data: chat,
    });
  } catch (err) {
    next(err);
  }
}

/* ── GET /api/chat/:id ───────────────────────────────────────── */
export async function getChat(req, res, next) {
  try {
    const chat = await Chat.findOne({
      _id: req.params.id,
      userId: req.user._id,
    });

    if (!chat) {
      return res.status(404).json({
        status: 'error',
        message: 'Chat conversation not found.',
      });
    }

    return res.status(200).json({
      status: 'success',
      data: chat,
    });
  } catch (err) {
    next(err);
  }
}

/* ── POST /api/chat/:id/message ──────────────────────────────── */
export async function sendMessage(req, res, next) {
  try {
    const { content } = req.body;
    if (!content || !content.trim()) {
      return res.status(400).json({
        status: 'error',
        message: 'Message content cannot be empty.',
      });
    }

    let chat = await Chat.findOne({
      _id: req.params.id,
      userId: req.user._id,
    });

    if (!chat) {
      return res.status(404).json({
        status: 'error',
        message: 'Chat conversation not found.',
      });
    }

    // Append user message
    const userMsg = {
      role: 'user',
      content: content.trim(),
    };
    chat.messages.push(userMsg);

    // Auto-update title if it's the first turn
    if (chat.messages.length === 1 || chat.title === 'New Security Thread' || chat.title === 'New Chat') {
      chat.title = generateChatTitle(content);
    }

    // Query AI engine
    const aiResult = await generateSecurityResponse({
      messages: chat.messages,
      contextThreats: chat.contextThreatIds,
      contextIncident: chat.contextIncidentId,
    });

    // Append assistant response
    const assistantMsg = {
      role: 'assistant',
      content: aiResult.content,
    };
    chat.messages.push(assistantMsg);
    chat.aiProvider = aiResult.provider;
    chat.aiModel = aiResult.model;

    await chat.save();

    return res.status(200).json({
      status: 'success',
      data: {
        chat,
        userMessage: userMsg,
        assistantMessage: assistantMsg,
      },
    });
  } catch (err) {
    next(err);
  }
}

/* ── DELETE /api/chat/:id ────────────────────────────────────── */
export async function deleteChat(req, res, next) {
  try {
    const result = await Chat.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id,
    });

    if (!result) {
      return res.status(404).json({
        status: 'error',
        message: 'Chat conversation not found.',
      });
    }

    return res.status(200).json({
      status: 'success',
      message: 'Chat conversation deleted successfully.',
    });
  } catch (err) {
    next(err);
  }
}
