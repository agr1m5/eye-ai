/**
 * Chat Routes — Step 7 & 8
 *
 * GET    /api/chat             — list conversations
 * POST   /api/chat             — create new conversation
 * GET    /api/chat/:id         — get conversation with messages
 * POST   /api/chat/:id/message — send message & get AI response
 * DELETE /api/chat/:id         — delete conversation
 */
import { Router } from 'express';
import { protect } from '../middleware/auth.js';
import {
  listChats,
  createChat,
  getChat,
  sendMessage,
  deleteChat,
} from '../controllers/chatController.js';

const router = Router();

// Protect all chat routes with JWT auth
router.use(protect);

router.get('/', listChats);
router.post('/', createChat);
router.get('/:id', getChat);
router.post('/:id/message', sendMessage);
router.delete('/:id', deleteChat);

export default router;
