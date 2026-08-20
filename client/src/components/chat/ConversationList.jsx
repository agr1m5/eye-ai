/**
 * ConversationList.jsx — Left sidebar listing previous AI chat sessions.
 */
import { Plus, MessageSquare, Trash2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

export default function ConversationList({
  chats = [],
  activeChatId,
  onSelectChat,
  onNewChat,
  onDeleteChat,
  loading = false,
}) {
  return (
    <div className="w-64 shrink-0 glass-card glow-border flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-900/40">
        <div className="flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-accent-400" />
          <span className="text-xs font-semibold text-slate-200">Conversations</span>
        </div>
        <button
          onClick={onNewChat}
          className="btn-ghost py-1 px-2.5 text-xs text-accent-400 hover:text-accent-300 hover:bg-accent-400/10"
          title="Start new conversation"
        >
          <Plus className="w-3.5 h-3.5" /> New
        </button>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {loading && chats.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-500">Loading history...</div>
        ) : chats.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center p-4 text-center">
            <p className="text-xs text-slate-500">No conversations yet.</p>
            <button
              onClick={onNewChat}
              className="text-xs text-accent-400 hover:underline mt-2"
            >
              Start one now
            </button>
          </div>
        ) : (
          chats.map((c) => {
            const isActive = c._id === activeChatId;
            return (
              <div
                key={c._id}
                onClick={() => onSelectChat(c._id)}
                className={`group flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs cursor-pointer transition-all ${
                  isActive
                    ? 'bg-accent-400/15 text-accent-300 border border-accent-400/30'
                    : 'text-slate-400 hover:bg-surface-700/50 hover:text-slate-200'
                }`}
              >
                <div className="min-w-0 flex-1">
                  <p className="font-medium truncate">{c.title || 'Security Thread'}</p>
                  {c.updatedAt && (
                    <span className="text-[10px] text-slate-500 block truncate">
                      {formatDistanceToNow(new Date(c.updatedAt), { addSuffix: true })}
                    </span>
                  )}
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteChat(c._id);
                  }}
                  className="opacity-0 group-hover:opacity-100 p-1 text-slate-500 hover:text-red-400 transition-opacity rounded"
                  title="Delete chat"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
