/**
 * ChatPage — AI SOC Analyst conversation hub.
 */
import { useState, useEffect, useRef } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import ConversationList from '@/components/chat/ConversationList';
import MessageBubble from '@/components/chat/MessageBubble';
import { chatApi } from '@/services/api';
import { Send, Bot, Sparkles, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';

const SUGGESTIONS = [
  'What is SQL Injection and how do I prevent it?',
  'Explain MITRE ATT&CK T1059 and detection methods',
  'How do I triage and contain a Ransomware outbreak?',
  'How to detect and mitigate an active Port Scan?',
];

export default function ChatPage() {
  const [chats, setChats] = useState([]);
  const [activeChatId, setActiveChatId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loadingChats, setLoadingChats] = useState(true);
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    loadChats();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, sending]);

  const loadChats = async () => {
    try {
      setLoadingChats(true);
      const { data } = await chatApi.list();
      if (data.status === 'success') {
        setChats(data.data);
        if (data.data.length > 0 && !activeChatId) {
          selectChat(data.data[0]._id);
        }
      }
    } catch (err) {
      toast.error('Failed to load chat history');
    } finally {
      setLoadingChats(false);
    }
  };

  const selectChat = async (id) => {
    setActiveChatId(id);
    try {
      const { data } = await chatApi.get(id);
      if (data.status === 'success') {
        setMessages(data.data.messages || []);
      }
    } catch (err) {
      toast.error('Failed to load conversation');
    }
  };

  const handleNewChat = async () => {
    try {
      const { data } = await chatApi.create();
      if (data.status === 'success') {
        setChats((prev) => [data.data, ...prev]);
        setActiveChatId(data.data._id);
        setMessages([]);
      }
    } catch (err) {
      toast.error('Failed to create new conversation');
    }
  };

  const handleDeleteChat = async (id) => {
    try {
      await chatApi.remove(id);
      setChats((prev) => prev.filter((c) => c._id !== id));
      if (activeChatId === id) {
        const remaining = chats.filter((c) => c._id !== id);
        if (remaining.length > 0) {
          selectChat(remaining[0]._id);
        } else {
          setActiveChatId(null);
          setMessages([]);
        }
      }
      toast.success('Conversation deleted');
    } catch (err) {
      toast.error('Failed to delete conversation');
    }
  };

  const handleSendMessage = async (queryText) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || sending) return;

    let targetChatId = activeChatId;

    // If no active chat, create one first
    if (!targetChatId) {
      try {
        const { data } = await chatApi.create();
        targetChatId = data.data._id;
        setActiveChatId(targetChatId);
        setChats((prev) => [data.data, ...prev]);
      } catch (err) {
        toast.error('Failed to initiate conversation');
        return;
      }
    }

    const optimisticUserMsg = {
      role: 'user',
      content: textToSend.trim(),
    };

    setMessages((prev) => [...prev, optimisticUserMsg]);
    setInput('');
    setSending(true);

    try {
      const { data } = await chatApi.message(targetChatId, textToSend.trim());
      if (data.status === 'success') {
        setMessages(data.data.chat.messages);

        // Update title in sidebar list
        setChats((prev) =>
          prev.map((c) =>
            c._id === targetChatId ? { ...c, title: data.data.chat.title, updatedAt: new Date() } : c
          )
        );
      }
    } catch (err) {
      toast.error('Failed to get AI response');
    } finally {
      setSending(false);
    }
  };

  return (
    <PageWrapper title="AI SOC Analyst" subtitle="Interactive cybersecurity intelligence and remediation assistant">
      <div className="flex h-[calc(100vh-10rem)] gap-4">
        {/* Left: Chat history */}
        <ConversationList
          chats={chats}
          activeChatId={activeChatId}
          onSelectChat={selectChat}
          onNewChat={handleNewChat}
          onDeleteChat={handleDeleteChat}
          loading={loadingChats}
        />

        {/* Right: Message stream + input */}
        <div className="flex-1 glass-card glow-border flex flex-col h-full overflow-hidden">
          {/* Messages view */}
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center gap-4 text-center px-4">
                <div className="w-14 h-14 rounded-2xl bg-accent-400/10 border border-accent-400/20 flex items-center justify-center">
                  <Bot className="w-7 h-7 text-accent-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100">Eye AI Analyst</h3>
                  <p className="text-xs text-slate-500 max-w-sm mt-1">
                    Ask threat intelligence questions, investigate MITRE techniques, or request remediation playbooks.
                  </p>
                </div>

                <div className="flex flex-wrap justify-center gap-2 max-w-lg mt-2">
                  {SUGGESTIONS.map((q) => (
                    <button
                      key={q}
                      onClick={() => handleSendMessage(q)}
                      className="text-xs px-3 py-1.5 rounded-full bg-surface-700/60 border border-white/5 text-slate-400 hover:border-accent-400/40 hover:text-accent-300 transition-colors flex items-center gap-1.5"
                    >
                      <Sparkles className="w-3 h-3 text-accent-400" />
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((m, idx) => (
                <MessageBubble key={m._id || idx} message={m} />
              ))
            )}

            {sending && (
              <div className="flex gap-3 my-3">
                <div className="w-8 h-8 rounded-lg bg-accent-400/10 border border-accent-400/20 flex items-center justify-center shrink-0 mt-1">
                  <Bot className="w-4 h-4 text-accent-400 animate-pulse" />
                </div>
                <div className="glass-card px-4 py-3 rounded-xl flex items-center gap-2 text-xs text-slate-400">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-accent-400" />
                  <span>Analyzing security intelligence...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input field */}
          <div className="p-4 border-t border-white/5 bg-surface-900/50">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="flex gap-2"
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask about CVEs, threat techniques, or IOCs..."
                className="input flex-1"
                disabled={sending}
                autoFocus
              />
              <button
                type="submit"
                disabled={!input.trim() || sending}
                className="btn-primary px-4 shrink-0"
              >
                <Send className="w-4 h-4" />
                <span className="hidden sm:inline">Send</span>
              </button>
            </form>
          </div>
        </div>
      </div>
    </PageWrapper>
  );
}
