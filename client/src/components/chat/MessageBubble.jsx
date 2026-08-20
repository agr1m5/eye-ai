/**
 * MessageBubble.jsx — Formatted chat message bubble supporting markdown and code snippets.
 */
import { useState } from 'react';
import { Bot, User, Copy, Check } from 'lucide-react';

export default function MessageBubble({ message }) {
  const isUser = message.role === 'user';
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple clean markdown-like line renderer
  const renderFormattedContent = (content) => {
    const lines = content.split('\n');
    let inCodeBlock = false;
    let codeBuffer = [];

    const elements = [];

    lines.forEach((line, idx) => {
      if (line.startsWith('```')) {
        if (inCodeBlock) {
          elements.push(
            <pre key={`code-${idx}`} className="my-2 p-3 rounded-lg bg-surface-950/80 border border-white/10 font-mono text-xs text-accent-300 overflow-x-auto">
              <code>{codeBuffer.join('\n')}</code>
            </pre>
          );
          codeBuffer = [];
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
        }
        return;
      }

      if (inCodeBlock) {
        codeBuffer.push(line);
        return;
      }

      if (line.startsWith('### ')) {
        elements.push(
          <h3 key={idx} className="text-sm font-bold text-slate-100 mt-3 mb-1.5 flex items-center gap-1.5">
            {line.replace('### ', '')}
          </h3>
        );
      } else if (line.startsWith('#### ')) {
        elements.push(
          <h4 key={idx} className="text-xs font-semibold text-accent-400 mt-2 mb-1">
            {line.replace('#### ', '')}
          </h4>
        );
      } else if (line.startsWith('- [ ] ') || line.startsWith('- [x] ')) {
        const checked = line.startsWith('- [x] ');
        elements.push(
          <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 my-1">
            <input type="checkbox" readOnly checked={checked} className="rounded border-slate-700 accent-accent-400" />
            <span>{line.replace(/- \[[ x]\] /, '')}</span>
          </div>
        );
      } else if (line.startsWith('- ') || line.startsWith('* ')) {
        elements.push(
          <li key={idx} className="text-xs text-slate-300 ml-4 list-disc my-0.5">
            {line.replace(/^[-*]\s+/, '')}
          </li>
        );
      } else if (line.trim() === '') {
        elements.push(<div key={idx} className="h-1.5" />);
      } else {
        elements.push(
          <p key={idx} className="text-xs text-slate-300 leading-relaxed">
            {line}
          </p>
        );
      }
    });

    if (inCodeBlock && codeBuffer.length > 0) {
      elements.push(
        <pre key="code-end" className="my-2 p-3 rounded-lg bg-surface-950/80 border border-white/10 font-mono text-xs text-accent-300 overflow-x-auto">
          <code>{codeBuffer.join('\n')}</code>
        </pre>
      );
    }

    return elements;
  };

  return (
    <div className={`flex gap-3 my-3 ${isUser ? 'justify-end' : 'justify-start'}`}>
      {!isUser && (
        <div className="w-8 h-8 rounded-lg bg-accent-400/10 border border-accent-400/20 flex items-center justify-center shrink-0 mt-1">
          <Bot className="w-4 h-4 text-accent-400" />
        </div>
      )}

      <div
        className={`relative group max-w-2xl px-4 py-3 rounded-xl ${
          isUser
            ? 'bg-accent-400/15 border border-accent-400/30 text-slate-100'
            : 'glass-card glow-border text-slate-200'
        }`}
      >
        {!isUser && (
          <button
            onClick={handleCopy}
            className="absolute top-2.5 right-2.5 p-1 rounded bg-surface-800/80 text-slate-400 hover:text-slate-200 opacity-0 group-hover:opacity-100 transition-opacity"
            title="Copy message"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        )}

        <div className="space-y-1">
          {renderFormattedContent(message.content)}
        </div>
      </div>

      {isUser && (
        <div className="w-8 h-8 rounded-lg bg-surface-700/60 border border-white/10 flex items-center justify-center shrink-0 mt-1">
          <User className="w-4 h-4 text-slate-300" />
        </div>
      )}
    </div>
  );
}
