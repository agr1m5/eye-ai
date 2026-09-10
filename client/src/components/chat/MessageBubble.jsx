/**
 * MessageBubble.jsx — Formatted chat message bubble supporting markdown and code snippets.
 */
import { useState } from 'react';
import { Bot, User, Copy, Check, Zap, ShieldCheck } from 'lucide-react';
import toast from 'react-hot-toast';
import { defenseApi } from '@/services/api';

export default function MessageBubble({ message }) {
  const isUser = message.role === 'user';
  const [copied, setCopied] = useState(false);
  const [executedActions, setExecutedActions] = useState({});

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExecuteContainment = async (actionType, target) => {
    try {
      const res = await defenseApi.contain({
        actionType,
        target,
        reason: 'Autonomous AI Copilot Playbook Execution',
        executedBy: 'autonomous_ai',
      });
      if (res.data?.status === 'success') {
        toast.success(`⚡ Countermeasure Enforced: ${actionType} on ${target}`);
        setExecutedActions((prev) => ({ ...prev, [target]: true }));
      }
    } catch (err) {
      toast.error(`Containment failed: ${err.response?.data?.message || err.message}`);
    }
  };

  // Simple clean markdown-like line renderer
  const renderFormattedContent = (content) => {
    const lines = content.split('\n');
    let inCodeBlock = false;
    let codeBuffer = [];

    const elements = [];

    lines.forEach((line, idx) => {
      // Interactive SOAR countermeasure card
      const actionMatch = line.match(/\[ACTION:(block_ip|kill_process|isolate_host|quarantine_file):([^\]]+)\]/);
      if (actionMatch) {
        const [, actionType, target] = actionMatch;
        const isExecuted = executedActions[target];
        elements.push(
          <div key={`action-${idx}`} className="my-2 p-3 rounded-lg bg-red-950/50 border border-red-800/80 flex items-center justify-between gap-3 shadow-lg">
            <div className="flex items-center gap-2.5">
              <div className="p-1 rounded bg-red-900/60 text-red-300">
                <Zap className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <p className="text-xs font-semibold text-red-200 uppercase tracking-wide font-mono">
                  Recommended Action: {actionType.replace('_', ' ')}
                </p>
                <p className="text-[11px] font-mono text-slate-300">Target: {target}</p>
              </div>
            </div>
            <button
              onClick={() => handleExecuteContainment(actionType, target)}
              disabled={isExecuted}
              className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all ${
                isExecuted
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 cursor-not-allowed'
                  : 'bg-red-700 hover:bg-red-600 text-white shadow-md hover:shadow-red-900/50'
              }`}
            >
              {isExecuted ? '✓ Enforced' : '⚡ Execute Containment'}
            </button>
          </div>
        );
        return;
      }
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
