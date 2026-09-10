/**
 * LiveEventFeed.jsx — Real-time event streaming feed for the SOC Dashboard.
 *
 * Subscribes to 'finding:new' socket events and renders incoming threats with
 * severity badges, metadata tags, and timestamps.
 */
import { useState, useEffect, useRef } from 'react';
import { useSocket } from '@/context/SocketContext';
import SeverityBadge from '@/components/common/SeverityBadge';
import { Activity, ShieldAlert, Terminal } from 'lucide-react';
import { format } from 'date-fns';
import { getHumanThreat, getHumanSource } from '@/utils/threatFormatter';

export default function LiveEventFeed({ initialEvents = [] }) {
  const { subscribe, connected } = useSocket();
  const [events, setEvents] = useState(initialEvents);
  const feedEndRef = useRef(null);

  useEffect(() => {
    // Subscribe to new incoming findings from socket
    const unsubscribe = subscribe('finding:new', (newFinding) => {
      setEvents((prev) => [newFinding, ...prev].slice(0, 50));
    });

    return () => {
      unsubscribe();
    };
  }, [subscribe]);

  return (
    <div className="glass-card glow-border h-80 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-900/40">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-accent-400 animate-pulse" />
          <span className="text-xs font-semibold text-slate-200">Live Event Feed</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-700/60 text-slate-400 font-mono">
            {events.length} events
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-ping' : 'bg-slate-600'}`} />
          <span className="text-[11px] text-slate-400">
            {connected ? 'Streaming' : 'Connecting'}
          </span>
        </div>
      </div>

      {/* Feed list */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1.5 font-mono text-xs">
        {events.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500">
            <Terminal className="w-8 h-8 mb-2 stroke-1 opacity-50 text-slate-400" />
            <p className="text-xs font-medium text-slate-400">Awaiting security events</p>
            <p className="text-[11px] text-slate-600 max-w-xs mt-0.5">
              Live findings emitted by the local agent will stream here in real time.
            </p>
          </div>
        ) : (
          events.map((evt, idx) => {
            const human = getHumanThreat(evt.type, evt);
            const timeStr = evt.createdAt ? format(new Date(evt.createdAt), 'HH:mm:ss') : format(new Date(), 'HH:mm:ss');
            const sourceText = getHumanSource(evt.source);

            return (
              <div
                key={evt._id || `${evt.type}-${idx}`}
                className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-surface-800/40 hover:bg-surface-800/80 border border-white/5 transition-colors"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="text-[10px] text-slate-500 shrink-0">{timeStr}</span>
                  <SeverityBadge severity={evt.severity} showIcon={false} />
                  <span className="text-slate-200 font-medium truncate">{human.title}</span>
                  <span className="text-slate-500 truncate hidden md:inline text-[11px] font-mono">
                    ({evt.type})
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="px-2 py-0.5 rounded bg-surface-700/50 text-[10px] text-accent-300 border border-accent-500/20">
                    {sourceText}
                  </span>
                </div>
              </div>
            );
          })
        )}
        <div ref={feedEndRef} />
      </div>
    </div>
  );
}
