/**
 * SeverityChart.jsx — Real-time severity distribution breakdown.
 *
 * Listens for new findings over Socket.IO and displays dynamic distribution bars
 * for each severity category (critical, high, medium, low, info).
 */
import { useState, useEffect, useMemo } from 'react';
import { useSocket } from '@/context/SocketContext';
import { BarChart3 } from 'lucide-react';

const SEVERITIES = [
  { key: 'critical', label: 'Critical', color: 'bg-red-500', text: 'text-red-400', border: 'border-red-500/30' },
  { key: 'high',     label: 'High',     color: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30' },
  { key: 'medium',   label: 'Medium',   color: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  { key: 'low',      label: 'Low',      color: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500/30' },
  { key: 'info',     label: 'Info',     color: 'bg-slate-500', text: 'text-slate-400', border: 'border-slate-500/30' },
];

export default function SeverityChart({ initialCounts = {} }) {
  const { subscribe } = useSocket();
  const [counts, setCounts] = useState({
    critical: initialCounts.critical || 0,
    high:     initialCounts.high || 0,
    medium:   initialCounts.medium || 0,
    low:      initialCounts.low || 0,
    info:     initialCounts.info || 0,
  });

  useEffect(() => {
    const unsubscribe = subscribe('finding:new', (finding) => {
      const sev = finding.severity?.toLowerCase();
      if (sev && counts[sev] !== undefined) {
        setCounts((prev) => ({
          ...prev,
          [sev]: (prev[sev] || 0) + 1,
        }));
      }
    });

    return () => unsubscribe();
  }, [subscribe, counts]);

  const total = useMemo(() => {
    return Object.values(counts).reduce((sum, n) => sum + n, 0);
  }, [counts]);

  return (
    <div className="glass-card glow-border h-80 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-900/40">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-accent-400" />
          <span className="text-xs font-semibold text-slate-200">Severity Distribution</span>
        </div>
        <span className="text-[10px] text-slate-500 font-mono">
          Total: <strong className="text-slate-300">{total}</strong>
        </span>
      </div>

      {/* Bars */}
      <div className="flex-1 p-5 flex flex-col justify-around">
        {SEVERITIES.map(({ key, label, color, text, border }) => {
          const val = counts[key] || 0;
          const percentage = total > 0 ? Math.round((val / total) * 100) : 0;

          return (
            <div key={key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className={`font-medium ${text}`}>{label}</span>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="text-slate-300 font-semibold">{val}</span>
                  <span className="text-slate-600">({percentage}%)</span>
                </div>
              </div>

              {/* Progress bar container */}
              <div className="w-full h-2 bg-surface-900 rounded-full overflow-hidden border border-white/5">
                <div
                  className={`h-full ${color} transition-all duration-500 rounded-full`}
                  style={{ width: `${Math.max(percentage, val > 0 ? 5 : 0)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
