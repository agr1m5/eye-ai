/**
 * SeverityChart.jsx — Real-time severity distribution breakdown.
 *
 * Hydrates initial counts from GET /api/threats/stats on mount so the
 * chart reflects historical data from the DB, not just the live session.
 * Live Socket.IO events then increment counts in real time.
 */
import { useState, useEffect, useRef } from 'react';
import { useSocket } from '@/context/SocketContext';
import { threatApi } from '@/services/api';
import { BarChart3, RefreshCw } from 'lucide-react';

const SEVERITIES = [
  { key: 'critical', label: 'Critical', color: 'bg-red-500',    text: 'text-red-400',    glow: 'shadow-red-500/30'    },
  { key: 'high',     label: 'High',     color: 'bg-orange-500', text: 'text-orange-400', glow: 'shadow-orange-500/30' },
  { key: 'medium',   label: 'Medium',   color: 'bg-yellow-500', text: 'text-yellow-400', glow: 'shadow-yellow-500/30' },
  { key: 'low',      label: 'Low',      color: 'bg-blue-500',   text: 'text-blue-400',   glow: 'shadow-blue-500/30'   },
  { key: 'info',     label: 'Info',     color: 'bg-slate-500',  text: 'text-slate-400',  glow: ''                     },
];

const ZERO = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

export default function SeverityChart() {
  const { subscribe } = useSocket();
  const [counts, setCounts]     = useState({ ...ZERO });
  const [hydrated, setHydrated] = useState(false);
  const mountedRef = useRef(true);

  // ── On mount: fetch historical severity distribution from DB ──
  useEffect(() => {
    mountedRef.current = true;

    threatApi.stats()
      .then((res) => {
        if (!mountedRef.current) return;
        const d = res.data?.data;
        if (d) {
          setCounts({
            critical: d.critical || 0,
            high:     d.high     || 0,
            medium:   d.medium   || 0,
            low:      d.low      || 0,
            info:     d.info     || 0,
          });
        }
        setHydrated(true);
      })
      .catch(() => setHydrated(true));

    return () => { mountedRef.current = false; };
  }, []);

  // ── Live: increment as new findings arrive ─────────────────────
  useEffect(() => {
    const unsub = subscribe('finding:new', (finding) => {
      const sev = finding.severity?.toLowerCase();
      if (sev && sev in ZERO) {
        setCounts((prev) => ({ ...prev, [sev]: (prev[sev] || 0) + 1 }));
      }
    });
    return () => unsub();
  }, [subscribe]);

  const total = Object.values(counts).reduce((s, n) => s + n, 0);

  return (
    <div className="glass-card glow-border h-80 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-900/40">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-accent-400" />
          <span className="text-xs font-semibold text-slate-200">Severity Distribution</span>
          {!hydrated && (
            <RefreshCw className="w-3 h-3 text-slate-500 animate-spin" />
          )}
        </div>
        <span className="text-[10px] text-slate-500 font-mono">
          Total: <strong className="text-slate-300">{total}</strong>
        </span>
      </div>

      {/* Bars */}
      <div className="flex-1 p-5 flex flex-col justify-around">
        {SEVERITIES.map(({ key, label, color, text }) => {
          const val        = counts[key] || 0;
          const percentage = total > 0 ? Math.round((val / total) * 100) : 0;
          const barWidth   = total > 0 ? Math.max(percentage, val > 0 ? 4 : 0) : 0;

          return (
            <div key={key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className={`font-medium ${text}`}>{label}</span>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="text-slate-200 font-semibold">{val}</span>
                  <span className="text-slate-600">({percentage}%)</span>
                </div>
              </div>
              <div className="w-full h-2 bg-surface-900 rounded-full overflow-hidden border border-white/5">
                <div
                  className={`h-full ${color} transition-all duration-700 ease-out rounded-full`}
                  style={{ width: `${barWidth}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
