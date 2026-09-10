/**
 * MitreMatrixPage.jsx — MITRE ATT&CK Coverage Heatmap.
 *
 * Fetches all threats for the current user, groups them by the inferred
 * MITRE technique tag, and renders a visual heatmap grid.
 *
 * - Observed techniques glow with severity-weighted colours.
 * - Unobserved techniques are dim — revealing detection gaps.
 * - Hovering a cell shows: observation count, last seen, and tactic.
 * - Uses the same technique-to-tactic mapping as correlationService.
 */
import { useState, useEffect } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import Spinner from '@/components/common/Spinner';
import { threatApi } from '@/services/api';
import { Shield, Target, Eye, EyeOff } from 'lucide-react';
import { format } from 'date-fns';

/* ── MITRE Technique catalogue ─────────────────────────────────
   Source: MITRE ATT&CK Enterprise (subset covering Rakshak's inferred techniques)
   Arranged by tactic for the matrix display.
──────────────────────────────────────────────────────────────── */
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Dev.' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Priv. Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Cred. Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'C2' },
  { id: 'TA0040', name: 'Impact' },
];

// All tracked techniques, each assigned to one tactic
const ALL_TECHNIQUES = [
  { id: 'T1595', name: 'Active Scanning',               tactic: 'TA0043' },
  { id: 'T1046', name: 'Network Service Discovery',     tactic: 'TA0007' },
  { id: 'T1110', name: 'Brute Force',                   tactic: 'TA0006' },
  { id: 'T1059', name: 'Command & Script. Interpreter', tactic: 'TA0002' },
  { id: 'T1190', name: 'Exploit Public-Facing App',     tactic: 'TA0001' },
  { id: 'T1486', name: 'Data Encrypted for Impact',     tactic: 'TA0040' },
  { id: 'T1071', name: 'Application Layer Protocol',    tactic: 'TA0011' },
  { id: 'T1068', name: 'Exploit for Priv. Escalation',  tactic: 'TA0004' },
  { id: 'T1498', name: 'Network Denial of Service',     tactic: 'TA0040' },
  { id: 'T1543', name: 'Create/Modify System Process',  tactic: 'TA0003' },
  { id: 'T1055', name: 'Process Injection',             tactic: 'TA0004' },
  { id: 'T1036', name: 'Masquerading',                  tactic: 'TA0005' },
  { id: 'T1070', name: 'Indicator Removal',             tactic: 'TA0005' },
  { id: 'T1105', name: 'Ingress Tool Transfer',         tactic: 'TA0011' },
  { id: 'T1021', name: 'Remote Services',               tactic: 'TA0008' },
  { id: 'T1133', name: 'External Remote Services',      tactic: 'TA0001' },
  { id: 'T1078', name: 'Valid Accounts',                tactic: 'TA0001' },
  { id: 'T1056', name: 'Input Capture',                 tactic: 'TA0009' },
  { id: 'T1041', name: 'Exfil Over C2 Channel',        tactic: 'TA0040' },
  { id: 'T1049', name: 'System Network Connections',    tactic: 'TA0007' },
  { id: 'T1082', name: 'System Information Discovery',  tactic: 'TA0007' },
  { id: 'T1562', name: 'Impair Defenses',               tactic: 'TA0005' },
  { id: 'T1204', name: 'User Execution',                tactic: 'TA0002' },
  { id: 'T1566', name: 'Phishing',                      tactic: 'TA0001' },
];

function heatColor(count, maxCount) {
  if (count === 0) return null;
  const ratio = Math.min(count / Math.max(maxCount, 1), 1);
  if (ratio > 0.6) return { bg: 'bg-red-500/80',    border: 'border-red-500',    text: 'text-white',       glow: 'shadow-red-500/40' };
  if (ratio > 0.3) return { bg: 'bg-orange-500/70', border: 'border-orange-500', text: 'text-white',       glow: 'shadow-orange-500/30' };
  return              { bg: 'bg-accent-400/50',   border: 'border-accent-400', text: 'text-slate-100',   glow: 'shadow-accent-400/20' };
}

function TechniqueCell({ tech, stats, maxCount }) {
  const [hovered, setHovered] = useState(false);
  const s = stats[tech.id];
  const count = s?.count || 0;
  const colors = heatColor(count, maxCount);
  const tactic = TACTICS.find((t) => t.id === tech.tactic);

  return (
    <div className="relative" onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <div
        className={`
          w-full h-14 rounded-lg border flex flex-col items-center justify-center cursor-default
          transition-all duration-200 text-center px-1
          ${count > 0
            ? `${colors.bg} ${colors.border} shadow-md ${colors.glow} ${colors.text}`
            : 'bg-surface-800/40 border-white/5 text-slate-700 hover:border-slate-600 hover:text-slate-500'
          }
        `}
      >
        <span className="text-[9px] font-mono font-bold leading-none">{tech.id}</span>
        <span className={`text-[8px] leading-tight text-center mt-0.5 ${count > 0 ? 'opacity-90' : 'opacity-50'} line-clamp-2`}>
          {tech.name}
        </span>
        {count > 0 && (
          <span className="text-[9px] font-bold mt-0.5 opacity-80">{count}×</span>
        )}
      </div>

      {/* Hover tooltip */}
      {hovered && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 glass-card p-3 rounded-xl border border-white/10 shadow-2xl pointer-events-none">
          <p className="text-xs font-bold text-slate-100">{tech.id}</p>
          <p className="text-[11px] text-slate-300 mt-0.5">{tech.name}</p>
          <p className="text-[10px] text-slate-500 mt-1">Tactic: {tactic?.name || 'Unknown'}</p>
          {count > 0 ? (
            <>
              <p className="text-[10px] text-accent-400 mt-1 font-semibold">{count} observation{count !== 1 ? 's' : ''}</p>
              {s?.lastSeen && (
                <p className="text-[10px] text-slate-500">Last: {format(new Date(s.lastSeen), 'dd MMM, HH:mm')}</p>
              )}
            </>
          ) : (
            <p className="text-[10px] text-slate-600 mt-1">No observations — detection gap</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function MitreMatrixPage() {
  const [stats, setStats]     = useState({});
  const [loading, setLoading] = useState(true);
  const [covered, setCovered] = useState(0);
  const [maxCount, setMaxCount] = useState(1);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        // Fetch all threats (up to 500) to build the heatmap client-side
        const { data } = await threatApi.list({ limit: 500, sort: '-createdAt' });
        if (cancelled) return;

        const threats = data?.data?.threats || [];
        const techStats = {};

        for (const t of threats) {
          // Check both mitreTag field and infer from type
          const tags = [];
          if (t.mitreTag) tags.push(t.mitreTag);

          // Inline heuristic inference (mirrors correlationService)
          const combined = `${t.type || ''} ${t.description || ''}`.toLowerCase();
          if (combined.includes('port scan') || combined.includes('reconnaissance')) tags.push('T1046');
          if (combined.includes('brute') || combined.includes('login')) tags.push('T1110');
          if (combined.includes('command') || combined.includes('powershell') || combined.includes('sh_spawn')) tags.push('T1059');
          if (combined.includes('sql') || combined.includes('exploit') || combined.includes('traversal')) tags.push('T1190');
          if (combined.includes('ransom') || combined.includes('encrypt')) tags.push('T1486');
          if (combined.includes('c2') || combined.includes('malware') || combined.includes('beacon')) tags.push('T1071');
          if (combined.includes('privilege') || combined.includes('root') || combined.includes('sudo')) tags.push('T1068');
          if (combined.includes('ddos') || combined.includes('flood')) tags.push('T1498');

          for (const tag of [...new Set(tags)]) {
            if (!techStats[tag]) techStats[tag] = { count: 0, lastSeen: null };
            techStats[tag].count++;
            const ts = t.createdAt;
            if (!techStats[tag].lastSeen || ts > techStats[tag].lastSeen) techStats[tag].lastSeen = ts;
          }
        }

        const max = Math.max(1, ...Object.values(techStats).map((s) => s.count));
        setStats(techStats);
        setMaxCount(max);
        setCovered(Object.keys(techStats).length);
      } catch (_) { /* non-blocking */ } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  const total = ALL_TECHNIQUES.length;
  const coveragePct = total > 0 ? Math.round((covered / total) * 100) : 0;

  return (
    <PageWrapper
      title="MITRE ATT&CK Coverage Matrix"
      subtitle="Observed technique heatmap — glowing cells indicate detected activity, dim cells are detection gaps"
    >
      {/* Coverage summary bar */}
      <div className="glass-card glow-border p-4 mb-6 flex flex-wrap items-center gap-6">
        <div className="flex items-center gap-3">
          <Target className="w-5 h-5 text-accent-400" />
          <div>
            <p className="text-xs text-slate-500">Coverage Score</p>
            <p className="text-xl font-bold text-slate-100">{coveragePct}%</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Eye className="w-4 h-4 text-emerald-400" />
          <div>
            <p className="text-xs text-slate-500">Observed Techniques</p>
            <p className="text-lg font-bold text-emerald-400">{covered}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <EyeOff className="w-4 h-4 text-slate-600" />
          <div>
            <p className="text-xs text-slate-500">Detection Gaps</p>
            <p className="text-lg font-bold text-slate-500">{total - covered}</p>
          </div>
        </div>
        {/* Coverage bar */}
        <div className="flex-1 min-w-40">
          <div className="w-full h-2 bg-surface-900 rounded-full overflow-hidden border border-white/5">
            <div
              className="h-full bg-accent-400 transition-all duration-1000 rounded-full"
              style={{ width: `${coveragePct}%` }}
            />
          </div>
          <p className="text-[10px] text-slate-600 mt-1 font-mono">{covered} / {total} tracked techniques</p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-red-500/80 inline-block" /> High freq.</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-orange-500/70 inline-block" /> Mid freq.</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-accent-400/50 inline-block" /> Observed</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-surface-800/40 border border-white/5 inline-block" /> Gap</span>
        </div>
      </div>

      {loading ? (
        <div className="py-24 flex justify-center"><Spinner size="lg" /></div>
      ) : (
        <>
          {/* Tactic header row */}
          <div className="grid gap-2 mb-1" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}>
            {TACTICS.map((t) => (
              <div key={t.id} className="text-center">
                <p className="text-[9px] font-semibold uppercase tracking-wider text-accent-400/80 truncate px-1">{t.name}</p>
              </div>
            ))}
          </div>

          {/* Matrix grid — one column per tactic, techniques stacked vertically */}
          <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}>
            {TACTICS.map((tactic) => {
              const techs = ALL_TECHNIQUES.filter((t) => t.tactic === tactic.id);
              return (
                <div key={tactic.id} className="flex flex-col gap-1.5">
                  {techs.map((tech) => (
                    <TechniqueCell key={tech.id} tech={tech} stats={stats} maxCount={maxCount} />
                  ))}
                </div>
              );
            })}
          </div>
        </>
      )}
    </PageWrapper>
  );
}
