/**
 * IncidentTimeline.jsx — Forensic chronological event trail for incident triage.
 *
 * Renders constituent threat findings for an incident in ascending time order,
 * with severity color-band connectors, source metadata, and expandable descriptions.
 * Designed to be embedded inside the Incident Detail Modal in IncidentsPage.jsx.
 */
import { useState } from 'react';
import { format } from 'date-fns';
import { ChevronDown, ChevronRight, Clock, Terminal } from 'lucide-react';
import SeverityBadge from '@/components/common/SeverityBadge';
import { getHumanStatus } from '@/utils/threatFormatter';

const SEV_COLORS = {
  critical: { line: 'bg-red-500',    dot: 'bg-red-400 ring-red-500/40',    card: 'border-red-500/20 hover:border-red-500/40' },
  high:     { line: 'bg-orange-500', dot: 'bg-orange-400 ring-orange-500/40', card: 'border-orange-500/20 hover:border-orange-500/40' },
  medium:   { line: 'bg-yellow-500', dot: 'bg-yellow-400 ring-yellow-500/40', card: 'border-yellow-500/20 hover:border-yellow-500/40' },
  low:      { line: 'bg-blue-500',   dot: 'bg-blue-400 ring-blue-500/40',   card: 'border-blue-500/20 hover:border-blue-500/40' },
  info:     { line: 'bg-slate-500',  dot: 'bg-slate-400 ring-slate-500/40', card: 'border-slate-600/20 hover:border-slate-600/40' },
};

function TimelineEvent({ threat, isLast }) {
  const [expanded, setExpanded] = useState(false);
  const sev    = threat.severity?.toLowerCase() || 'info';
  const colors = SEV_COLORS[sev] || SEV_COLORS.info;
  const ts     = threat.createdAt
    ? format(new Date(threat.createdAt), 'dd MMM yyyy · HH:mm:ss')
    : 'Unknown time';
  const src = threat.source?.ip
    || threat.source?.processName
    || threat.source?.hostname
    || null;

  return (
    <div className="flex gap-3 group">
      {/* Vertical connector */}
      <div className="flex flex-col items-center">
        <div className={`w-2.5 h-2.5 rounded-full ring-2 ring-offset-1 ring-offset-surface-900 shrink-0 mt-0.5 ${colors.dot}`} />
        {!isLast && <div className={`w-px flex-1 mt-1 opacity-40 ${colors.line}`} />}
      </div>

      {/* Event card */}
      <div className={`flex-1 pb-4 ${isLast ? 'pb-0' : ''}`}>
        <div
          className={`glass-card border px-3 py-2.5 rounded-xl cursor-pointer transition-all duration-200 ${colors.card}`}
          onClick={() => setExpanded((e) => !e)}
        >
          {/* Header row */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              {expanded
                ? <ChevronDown  className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                : <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />}
              <SeverityBadge severity={sev} showIcon={false} />
              <span className="text-xs font-semibold text-slate-200 truncate">{threat.type}</span>
              {src && (
                <span className="text-[11px] font-mono text-slate-500 truncate hidden sm:inline">
                  · {src}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className={`text-[9px] font-medium px-2 py-0.5 rounded-full border ${getHumanStatus(threat.status).color}`}>
                {getHumanStatus(threat.status).label}
              </span>
              <span className="text-[10px] font-mono text-slate-500 hidden sm:flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {ts}
              </span>
            </div>
          </div>

          {/* Expanded details */}
          {expanded && (
            <div className="mt-2.5 pt-2.5 border-t border-white/5 space-y-1.5 text-xs">
              {threat.description && (
                <p className="text-slate-300 leading-relaxed">{threat.description}</p>
              )}
              <div className="grid grid-cols-2 gap-x-6 gap-y-1 mt-2 text-[11px]">
                {threat.source?.ip && (
                  <>
                    <span className="text-slate-500">Source IP</span>
                    <span className="font-mono text-accent-400">{threat.source.ip}</span>
                  </>
                )}
                {threat.source?.processName && (
                  <>
                    <span className="text-slate-500">Process</span>
                    <span className="font-mono text-slate-300">{threat.source.processName}</span>
                  </>
                )}
                {threat.source?.pid && (
                  <>
                    <span className="text-slate-500">PID</span>
                    <span className="font-mono text-slate-300">{threat.source.pid}</span>
                  </>
                )}
                {threat.source?.port && (
                  <>
                    <span className="text-slate-500">Port</span>
                    <span className="font-mono text-slate-300">{threat.source.port}</span>
                  </>
                )}
                <>
                  <span className="text-slate-500">Status</span>
                  <span className="text-slate-300 capitalize">{threat.status || 'new'}</span>
                </>
                {threat._id && (
                  <>
                    <span className="text-slate-500">Threat ID</span>
                    <span className="font-mono text-[10px] text-slate-500 truncate">{threat._id}</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * @param {object[]} threats - Array of Threat objects linked to the incident
 */
export default function IncidentTimeline({ threats = [] }) {
  if (!threats || threats.length === 0) {
    return (
      <div className="py-8 flex flex-col items-center gap-2 text-slate-500">
        <Terminal className="w-7 h-7 opacity-40" />
        <p className="text-xs">No findings linked to this incident yet.</p>
      </div>
    );
  }

  // Sort ascending by creation time for a forensic trail
  const sorted = [...threats].sort(
    (a, b) => new Date(a.createdAt) - new Date(b.createdAt)
  );

  return (
    <div className="max-h-72 overflow-y-auto pr-1 space-y-0">
      {sorted.map((threat, idx) => (
        <TimelineEvent
          key={threat._id || idx}
          threat={threat}
          isLast={idx === sorted.length - 1}
        />
      ))}
    </div>
  );
}
