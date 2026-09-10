/**
 * ThreatRow.jsx — A single row in the threats table.
 *
 * Props:
 *   threat     {object}   — Threat document
 *   onSelect   {function} — called with threat when row is clicked
 *   onDismiss  {function} — called with threat._id to dismiss
 *   onAck      {function} — called with threat._id to acknowledge
 */
import { formatDistanceToNow } from 'date-fns';
import SeverityBadge from '@/components/common/SeverityBadge';
import { CheckCircle2, XCircle, ChevronRight } from 'lucide-react';
import { getHumanThreat, getHumanSource, getHumanStatus } from '@/utils/threatFormatter';

export default function ThreatRow({ threat, onSelect, onDismiss, onAck }) {
  const human = getHumanThreat(threat.type, threat);
  const sourceLabel = getHumanSource(threat.source);
  const statusInfo = getHumanStatus(threat.status);

  const timeAgo = threat.createdAt
    ? formatDistanceToNow(new Date(threat.createdAt), { addSuffix: true })
    : '—';

  return (
    <div
      role="row"
      onClick={() => onSelect(threat)}
      className="grid grid-cols-12 items-center px-4 py-3
                 border-b border-white/5 last:border-0
                 hover:bg-white/[0.02] transition-colors cursor-pointer group"
    >
      {/* Severity */}
      <div className="col-span-2">
        <SeverityBadge severity={threat.severity} />
      </div>

      {/* Type */}
      <div className="col-span-3 text-xs pr-2">
        <p className="font-semibold text-slate-200 truncate">{human.title}</p>
        <p className="text-[10px] text-slate-500 font-mono truncate">{threat.type}</p>
      </div>

      {/* Source */}
      <div className="col-span-3 text-xs text-slate-400 truncate pr-2">
        <span>{sourceLabel}</span>
      </div>

      {/* Detected */}
      <div className="col-span-2 text-xs text-slate-500">
        {timeAgo}
      </div>

      {/* Status */}
      <div className="col-span-1">
        <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full border whitespace-nowrap ${statusInfo.color}`}>
          {statusInfo.label}
        </span>
      </div>

      {/* Actions */}
      <div
        className="col-span-2 flex items-center justify-end gap-1
                   opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={(e) => e.stopPropagation()}
      >
        {threat.status !== 'acknowledged' && threat.status !== 'dismissed' && (
          <button
            onClick={() => onAck(threat._id)}
            title="Acknowledge"
            aria-label="Acknowledge threat"
            className="p-1.5 rounded-lg text-amber-500 hover:text-amber-300 hover:bg-amber-400/10 transition-colors"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
          </button>
        )}
        {threat.status !== 'dismissed' && (
          <button
            onClick={() => onDismiss(threat._id)}
            title="Dismiss"
            aria-label="Dismiss threat"
            className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-400/10 transition-colors"
          >
            <XCircle className="w-3.5 h-3.5" />
          </button>
        )}
        <ChevronRight className="w-3.5 h-3.5 text-slate-600 ml-1" />
      </div>
    </div>
  );
}
