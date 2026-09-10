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
import { CheckCircle2, XCircle, ChevronRight, Filter } from 'lucide-react';
import { getHumanThreat, getHumanSource, getHumanStatus } from '@/utils/threatFormatter';

export default function ThreatRow({
  threat,
  onSelect,
  onDismiss,
  onAck,
  isSelected = false,
  onToggleSelect,
  onFilterType,
}) {
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
      className={`grid grid-cols-12 items-center px-4 py-3
                 border-b border-white/5 last:border-0
                 hover:bg-white/[0.02] transition-colors cursor-pointer group ${
                   isSelected ? 'bg-brand-500/[0.07]' : ''
                 }`}
    >
      {/* Checkbox */}
      <div
        className="col-span-1 flex items-center"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          type="checkbox"
          checked={isSelected}
          onChange={() => onToggleSelect && onToggleSelect(threat._id)}
          aria-label={`Select threat ${human.title}`}
          className="w-4 h-4 rounded border-slate-700 bg-surface-900 text-brand-500 focus:ring-brand-500/20 cursor-pointer"
        />
      </div>

      {/* Severity */}
      <div className="col-span-2">
        <SeverityBadge severity={threat.severity} />
      </div>

      {/* Type */}
      <div className="col-span-3 text-xs pr-2">
        <div className="flex items-center gap-1.5">
          <p className="font-semibold text-slate-200 truncate">{human.title}</p>
          {onFilterType && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onFilterType(threat.type);
              }}
              title={`Filter all threats of type "${human.title}"`}
              className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-slate-500 hover:text-brand-400 hover:bg-brand-400/10 transition-all"
            >
              <Filter className="w-3 h-3" />
            </button>
          )}
        </div>
        <p className="text-[10px] text-slate-500 font-mono truncate">{threat.type}</p>
      </div>

      {/* Source */}
      <div className="col-span-2 text-xs text-slate-400 truncate pr-2">
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
        className="col-span-1 flex items-center justify-end gap-1
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
            title="Dismiss / Close"
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

