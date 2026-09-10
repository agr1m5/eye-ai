/**
 * IncidentCard.jsx — Card representation of a correlated incident.
 *
 * Props:
 *   incident       {object}   — Incident document
 *   onSelect       {function} — called when card or details clicked
 *   onStatusChange {function} — called with (incidentId, newStatus)
 */
import { useState } from 'react';
import { formatDistanceToNow, format } from 'date-fns';
import { GitBranch, Shield, ChevronDown, ChevronUp, AlertCircle, Clock, CheckCircle } from 'lucide-react';
import SeverityBadge from '@/components/common/SeverityBadge';
import { formatTechnique } from '@/utils/threatFormatter';

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open', color: 'text-amber-400 bg-amber-400/10 border-amber-400/20' },
  { value: 'investigating', label: 'Investigating', color: 'text-blue-400 bg-blue-400/10 border-blue-400/20' },
  { value: 'resolved', label: 'Resolved', color: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20' },
  { value: 'closed', label: 'Closed', color: 'text-slate-500 bg-slate-500/10 border-slate-500/20' },
];

export default function IncidentCard({ incident, onSelect, onStatusChange }) {
  const [isUpdating, setIsUpdating] = useState(false);

  const handleStatusSelect = async (e) => {
    e.stopPropagation();
    const newStatus = e.target.value;
    if (newStatus === incident.status) return;

    setIsUpdating(true);
    try {
      await onStatusChange(incident._id, newStatus);
    } finally {
      setIsUpdating(false);
    }
  };

  const currentStatusObj = STATUS_OPTIONS.find((s) => s.value === incident.status) || STATUS_OPTIONS[0];

  const timeAgo = incident.createdAt
    ? formatDistanceToNow(new Date(incident.createdAt), { addSuffix: true })
    : '—';

  return (
    <div
      onClick={() => onSelect(incident)}
      className="glass-card glow-border p-5 rounded-xl border border-white/5 hover:border-accent-400/30
                 transition-all duration-200 cursor-pointer group space-y-4"
    >
      {/* Top Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-surface-800 border border-white/5 text-accent-400 mt-0.5">
            <GitBranch className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={incident.severity} />
              <span className="text-[11px] font-mono text-slate-500">#{incident._id.slice(-6)}</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-100 group-hover:text-accent-300 transition-colors mt-1">
              {incident.title}
            </h3>
          </div>
        </div>

        {/* Status Dropdown */}
        <div onClick={(e) => e.stopPropagation()} className="relative">
          <select
            value={incident.status}
            onChange={handleStatusSelect}
            disabled={isUpdating}
            className={`text-xs px-2.5 py-1 rounded-full font-medium border appearance-none pr-7 cursor-pointer
                        bg-surface-900 focus:outline-none focus:ring-1 focus:ring-accent-400 transition-colors
                        ${currentStatusObj.color} ${isUpdating ? 'opacity-50 cursor-wait' : ''}`}
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value} className="bg-surface-900 text-slate-200">
                {opt.label}
              </option>
            ))}
          </select>
          <ChevronDown className="w-3.5 h-3.5 absolute right-2 top-2 pointer-events-none text-slate-400" />
        </div>
      </div>

      {/* Narrative / Summary */}
      {incident.summary && (
        <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
          {incident.summary}
        </p>
      )}

      {/* MITRE ATT&CK badges */}
      {incident.mitreTechniques && incident.mitreTechniques.length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {incident.mitreTechniques.map((tech) => (
            <span
              key={tech}
              className="text-[10px] font-medium px-2 py-0.5 rounded bg-purple-950/40 border border-purple-800/30 text-purple-300"
            >
              {formatTechnique(tech)}
            </span>
          ))}
        </div>
      )}

      {/* Footer Info */}
      <div className="flex items-center justify-between pt-3 border-t border-white/5 text-xs text-slate-500">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-slate-600" />
          <span>{incident.threatIds?.length || 0} correlated threats</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-slate-600" />
          <span>{timeAgo}</span>
        </div>
      </div>
    </div>
  );
}
