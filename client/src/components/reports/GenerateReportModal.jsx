/**
 * GenerateReportModal.jsx — Modal for configuring and generating PDF incident reports.
 *
 * Props:
 *   isOpen       {boolean}
 *   onClose      {function}
 *   onGenerate   {function} — called with payload { title, incidentId, timeRange }
 *   incidents    {array}    — list of available incidents
 */
import { useState } from 'react';
import Modal from '@/components/common/Modal';
import { FileText, Calendar, GitBranch, Loader2 } from 'lucide-react';

export default function GenerateReportModal({ isOpen, onClose, onGenerate, incidents = [] }) {
  const [reportType, setReportType] = useState('incident'); // 'incident' | 'timerange'
  const [title, setTitle] = useState('');
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [fromDate, setFromDate] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 7);
    return d.toISOString().split('T')[0];
  });
  const [toDate, setToDate] = useState(() => new Date().toISOString().split('T')[0]);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) return;

    setLoading(true);
    try {
      const payload = {
        title: title.trim(),
        incidentId: reportType === 'incident' ? selectedIncidentId || null : null,
        timeRange: reportType === 'timerange' ? {
          from: new Date(fromDate).toISOString(),
          to: new Date(`${toDate}T23:59:59.999Z`).toISOString(),
        } : null,
      };

      await onGenerate(payload);
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Generate Security Report" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Title */}
        <div>
          <label className="block text-xs font-semibold text-slate-400 mb-1">Report Title</label>
          <input
            type="text"
            required
            placeholder="e.g., Weekly Threat Summary or Ransomware Incident Brief"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="input w-full text-xs"
          />
        </div>

        {/* Scope Type Tabs */}
        <div>
          <label className="block text-xs font-semibold text-slate-400 mb-1.5">Report Scope</label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setReportType('incident')}
              className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg border text-xs font-medium transition-colors ${
                reportType === 'incident'
                  ? 'border-accent-400/50 bg-accent-400/10 text-accent-300'
                  : 'border-white/5 bg-surface-800/40 text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              Incident Scoped
            </button>
            <button
              type="button"
              onClick={() => setReportType('timerange')}
              className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg border text-xs font-medium transition-colors ${
                reportType === 'timerange'
                  ? 'border-accent-400/50 bg-accent-400/10 text-accent-300'
                  : 'border-white/5 bg-surface-800/40 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Calendar className="w-3.5 h-3.5" />
              Time Range
            </button>
          </div>
        </div>

        {/* Scope Inputs */}
        {reportType === 'incident' ? (
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Target Incident</label>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="input w-full text-xs bg-surface-900 cursor-pointer"
              required={reportType === 'incident'}
            >
              <option value="">Select an incident...</option>
              {incidents.map((inc) => (
                <option key={inc._id} value={inc._id}>
                  [{inc.severity?.toUpperCase()}] {inc.title}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">From Date</label>
              <input
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
                className="input w-full text-xs"
                required={reportType === 'timerange'}
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">To Date</label>
              <input
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
                className="input w-full text-xs"
                required={reportType === 'timerange'}
              />
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/5">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="btn-ghost text-xs px-4"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading || !title.trim() || (reportType === 'incident' && !selectedIncidentId)}
            className="btn-primary text-xs px-4 flex items-center gap-1.5"
          >
            {loading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Generating PDF...
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5" />
                Generate Report
              </>
            )}
          </button>
        </div>
      </form>
    </Modal>
  );
}
