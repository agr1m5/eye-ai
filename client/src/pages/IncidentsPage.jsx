/**
 * IncidentsPage — Correlated threat clusters and triage management.
 *
 * Supports:
 *   - Status filtering (All, Open, Investigating, Resolved, Closed)
 *   - Automatic bidirectional synchronization with constituent threats
 *   - One-click Resolve & Dismiss All Threats, Investigate & Ack All Threats
 *   - Incident & correlated threats deletion with confirmation
 *   - Incident detail modal with constituent threats list & analyst notes editor
 *   - Manual Incident creation modal
 */
import { useState, useEffect, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import IncidentCard from '@/components/incidents/IncidentCard';
import Modal from '@/components/common/Modal';
import EmptyState from '@/components/common/EmptyState';
import Pagination from '@/components/common/Pagination';
import Spinner from '@/components/common/Spinner';
import SeverityBadge from '@/components/common/SeverityBadge';
import { incidentApi } from '@/services/api';
import {
  GitBranch,
  Filter,
  Plus,
  Clock,
  ShieldAlert,
  FileText,
  Save,
  Check,
  CheckCircle,
  CheckCircle2,
  Trash2,
  AlertTriangle,
  ShieldCheck,
  RotateCcw,
} from 'lucide-react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';
import IncidentTimeline from '@/components/incidents/IncidentTimeline';
import { useSocket } from '@/context/SocketContext';

const STATUS_FILTERS = [
  { value: '', label: 'All Incidents' },
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'closed', label: 'Closed' },
];

export default function IncidentsPage() {
  const { subscribe } = useSocket();
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });

  // Detail Modal
  const [activeIncident, setActiveIncident] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [notesInput, setNotesInput] = useState('');
  const [savingNotes, setSavingNotes] = useState(false);

  // Delete confirmation
  const [deleteConfirm, setDeleteConfirm] = useState(null);
  const [deleting, setDeleting] = useState(false);

  // Create Modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState('medium');
  const [newSummary, setNewSummary] = useState('');
  const [creating, setCreating] = useState(false);

  const fetchIncidents = useCallback(async (page = 1, status = statusFilter) => {
    setLoading(true);
    try {
      const params = { page, limit: 20 };
      if (status) params.status = status;

      const { data } = await incidentApi.list(params);
      if (data.status === 'success') {
        setIncidents(data.data.incidents || []);
        setPagination(data.data.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
      }
    } catch (err) {
      toast.error('Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchIncidents(1, statusFilter);
  }, [statusFilter, fetchIncidents]);

  // Real-time synchronization for new incidents, updates, and attack takedowns
  useEffect(() => {
    if (!subscribe) return;

    const unsubNew = subscribe('incident:new', (newInc) => {
      if (!newInc) return;
      setIncidents((prev) => [newInc, ...prev.filter((i) => i._id !== newInc._id)]);
      setPagination((p) => ({ ...p, total: p.total + 1 }));
      toast(`🚨 New Incident Correlated: ${newInc.title}`, { icon: '⚡' });
    });

    const unsubUpdated = subscribe('incident:updated', (updatedInc) => {
      if (!updatedInc) return;
      setIncidents((prev) => prev.map((i) => (i._id === updatedInc._id ? { ...i, ...updatedInc } : i)));
      if (activeIncident?._id === updatedInc._id) {
        setActiveIncident((prev) => ({ ...prev, ...updatedInc }));
        setIncidentDetail((prev) => (prev ? { ...prev, ...updatedInc } : prev));
      }
    });

    const unsubResolved = subscribe('incident:resolved', (resData) => {
      if (!resData?.incidentId) return;
      setIncidents((prev) =>
        prev.map((i) =>
          i._id === resData.incidentId
            ? {
                ...i,
                status: 'resolved',
                resolvedAt: resData.resolvedAt || new Date(),
                notes: resData.incident?.notes || i.notes,
                summary: resData.incident?.summary || i.summary,
              }
            : i
        )
      );

      if (activeIncident?._id === resData.incidentId) {
        setActiveIncident((prev) => ({ ...prev, status: 'resolved' }));
        setIncidentDetail((prev) =>
          prev
            ? {
                ...prev,
                status: 'resolved',
                resolvedAt: resData.resolvedAt || new Date(),
                notes: resData.incident?.notes || prev.notes,
                summary: resData.incident?.summary || prev.summary,
              }
            : prev
        );
      }

      toast.success(
        `🛡️ Attack Taken Down: Incident #${resData.incidentId.slice(-6)} neutralized and updated in Incidents!`,
        { icon: '✅', duration: 6000 }
      );
    });

    return () => {
      unsubNew();
      unsubUpdated();
      unsubResolved();
    };
  }, [subscribe, activeIncident]);

  const handleStatusChange = async (id, newStatus) => {
    try {
      const { data } = await incidentApi.updateStatus(id, newStatus);
      if (data.status === 'success') {
        setIncidents((prev) => prev.map((i) => (i._id === id ? { ...i, status: newStatus } : i)));

        if (activeIncident?._id === id) {
          setActiveIncident((prev) => ({ ...prev, status: newStatus }));
          // Refresh detail view so constituent threats display updated status
          const detailRes = await incidentApi.get(id);
          if (detailRes.data?.status === 'success') {
            setIncidentDetail(detailRes.data.data);
          }
        }

        const syncedCount = data.meta?.syncedThreatsCount;
        if (syncedCount > 0) {
          toast.success(
            `Incident ${newStatus} — synced & updated ${syncedCount} correlated threat(s)`
          );
        } else {
          toast.success(`Incident status updated to ${newStatus}`);
        }
      }
    } catch (err) {
      toast.error('Failed to update incident status');
    }
  };

  const handleOpenDetail = async (incident) => {
    setActiveIncident(incident);
    setLoadingDetail(true);
    try {
      const { data } = await incidentApi.get(incident._id);
      if (data.status === 'success') {
        setIncidentDetail(data.data);
        setNotesInput(data.data.notes || '');
      }
    } catch (err) {
      toast.error('Failed to load incident detail');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!activeIncident) return;
    setSavingNotes(true);
    try {
      await incidentApi.updateNotes(activeIncident._id, notesInput);
      setIncidents((prev) => prev.map((i) => (i._id === activeIncident._id ? { ...i, notes: notesInput } : i)));
      toast.success('Notes saved');
    } catch (err) {
      toast.error('Failed to save notes');
    } finally {
      setSavingNotes(false);
    }
  };

  const executeDeleteIncident = async () => {
    if (!deleteConfirm) return;
    setDeleting(true);
    try {
      const { data } = await incidentApi.delete(deleteConfirm._id, { deleteThreats: true });
      const count = data.data?.deletedThreatsCount ?? 0;
      toast.success(`Incident and ${count} correlated threat(s) deleted successfully`);

      setIncidents((prev) => prev.filter((i) => i._id !== deleteConfirm._id));
      if (activeIncident?._id === deleteConfirm._id) {
        setActiveIncident(null);
        setIncidentDetail(null);
      }
      setDeleteConfirm(null);
      fetchIncidents(pagination.page, statusFilter);
    } catch (err) {
      toast.error('Failed to delete incident');
    } finally {
      setDeleting(false);
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    setCreating(true);
    try {
      const { data } = await incidentApi.create({
        title: newTitle.trim(),
        severity: newSeverity,
        summary: newSummary.trim(),
      });

      if (data.status === 'success') {
        toast.success('Incident created');
        setIsCreateOpen(false);
        setNewTitle('');
        setNewSummary('');
        fetchIncidents(1, statusFilter);
      }
    } catch (err) {
      toast.error('Failed to create incident');
    } finally {
      setCreating(false);
    }
  };

  return (
    <PageWrapper
      title="Correlated Incidents"
      subtitle="Aggregated multi-stage threat clusters for SOC triage and containment"
      actions={
        <button
          onClick={() => setIsCreateOpen(true)}
          className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>New Incident</span>
        </button>
      }
    >
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-1.5 bg-surface-800/60 p-1 rounded-xl border border-white/5">
          <Filter className="w-3.5 h-3.5 text-slate-500 ml-2" />
          {STATUS_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setStatusFilter(f.value)}
              className={`text-xs px-3 py-1 rounded-lg font-medium transition-colors ${
                statusFilter === f.value
                  ? 'bg-accent-400/20 text-accent-300 border border-accent-400/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <span className="text-xs text-slate-500">
          {pagination.total} incident{pagination.total === 1 ? '' : 's'} recorded
        </span>
      </div>

      {/* Main Grid */}
      {loading ? (
        <div className="py-24 flex justify-center">
          <Spinner size="lg" />
        </div>
      ) : incidents.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="No incidents found"
          message={
            statusFilter
              ? `No incidents matching the "${statusFilter}" status filter.`
              : 'Correlated incidents will automatically generate when multiple threats link to the same host, IP, or kill-chain pattern.'
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {incidents.map((incident) => (
            <IncidentCard
              key={incident._id}
              incident={incident}
              onSelect={handleOpenDetail}
              onStatusChange={handleStatusChange}
              onDelete={(inc) => setDeleteConfirm(inc)}
            />
          ))}
        </div>
      )}

      {/* Pagination */}
      <Pagination
        page={pagination.page}
        totalPages={pagination.totalPages}
        onPageChange={(p) => fetchIncidents(p, statusFilter)}
      />

      {/* Incident Detail Modal */}
      <Modal
        isOpen={!!activeIncident}
        onClose={() => {
          setActiveIncident(null);
          setIncidentDetail(null);
        }}
        title="Incident Investigation & Triage"
        size="lg"
      >
        {loadingDetail || !incidentDetail ? (
          <div className="py-12 flex justify-center">
            <Spinner size="md" />
          </div>
        ) : (
          <div className="space-y-5">
            {/* Top header banner */}
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-white/5">
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <SeverityBadge severity={incidentDetail.severity} />
                  <span className="text-xs font-mono text-slate-500">ID: {incidentDetail._id}</span>
                </div>
                <h3 className="text-base font-bold text-slate-100">{incidentDetail.title}</h3>
                <p className="text-xs text-slate-400 mt-1">{incidentDetail.summary || 'No narrative provided.'}</p>
              </div>

              <div className="text-right shrink-0">
                <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">Status</span>
                <span className="text-xs px-2.5 py-1 rounded-full font-medium bg-surface-800 border border-white/10 text-slate-300">
                  {incidentDetail.status.toUpperCase()}
                </span>
              </div>
            </div>

            {/* Attack Taken Down Notification Banner */}
            {(incidentDetail.status === 'resolved' || incidentDetail.status === 'closed') && (
              <div className="p-3.5 rounded-xl bg-emerald-950/50 border border-emerald-500/60 flex items-start gap-3 text-emerald-300 shadow-md shadow-emerald-950/40">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-emerald-300 tracking-wide uppercase">
                      ATTACK TAKEN DOWN · SOAR COUNTERMEASURE ENFORCED
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-900/70 text-emerald-200 border border-emerald-500/40 font-bold">
                      RESOLVED
                    </span>
                  </div>
                  <p className="text-xs text-emerald-200/90 leading-relaxed font-sans mt-1">
                    {incidentDetail.notes?.includes('Attack taken down')
                      ? incidentDetail.notes.split('\n').filter(l => l.includes('Attack taken down')).pop()
                      : 'Adversary intrusion vector was neutralized and contained by autonomous SOAR response. Malicious processes terminated and constituent threats dismissed.'}
                  </p>
                </div>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {incidentDetail.mitreTechniques?.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1.5">
                  Observed MITRE Techniques
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {incidentDetail.mitreTechniques.map((tech) => (
                    <span
                      key={tech}
                      className="text-xs font-mono px-2.5 py-1 rounded-lg bg-surface-800/80 border border-white/10 text-accent-400"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Correlated Threat Timeline */}
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-3">
                Forensic Event Timeline ({incidentDetail.threats?.length || 0} findings)
              </p>
              <IncidentTimeline threats={incidentDetail.threats} />
            </div>

            {/* Analyst Notes */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                  Analyst Notes & Containment Log
                </label>
                <button
                  onClick={handleSaveNotes}
                  disabled={savingNotes}
                  className="btn-ghost text-xs px-2.5 py-1 flex items-center gap-1 text-accent-400 hover:text-accent-300"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{savingNotes ? 'Saving...' : 'Save Notes'}</span>
                </button>
              </div>
              <textarea
                value={notesInput}
                onChange={(e) => setNotesInput(e.target.value)}
                placeholder="Document root cause, containment steps taken, compromised hosts isolated..."
                className="input w-full text-xs h-24 resize-none leading-relaxed"
              />
            </div>

            {/* Dual-Sync Action Toolbar */}
            <div className="pt-4 border-t border-white/5 flex flex-wrap items-center justify-between gap-3">
              <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span>
                  Auto-Sync Active: Actions apply to both Incident & {incidentDetail.threats?.length || 0} constituent threats
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {incidentDetail.status !== 'investigating' && incidentDetail.status !== 'resolved' && incidentDetail.status !== 'closed' && (
                  <button
                    onClick={() => handleStatusChange(incidentDetail._id, 'investigating')}
                    className="text-xs px-3 py-1.5 rounded-lg font-medium bg-blue-500/15 hover:bg-blue-500/25 text-blue-300 border border-blue-500/30 flex items-center gap-1.5 transition-all"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Investigate & Ack Threats</span>
                  </button>
                )}

                {incidentDetail.status !== 'resolved' && incidentDetail.status !== 'closed' && (
                  <button
                    onClick={() => handleStatusChange(incidentDetail._id, 'resolved')}
                    className="text-xs px-3 py-1.5 rounded-lg font-medium bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 flex items-center gap-1.5 transition-all"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Resolve & Dismiss Threats</span>
                  </button>
                )}

                {incidentDetail.status === 'resolved' || incidentDetail.status === 'closed' ? (
                  <button
                    onClick={() => handleStatusChange(incidentDetail._id, 'open')}
                    className="text-xs px-3 py-1.5 rounded-lg font-medium bg-slate-700/40 hover:bg-slate-700/60 text-slate-300 border border-slate-600/40 flex items-center gap-1.5 transition-all"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reopen Incident</span>
                  </button>
                ) : null}

                <button
                  onClick={() => setDeleteConfirm(incidentDetail)}
                  className="text-xs px-3 py-1.5 rounded-lg font-medium bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 flex items-center gap-1.5 transition-all"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete Incident</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Manual Create Incident Modal */}
      <Modal isOpen={isCreateOpen} onClose={() => setIsCreateOpen(false)} title="Create New Security Incident">
        <form onSubmit={handleCreateIncident} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Incident Title</label>
            <input
              type="text"
              required
              placeholder="e.g. Distributed SSH Brute Force Campaign"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="input w-full text-xs"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Severity Rating</label>
            <select
              value={newSeverity}
              onChange={(e) => setNewSeverity(e.target.value)}
              className="input w-full text-xs bg-surface-900 cursor-pointer"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Executive Summary / Context</label>
            <textarea
              placeholder="Brief description of the observed threat pattern and suspected adversary intent..."
              value={newSummary}
              onChange={(e) => setNewSummary(e.target.value)}
              className="input w-full text-xs h-24 resize-none"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-3 border-t border-white/5">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="btn-ghost text-xs px-4"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creating || !newTitle.trim()}
              className="btn-primary text-xs px-4"
            >
              {creating ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Incident Confirmation Modal */}
      <Modal
        isOpen={!!deleteConfirm}
        onClose={() => !deleting && setDeleteConfirm(null)}
        title="Confirm Incident & Threats Deletion"
        size="sm"
      >
        <div className="space-y-4">
          <div className="flex items-start gap-3 p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs leading-relaxed">
              <p className="font-semibold text-red-200 mb-1">Permanent Removal</p>
              <p>
                Are you sure you want to permanently delete incident{' '}
                <strong className="text-white">"{deleteConfirm?.title}"</strong> and all its{' '}
                <strong>{deleteConfirm?.threatIds?.length || deleteConfirm?.threats?.length || 0}</strong> correlated constituent threats?
              </p>
              <p className="mt-1 text-slate-400">
                This will automatically remove both the incident and its threat findings from the database so you don't need to perform the operation separately on both.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setDeleteConfirm(null)}
              disabled={deleting}
              className="btn-ghost text-xs px-3 py-1.5"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={executeDeleteIncident}
              disabled={deleting}
              className="btn-danger text-xs px-3 py-1.5 flex items-center gap-1.5"
            >
              {deleting ? <Spinner size="sm" /> : <Trash2 className="w-3.5 h-3.5" />}
              <span>{deleting ? 'Deleting...' : 'Delete Both'}</span>
            </button>
          </div>
        </div>
      </Modal>
    </PageWrapper>
  );
}
