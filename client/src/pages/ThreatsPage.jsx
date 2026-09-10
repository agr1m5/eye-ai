/**
 * ThreatsPage — Live and recorded security threat findings.
 *
 * Supports:
 *   - Severity filters (All, Critical, High, Medium, Low)
 *   - Threat Type filter with dynamic aggregated counts
 *   - Bulk operations by Threat Type: Acknowledge All, Close / Dismiss All, Delete All
 *   - Multi-select row selection for custom bulk actions
 *   - Live updates via Socket.IO ('finding:new')
 *   - Paginated browsing
 *   - Quick individual acknowledge / dismiss actions
 *   - Slide-over detail drawer with raw payload inspection & MITRE mapping
 *   - Safe confirmation modal for irreversible deletion operations
 */
import { useState, useEffect, useCallback, useMemo } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import ThreatRow from '@/components/threats/ThreatRow';
import ThreatDetailDrawer from '@/components/threats/ThreatDetailDrawer';
import EmptyState from '@/components/common/EmptyState';
import Pagination from '@/components/common/Pagination';
import Spinner from '@/components/common/Spinner';
import Modal from '@/components/common/Modal';
import { threatApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';
import { getHumanThreat } from '@/utils/threatFormatter';
import {
  Skull,
  Filter,
  RefreshCw,
  Layers,
  CheckCircle2,
  XCircle,
  Trash2,
  AlertTriangle,
  X,
  CheckSquare,
} from 'lucide-react';
import toast from 'react-hot-toast';

const SEVERITY_FILTERS = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

export default function ThreatsPage() {
  const { subscribe } = useSocket();
  const [threats, setThreats] = useState([]);
  const [availableTypes, setAvailableTypes] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [bulkLoading, setBulkLoading] = useState(false);

  // Filters & selection
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });

  // Confirmation modal state: { type?: string, name?: string, count: number, ids?: string[] } | null
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  // Fetch aggregated threat types with total, new, ack, dismissed counts
  const fetchThreatTypes = useCallback(async () => {
    try {
      const { data } = await threatApi.types();
      if (data?.status === 'success') {
        setAvailableTypes(data.data || []);
      }
    } catch (err) {
      console.error('Failed to load threat types:', err);
    }
  }, []);

  // Fetch paginated threats with severity and type filtering
  const fetchThreats = useCallback(
    async (page = 1, severity = severityFilter, type = typeFilter, isManual = false) => {
      if (isManual) setRefreshing(true);
      else setLoading(true);

      try {
        const params = { page, limit: 20 };
        if (severity) params.severity = severity;
        if (type) params.type = type;

        const { data } = await threatApi.list(params);
        if (data?.status === 'success') {
          setThreats(data.data.threats || []);
          setPagination(data.data.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
        }
      } catch (err) {
        toast.error('Failed to load threats');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [severityFilter, typeFilter]
  );

  // Initial load and filter change trigger
  useEffect(() => {
    fetchThreats(1, severityFilter, typeFilter);
    fetchThreatTypes();
  }, [severityFilter, typeFilter, fetchThreats, fetchThreatTypes]);

  // Real-time live threat emissions from agent
  useEffect(() => {
    const unsubscribe = subscribe('finding:new', (newThreat) => {
      // Check if new threat matches currently applied filters
      const matchSeverity = !severityFilter || newThreat.severity === severityFilter;
      const matchType = !typeFilter || newThreat.type === typeFilter;

      if (matchSeverity && matchType) {
        setThreats((prev) => [newThreat, ...prev.slice(0, 19)]);
        setPagination((prev) => ({ ...prev, total: prev.total + 1 }));
      }
      fetchThreatTypes();
    });
    return () => unsubscribe();
  }, [subscribe, severityFilter, typeFilter, fetchThreatTypes]);

  // Current active type statistics
  const activeTypeStat = useMemo(() => {
    if (!typeFilter) return null;
    return availableTypes.find((t) => t.type === typeFilter) || null;
  }, [availableTypes, typeFilter]);

  // Overall total count across all types
  const totalAllTypes = useMemo(() => {
    return availableTypes.reduce((acc, curr) => acc + curr.total, 0);
  }, [availableTypes]);

  /* ── Selection handlers ─────────────────────────────────────── */
  const isAllPageSelected = threats.length > 0 && threats.every((t) => selectedIds.includes(t._id));

  const handleToggleSelectAll = () => {
    if (isAllPageSelected) {
      // Deselect all on current page
      const pageIds = new Set(threats.map((t) => t._id));
      setSelectedIds((prev) => prev.filter((id) => !pageIds.has(id)));
    } else {
      // Select all on current page
      const newIds = new Set([...selectedIds, ...threats.map((t) => t._id)]);
      setSelectedIds(Array.from(newIds));
    }
  };

  const handleToggleRow = (id) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  /* ── Individual Threat Actions ─────────────────────────────── */
  const handleDismiss = async (id) => {
    try {
      await threatApi.dismiss(id);
      setThreats((prev) => prev.map((t) => (t._id === id ? { ...t, status: 'dismissed' } : t)));
      if (selectedThreat?._id === id) {
        setSelectedThreat((prev) => (prev ? { ...prev, status: 'dismissed' } : null));
      }
      toast.success('Threat dismissed');
      fetchThreatTypes();
    } catch (err) {
      toast.error('Failed to dismiss threat');
    }
  };

  const handleAck = async (id) => {
    try {
      await threatApi.updateStatus(id, 'acknowledged');
      setThreats((prev) => prev.map((t) => (t._id === id ? { ...t, status: 'acknowledged' } : t)));
      if (selectedThreat?._id === id) {
        setSelectedThreat((prev) => (prev ? { ...prev, status: 'acknowledged' } : null));
      }
      toast.success('Threat acknowledged');
      fetchThreatTypes();
    } catch (err) {
      toast.error('Failed to acknowledge threat');
    }
  };

  /* ── Bulk Status Handler (by Type or by selected IDs) ───────── */
  const handleBulkStatus = async ({ type, ids, status }) => {
    setBulkLoading(true);
    try {
      const payload = { status };
      if (type) payload.type = type;
      if (ids && ids.length > 0) payload.ids = ids;

      const { data } = await threatApi.bulkStatus(payload);
      const count = data?.data?.modifiedCount ?? 'all';
      const label = status === 'acknowledged' ? 'acknowledged' : 'closed / dismissed';

      toast.success(`Successfully ${label} ${count} threat(s)`);

      // Refresh list, types, and clear selection
      setSelectedIds([]);
      await Promise.all([
        fetchThreats(pagination.page, severityFilter, typeFilter),
        fetchThreatTypes(),
      ]);

      if (selectedThreat) {
        if (type && selectedThreat.type === type) {
          setSelectedThreat((prev) => (prev ? { ...prev, status } : null));
        } else if (ids && ids.includes(selectedThreat._id)) {
          setSelectedThreat((prev) => (prev ? { ...prev, status } : null));
        }
      }
    } catch (err) {
      toast.error(err.response?.data?.message || 'Bulk status update failed');
    } finally {
      setBulkLoading(false);
    }
  };

  /* ── Bulk Delete Handler ────────────────────────────────────── */
  const executeBulkDelete = async () => {
    if (!deleteConfirm) return;
    setBulkLoading(true);

    try {
      const payload = {};
      if (deleteConfirm.type) payload.type = deleteConfirm.type;
      if (deleteConfirm.ids) payload.ids = deleteConfirm.ids;

      const { data } = await threatApi.bulkDelete(payload);
      const count = data?.data?.deletedCount ?? deleteConfirm.count;

      toast.success(`Permanently deleted ${count} threat(s)`);

      setDeleteConfirm(null);
      setSelectedIds([]);

      // If we deleted all threats of current filter, refresh
      await Promise.all([
        fetchThreats(1, severityFilter, typeFilter),
        fetchThreatTypes(),
      ]);

      if (selectedThreat) {
        if (deleteConfirm.type && selectedThreat.type === deleteConfirm.type) {
          setSelectedThreat(null);
        } else if (deleteConfirm.ids && deleteConfirm.ids.includes(selectedThreat._id)) {
          setSelectedThreat(null);
        }
      }
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to delete threats');
    } finally {
      setBulkLoading(false);
    }
  };

  return (
    <PageWrapper
      title="Threat Findings"
      subtitle="Security events detected by the live agent, honeypots, and imported logs"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchThreats(pagination.page, severityFilter, typeFilter, true);
              fetchThreatTypes();
            }}
            disabled={refreshing || loading}
            className="btn-ghost text-xs px-2.5 py-1.5 flex items-center gap-1.5"
            title="Refresh threats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      }
    >
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Filters */}
          <div className="flex items-center gap-1 bg-surface-800/60 p-1 rounded-xl border border-white/5">
            <Filter className="w-3.5 h-3.5 text-slate-500 ml-2 mr-1" />
            {SEVERITY_FILTERS.map((f) => (
              <button
                key={f.value}
                onClick={() => {
                  setSeverityFilter(f.value);
                  setSelectedIds([]);
                }}
                className={`text-xs px-2.5 py-1 rounded-lg font-medium transition-colors ${
                  severityFilter === f.value
                    ? 'bg-accent-400/20 text-accent-300 border border-accent-400/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Threat Type Filter Dropdown */}
          <div className="flex items-center gap-1.5 bg-surface-800/60 px-2.5 py-1 rounded-xl border border-white/5">
            <Layers className="w-3.5 h-3.5 text-brand-400 shrink-0" />
            <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setSelectedIds([]);
              }}
              className="bg-transparent border-0 text-xs font-medium text-slate-200 focus:ring-0 focus:outline-none cursor-pointer py-1 pr-3"
            >
              <option value="" className="bg-surface-900 text-slate-200">
                All Types ({totalAllTypes || pagination.total})
              </option>
              {availableTypes.map((t) => {
                const info = getHumanThreat(t.type);
                return (
                  <option key={t.type} value={t.type} className="bg-surface-900 text-slate-200">
                    {info.title} ({t.total})
                  </option>
                );
              })}
            </select>
          </div>
        </div>

        <span className="text-xs text-slate-500">
          Showing {threats.length} of {pagination.total} threats
        </span>
      </div>

      {/* ── Threat Type Bulk Actions Banner (When Type Filter is Active) ── */}
      {typeFilter && (
        <div className="mb-4 p-3.5 rounded-xl bg-gradient-to-r from-brand-950/40 via-surface-900/60 to-surface-900/40 border border-brand-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-lg shadow-brand-500/5 animate-fadeIn">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-brand-500/20 text-brand-400 shrink-0">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold text-white">
                  {getHumanThreat(typeFilter)?.title || typeFilter}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400">
                  {typeFilter}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                <strong>{activeTypeStat?.total ?? pagination.total}</strong> total in database •{' '}
                <span className="text-cyan-400 font-medium">{activeTypeStat?.newCount ?? 0} new</span> •{' '}
                <span className="text-amber-400 font-medium">{activeTypeStat?.ackCount ?? 0} acknowledged</span> •{' '}
                <span className="text-slate-400 font-medium">{activeTypeStat?.dismissedCount ?? 0} closed</span>
              </p>
            </div>
          </div>

          {/* Bulk Action Buttons for this Type */}
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            {/* Acknowledge All */}
            <button
              onClick={() => handleBulkStatus({ type: typeFilter, status: 'acknowledged' })}
              disabled={bulkLoading}
              className="text-xs px-3 py-1.5 rounded-lg font-medium bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 flex items-center gap-1.5 transition-all disabled:opacity-50"
              title={`Acknowledge all threats of type "${typeFilter}"`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
              <span>Acknowledge All</span>
            </button>

            {/* Close / Dismiss All */}
            <button
              onClick={() => handleBulkStatus({ type: typeFilter, status: 'dismissed' })}
              disabled={bulkLoading}
              className="text-xs px-3 py-1.5 rounded-lg font-medium bg-slate-700/40 hover:bg-slate-700/60 text-slate-300 border border-slate-600/40 flex items-center gap-1.5 transition-all disabled:opacity-50"
              title={`Close and dismiss all threats of type "${typeFilter}"`}
            >
              <XCircle className="w-3.5 h-3.5 text-slate-400" />
              <span>Close All</span>
            </button>

            {/* Delete All */}
            <button
              onClick={() =>
                setDeleteConfirm({
                  type: typeFilter,
                  name: getHumanThreat(typeFilter)?.title || typeFilter,
                  count: activeTypeStat?.total || pagination.total,
                })
              }
              disabled={bulkLoading}
              className="text-xs px-3 py-1.5 rounded-lg font-medium bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 flex items-center gap-1.5 transition-all disabled:opacity-50"
              title={`Permanently delete all threats of type "${typeFilter}"`}
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
              <span>Delete All</span>
            </button>

            {/* Clear Filter */}
            <button
              onClick={() => {
                setTypeFilter('');
                setSelectedIds([]);
              }}
              className="text-xs px-2 py-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors ml-auto md:ml-0"
              title="Clear type filter"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* ── Multi-Select Batch Actions Bar (When checkboxes are checked) ── */}
      {selectedIds.length > 0 && (
        <div className="mb-4 p-2.5 px-4 rounded-xl bg-accent-500/10 border border-accent-500/30 flex flex-wrap items-center justify-between gap-3 animate-fadeIn">
          <div className="flex items-center gap-2">
            <CheckSquare className="w-4 h-4 text-accent-400" />
            <span className="text-xs font-semibold text-accent-200">
              {selectedIds.length} threat{selectedIds.length > 1 ? 's' : ''} selected
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleBulkStatus({ ids: selectedIds, status: 'acknowledged' })}
              disabled={bulkLoading}
              className="text-xs px-2.5 py-1 rounded-lg font-medium bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 flex items-center gap-1 transition-all disabled:opacity-50"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
              <span>Acknowledge Selected</span>
            </button>

            <button
              onClick={() => handleBulkStatus({ ids: selectedIds, status: 'dismissed' })}
              disabled={bulkLoading}
              className="text-xs px-2.5 py-1 rounded-lg font-medium bg-slate-700/40 hover:bg-slate-700/60 text-slate-300 border border-slate-600/40 flex items-center gap-1 transition-all disabled:opacity-50"
            >
              <XCircle className="w-3.5 h-3.5 text-slate-400" />
              <span>Close Selected</span>
            </button>

            <button
              onClick={() =>
                setDeleteConfirm({
                  ids: selectedIds,
                  count: selectedIds.length,
                })
              }
              disabled={bulkLoading}
              className="text-xs px-2.5 py-1 rounded-lg font-medium bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 flex items-center gap-1 transition-all disabled:opacity-50"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
              <span>Delete Selected</span>
            </button>

            <button
              onClick={() => setSelectedIds([])}
              className="text-xs px-2 py-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            >
              Deselect All
            </button>
          </div>
        </div>
      )}

      {/* Threats Table Card */}
      <div className="glass-card glow-border overflow-hidden rounded-xl">
        {/* Table Header */}
        <div className="grid grid-cols-12 px-4 py-3 border-b border-white/5 text-[10px] font-semibold uppercase tracking-widest text-slate-500 bg-surface-800/40 items-center">
          <div className="col-span-1 flex items-center" onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={isAllPageSelected}
              onChange={handleToggleSelectAll}
              aria-label="Select all threats on page"
              className="w-4 h-4 rounded border-slate-700 bg-surface-900 text-brand-500 focus:ring-brand-500/20 cursor-pointer"
            />
          </div>
          <span className="col-span-2">Severity</span>
          <span className="col-span-3">Type</span>
          <span className="col-span-2">Source</span>
          <span className="col-span-2">Detected</span>
          <span className="col-span-1">Status</span>
          <span className="col-span-1 text-right">Actions</span>
        </div>

        {/* Content */}
        {loading ? (
          <div className="py-20 flex justify-center">
            <Spinner size="lg" />
          </div>
        ) : threats.length === 0 ? (
          <EmptyState
            icon={Skull}
            title="No threats detected"
            message={
              typeFilter || severityFilter
                ? `No threats found matching the current filters (${[
                    severityFilter ? `Severity: ${severityFilter}` : null,
                    typeFilter ? `Type: ${typeFilter}` : null,
                  ]
                    .filter(Boolean)
                    .join(', ')}).`
                : 'Threat findings will appear here once the local agent reports suspicious telemetry or a log file is imported.'
            }
          />
        ) : (
          <div className="divide-y divide-white/5">
            {threats.map((threat) => (
              <ThreatRow
                key={threat._id}
                threat={threat}
                isSelected={selectedIds.includes(threat._id)}
                onToggleSelect={handleToggleRow}
                onFilterType={(t) => {
                  setTypeFilter(t);
                  setSelectedIds([]);
                }}
                onSelect={setSelectedThreat}
                onDismiss={handleDismiss}
                onAck={handleAck}
              />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      <Pagination
        page={pagination.page}
        totalPages={pagination.totalPages}
        onPageChange={(p) => fetchThreats(p, severityFilter, typeFilter)}
      />

      {/* Detail Slideover Drawer */}
      <ThreatDetailDrawer
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onDismiss={handleDismiss}
        onAck={handleAck}
        onFilterType={(t) => {
          setTypeFilter(t);
          setSelectedIds([]);
          setSelectedThreat(null);
        }}
      />

      {/* ── Permanent Deletion Confirmation Modal ── */}
      <Modal
        isOpen={!!deleteConfirm}
        onClose={() => !bulkLoading && setDeleteConfirm(null)}
        title="Confirm Permanent Deletion"
        size="sm"
      >
        <div className="space-y-4">
          <div className="flex items-start gap-3 p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs leading-relaxed">
              <p className="font-semibold text-red-200 mb-1">Irreversible Security Log Removal</p>
              {deleteConfirm?.type ? (
                <p>
                  Are you sure you want to permanently delete all{' '}
                  <strong>{deleteConfirm.count}</strong> threat(s) of type{' '}
                  <span className="font-mono text-red-300 font-semibold">{deleteConfirm.name}</span>?
                </p>
              ) : (
                <p>
                  Are you sure you want to permanently delete the{' '}
                  <strong>{deleteConfirm?.count || selectedIds.length}</strong> selected threat(s)?
                </p>
              )}
              <p className="mt-1 text-slate-400">
                These records and raw forensic telemetry dumps will be completely removed from the database and cannot be recovered.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setDeleteConfirm(null)}
              disabled={bulkLoading}
              className="btn-ghost text-xs px-3 py-1.5"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={executeBulkDelete}
              disabled={bulkLoading}
              className="btn-danger text-xs px-3 py-1.5 flex items-center gap-1.5"
            >
              {bulkLoading ? <Spinner size="sm" /> : <Trash2 className="w-3.5 h-3.5" />}
              <span>{bulkLoading ? 'Deleting...' : 'Confirm Delete'}</span>
            </button>
          </div>
        </div>
      </Modal>
    </PageWrapper>
  );
}
