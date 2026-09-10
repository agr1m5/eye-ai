/**
 * ThreatsPage — Live and recorded security threat findings.
 *
 * Supports:
 *   - Severity filters (All, Critical, High, Medium, Low)
 *   - Live updates via Socket.IO ('finding:new')
 *   - Paginated browsing
 *   - Quick acknowledge / dismiss actions
 *   - Slide-over detail drawer with raw payload inspection
 */
import { useState, useEffect, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import ThreatRow from '@/components/threats/ThreatRow';
import ThreatDetailDrawer from '@/components/threats/ThreatDetailDrawer';
import EmptyState from '@/components/common/EmptyState';
import Pagination from '@/components/common/Pagination';
import Spinner from '@/components/common/Spinner';
import { threatApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';
import { Skull, Filter, RefreshCw } from 'lucide-react';
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
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });

  const fetchThreats = useCallback(async (page = 1, severity = severityFilter, isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const params = { page, limit: 20 };
      if (severity) params.severity = severity;

      const { data } = await threatApi.list(params);
      if (data.status === 'success') {
        setThreats(data.data.threats || []);
        setPagination(data.data.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
      }
    } catch (err) {
      toast.error('Failed to load threats');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [severityFilter]);

  useEffect(() => {
    fetchThreats(1, severityFilter);
  }, [severityFilter, fetchThreats]);

  // Listen for real-time live threat emissions from agent
  useEffect(() => {
    const unsubscribe = subscribe('finding:new', (newThreat) => {
      // If current filter matches or is 'All', prepend to top
      if (!severityFilter || newThreat.severity === severityFilter) {
        setThreats((prev) => [newThreat, ...prev.slice(0, 19)]);
        setPagination((prev) => ({ ...prev, total: prev.total + 1 }));
      }
    });
    return () => unsubscribe();
  }, [subscribe, severityFilter]);

  const handleDismiss = async (id) => {
    try {
      await threatApi.dismiss(id);
      setThreats((prev) => prev.map((t) => (t._id === id ? { ...t, status: 'dismissed' } : t)));
      if (selectedThreat?._id === id) {
        setSelectedThreat((prev) => (prev ? { ...prev, status: 'dismissed' } : null));
      }
      toast.success('Threat dismissed');
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
    } catch (err) {
      toast.error('Failed to acknowledge threat');
    }
  };

  return (
    <PageWrapper
      title="Threat Findings"
      subtitle="Security events detected by the live agent and imported logs"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchThreats(pagination.page, severityFilter, true)}
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
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-1.5 bg-surface-800/60 p-1 rounded-xl border border-white/5">
          <Filter className="w-3.5 h-3.5 text-slate-500 ml-2" />
          {SEVERITY_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setSeverityFilter(f.value)}
              className={`text-xs px-3 py-1 rounded-lg font-medium transition-colors ${
                severityFilter === f.value
                  ? 'bg-accent-400/20 text-accent-300 border border-accent-400/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <span className="text-xs text-slate-500">
          Showing {threats.length} of {pagination.total} threats
        </span>
      </div>

      {/* Threats Table Card */}
      <div className="glass-card glow-border overflow-hidden rounded-xl">
        {/* Table Header */}
        <div className="grid grid-cols-12 px-4 py-3 border-b border-white/5 text-[10px] font-semibold uppercase tracking-widest text-slate-500 bg-surface-800/40">
          <span className="col-span-2">Severity</span>
          <span className="col-span-3">Type</span>
          <span className="col-span-2">Source</span>
          <span className="col-span-2">Detected</span>
          <span className="col-span-1">Status</span>
          <span className="col-span-2 text-right">Actions</span>
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
              severityFilter
                ? `No threats found matching severity: ${severityFilter}.`
                : 'Threat findings will appear here once the local agent reports suspicious telemetry or a log file is imported.'
            }
          />
        ) : (
          <div className="divide-y divide-white/5">
            {threats.map((threat) => (
              <ThreatRow
                key={threat._id}
                threat={threat}
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
        onPageChange={(p) => fetchThreats(p, severityFilter)}
      />

      {/* Detail Slideover Drawer */}
      <ThreatDetailDrawer
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onDismiss={handleDismiss}
        onAck={handleAck}
      />
    </PageWrapper>
  );
}
