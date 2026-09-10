/**
 * HuntPage.jsx — Threat Hunt / Global Search Interface.
 *
 * Full-text search across all ingested findings with live filtering by:
 *   - Query string (type, description, source IP, process name, hostname)
 *   - Severity (multi-select chips)
 *   - Date range (preset windows: 1h, 6h, 24h, 7d, or custom)
 *   - Status
 *
 * Results export as CSV (client-side, no server endpoint needed).
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import Spinner from '@/components/common/Spinner';
import SeverityBadge from '@/components/common/SeverityBadge';
import EmptyState from '@/components/common/EmptyState';
import { threatApi } from '@/services/api';
import {
  Search, SlidersHorizontal, Download, ChevronDown, ChevronRight,
  X, Clock, Crosshair, RefreshCw,
} from 'lucide-react';
import { format, subHours, subDays } from 'date-fns';
import toast from 'react-hot-toast';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['', 'new', 'acknowledged', 'dismissed'];

const DATE_PRESETS = [
  { label: 'Last 1h',  getValue: () => subHours(new Date(), 1)  },
  { label: 'Last 6h',  getValue: () => subHours(new Date(), 6)  },
  { label: 'Last 24h', getValue: () => subHours(new Date(), 24) },
  { label: 'Last 7d',  getValue: () => subDays(new Date(), 7)   },
  { label: 'All time', getValue: () => null                     },
];

function ExpandableRow({ threat }) {
  const [open, setOpen] = useState(false);
  const ts = threat.createdAt ? format(new Date(threat.createdAt), 'dd MMM yyyy, HH:mm:ss') : '—';
  const src = threat.source?.ip || threat.source?.processName || threat.source?.hostname || '—';

  return (
    <>
      <tr
        className="border-b border-white/5 hover:bg-white/[0.02] cursor-pointer transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <td className="py-2.5 pl-4 pr-2 w-5">
          {open
            ? <ChevronDown  className="w-3.5 h-3.5 text-slate-500" />
            : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />}
        </td>
        <td className="py-2.5 px-2">
          <SeverityBadge severity={threat.severity} showIcon={false} />
        </td>
        <td className="py-2.5 px-2 text-xs font-semibold text-slate-200 max-w-[180px] truncate">{threat.type}</td>
        <td className="py-2.5 px-2 text-xs font-mono text-accent-400">{src}</td>
        <td className="py-2.5 px-2 text-xs text-slate-400 max-w-xs truncate hidden lg:table-cell">
          {threat.description || '—'}
        </td>
        <td className="py-2.5 px-2 text-[11px] font-mono text-slate-500 whitespace-nowrap">{ts}</td>
        <td className="py-2.5 px-3">
          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium capitalize ${
            threat.status === 'new'          ? 'bg-blue-500/15 text-blue-400' :
            threat.status === 'acknowledged' ? 'bg-amber-500/15 text-amber-400' :
            'bg-slate-500/15 text-slate-400'
          }`}>{threat.status}</span>
        </td>
      </tr>

      {open && (
        <tr className="bg-surface-800/30">
          <td colSpan={7} className="px-6 py-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-8 gap-y-1.5 text-[11px] font-mono">
              {threat._id && <><span className="text-slate-500">Threat ID</span><span className="text-slate-400 truncate">{threat._id}</span></>}
              {threat.source?.ip && <><span className="text-slate-500">Source IP</span><span className="text-accent-400">{threat.source.ip}</span></>}
              {threat.source?.processName && <><span className="text-slate-500">Process</span><span className="text-slate-300">{threat.source.processName}</span></>}
              {threat.source?.pid && <><span className="text-slate-500">PID</span><span className="text-slate-300">{threat.source.pid}</span></>}
              {threat.source?.port && <><span className="text-slate-500">Port</span><span className="text-slate-300">{threat.source.port}</span></>}
              {threat.incidentId && <><span className="text-slate-500">Incident</span><span className="text-orange-400">{threat.incidentId}</span></>}
              {threat.agentSessionId && <><span className="text-slate-500">Session</span><span className="text-slate-400 truncate">{threat.agentSessionId}</span></>}
              {threat.fromImport !== undefined && <><span className="text-slate-500">Source</span><span className="text-slate-300">{threat.fromImport ? 'Log Import' : 'Live Agent'}</span></>}
            </div>
            {threat.description && (
              <p className="text-xs text-slate-300 mt-2 leading-relaxed">{threat.description}</p>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

/** Export results array to CSV and trigger download */
function exportCsv(results) {
  const headers = ['ID', 'Severity', 'Type', 'Source IP', 'Process', 'Description', 'Status', 'Created At'];
  const rows = results.map((t) => [
    t._id,
    t.severity,
    t.type,
    t.source?.ip || '',
    t.source?.processName || '',
    (t.description || '').replace(/"/g, '""'),
    t.status,
    t.createdAt ? format(new Date(t.createdAt), 'yyyy-MM-dd HH:mm:ss') : '',
  ]);

  const csv = [headers, ...rows]
    .map((row) => row.map((cell) => `"${cell}"`).join(','))
    .join('\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href     = url;
  link.download = `threat-hunt-${format(new Date(), 'yyyy-MM-dd_HH-mm')}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

export default function HuntPage() {
  const [query, setQuery]             = useState('');
  const [severities, setSeverities]   = useState([]);
  const [status, setStatus]           = useState('');
  const [datePreset, setDatePreset]   = useState('All time');
  const [results, setResults]         = useState([]);
  const [loading, setLoading]         = useState(false);
  const [total, setTotal]             = useState(0);
  const [page, setPage]               = useState(1);
  const [totalPages, setTotalPages]   = useState(1);
  const [searched, setSearched]       = useState(false);
  const debounceRef = useRef(null);

  const getDateFrom = useCallback(() => {
    const preset = DATE_PRESETS.find((p) => p.label === datePreset);
    const d = preset?.getValue();
    return d ? d.toISOString() : undefined;
  }, [datePreset]);

  const hunt = useCallback(async (pg = 1) => {
    setLoading(true);
    setSearched(true);
    try {
      const params = { limit: 50, page: pg, sort: '-createdAt' };
      if (query.trim())   params.q        = query.trim();
      if (severities.length === 1) params.severity = severities[0];
      if (status)         params.status   = status;
      const df = getDateFrom();
      if (df)             params.dateFrom = df;

      const { data } = await threatApi.list(params);
      if (data.status === 'success') {
        setResults(data.data.threats || []);
        setTotal(data.data.pagination?.total || 0);
        setTotalPages(data.data.pagination?.totalPages || 1);
        setPage(pg);
      }
    } catch (err) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  }, [query, severities, status, getDateFrom]);

  // Debounce query changes
  useEffect(() => {
    if (!searched && !query) return;
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => hunt(1), 400);
    return () => clearTimeout(debounceRef.current);
  }, [query, severities, status, datePreset]); // eslint-disable-line

  const toggleSeverity = (sev) => {
    setSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  const clearAll = () => {
    setQuery('');
    setSeverities([]);
    setStatus('');
    setDatePreset('All time');
    setResults([]);
    setSearched(false);
  };

  const SEV_COLORS = {
    critical: 'border-red-500 bg-red-500/20 text-red-300',
    high:     'border-orange-500 bg-orange-500/20 text-orange-300',
    medium:   'border-yellow-500 bg-yellow-500/20 text-yellow-300',
    low:      'border-blue-500 bg-blue-500/20 text-blue-300',
    info:     'border-slate-500 bg-slate-500/20 text-slate-300',
  };

  return (
    <PageWrapper
      title="Threat Hunt"
      subtitle="Search and investigate across all ingested security findings"
      actions={
        results.length > 0 && (
          <button
            onClick={() => exportCsv(results)}
            className="btn-ghost text-xs px-3 py-1.5 flex items-center gap-1.5 text-accent-400"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        )
      }
    >
      {/* ── Search Controls ─────────────────────────────────────── */}
      <div className="glass-card glow-border p-4 mb-5 space-y-3">
        {/* Search bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && hunt(1)}
            placeholder="Search by type, IP address, process name, description..."
            className="input w-full pl-10 pr-10 text-sm"
            id="hunt-search-input"
          />
          {query && (
            <button className="absolute right-3 top-1/2 -translate-y-1/2" onClick={() => setQuery('')}>
              <X className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
            </button>
          )}
        </div>

        {/* Filter chips row */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1.5">
            <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-[11px] text-slate-500 font-medium">Severity:</span>
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border capitalize transition-all ${
                  severities.includes(sev)
                    ? SEV_COLORS[sev]
                    : 'border-white/10 text-slate-500 hover:border-slate-500'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-[11px] text-slate-500 font-medium">Status:</span>
            {STATUSES.map((s) => (
              <button
                key={s || 'all'}
                onClick={() => setStatus(s)}
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border capitalize transition-all ${
                  status === s
                    ? 'border-accent-400 bg-accent-400/15 text-accent-300'
                    : 'border-white/10 text-slate-500 hover:border-slate-500'
                }`}
              >
                {s || 'All'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            {DATE_PRESETS.map((p) => (
              <button
                key={p.label}
                onClick={() => setDatePreset(p.label)}
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border transition-all ${
                  datePreset === p.label
                    ? 'border-accent-400 bg-accent-400/15 text-accent-300'
                    : 'border-white/10 text-slate-500 hover:border-slate-500'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="ml-auto flex items-center gap-2">
            {(query || severities.length || status || datePreset !== 'All time') && (
              <button onClick={clearAll} className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1">
                <X className="w-3 h-3" /> Clear
              </button>
            )}
            <button
              onClick={() => hunt(1)}
              disabled={loading}
              className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Crosshair className="w-3.5 h-3.5" />}
              Hunt
            </button>
          </div>
        </div>
      </div>

      {/* ── Results ─────────────────────────────────────────────── */}
      {loading ? (
        <div className="py-24 flex justify-center"><Spinner size="lg" /></div>
      ) : !searched ? (
        <EmptyState
          icon={Crosshair}
          title="Start Threat Hunting"
          message="Enter a search term, apply severity filters, or select a time window above and click Hunt to begin investigating."
        />
      ) : results.length === 0 ? (
        <EmptyState
          icon={Search}
          title="No findings match your query"
          message="Try broadening your search — adjust the filters or time window."
        />
      ) : (
        <>
          <div className="flex items-center justify-between mb-2 px-1">
            <p className="text-xs text-slate-500">
              Showing <strong className="text-slate-300">{results.length}</strong> of{' '}
              <strong className="text-slate-300">{total}</strong> findings
            </p>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <button
                disabled={page <= 1}
                onClick={() => hunt(page - 1)}
                className="px-2 py-1 rounded border border-white/10 disabled:opacity-30 hover:border-slate-500 transition"
              >‹</button>
              <span>Page {page} / {totalPages}</span>
              <button
                disabled={page >= totalPages}
                onClick={() => hunt(page + 1)}
                className="px-2 py-1 rounded border border-white/10 disabled:opacity-30 hover:border-slate-500 transition"
              >›</button>
            </div>
          </div>

          <div className="glass-card glow-border overflow-hidden rounded-xl">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/5 bg-surface-900/60">
                  <th className="py-2.5 pl-4 pr-2 w-5" />
                  <th className="py-2.5 px-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Sev</th>
                  <th className="py-2.5 px-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Type</th>
                  <th className="py-2.5 px-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Source</th>
                  <th className="py-2.5 px-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold hidden lg:table-cell">Description</th>
                  <th className="py-2.5 px-2 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Detected At</th>
                  <th className="py-2.5 px-3 text-left text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {results.map((t) => (
                  <ExpandableRow key={t._id} threat={t} />
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </PageWrapper>
  );
}
