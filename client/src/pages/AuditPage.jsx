/**
 * AuditPage.jsx — Analyst Audit Trail & Compliance Log
 *
 * Displays an immutable chronological record of all analyst decisions,
 * status transitions, agent actions, and settings alterations.
 */
import { useState, useEffect, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import EmptyState from '@/components/common/EmptyState';
import Pagination from '@/components/common/Pagination';
import Spinner from '@/components/common/Spinner';
import { auditApi } from '@/services/api';
import {
  ClipboardList,
  ShieldAlert,
  GitBranch,
  Bot,
  Settings,
  Clock,
  Search,
  RefreshCw,
  User,
  Activity,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { format } from 'date-fns';

const CATEGORY_TABS = [
  { value: '', label: 'All Activities' },
  { value: 'Incident', label: 'Incidents' },
  { value: 'Threat', label: 'Threats' },
  { value: 'Agent', label: 'Agents' },
  { value: 'Settings', label: 'Settings' },
];

function ActionIcon({ action = '' }) {
  if (action.startsWith('incident')) return <GitBranch className="w-3.5 h-3.5 text-purple-400" />;
  if (action.startsWith('threat'))   return <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />;
  if (action.startsWith('agent'))    return <Bot className="w-3.5 h-3.5 text-emerald-400" />;
  if (action.startsWith('settings') || action.startsWith('preferences')) return <Settings className="w-3.5 h-3.5 text-blue-400" />;
  if (action.startsWith('report'))   return <ClipboardList className="w-3.5 h-3.5 text-cyan-400" />;
  if (action.startsWith('analyst') || action.startsWith('auth') || action.startsWith('user')) return <User className="w-3.5 h-3.5 text-amber-400" />;
  return <Activity className="w-3.5 h-3.5 text-slate-400" />;
}

function ActionBadge({ action = '' }) {
  let badgeStyle = 'bg-surface-700/60 text-slate-300 border-surface-600/40';
  if (action.startsWith('incident')) badgeStyle = 'bg-purple-950/60 text-purple-300 border-purple-800/40';
  else if (action.startsWith('threat'))   badgeStyle = 'bg-orange-950/60 text-orange-300 border-orange-800/40';
  else if (action.startsWith('agent'))    badgeStyle = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40';
  else if (action.startsWith('settings') || action.startsWith('preferences')) badgeStyle = 'bg-blue-950/60 text-blue-300 border-blue-800/40';
  else if (action.startsWith('report'))   badgeStyle = 'bg-cyan-950/60 text-cyan-300 border-cyan-800/40';
  else if (action.startsWith('analyst') || action.startsWith('auth') || action.startsWith('user')) badgeStyle = 'bg-amber-950/60 text-amber-300 border-amber-800/40';

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border ${badgeStyle}`}>
      <ActionIcon action={action} />
      <span>{action}</span>
    </span>
  );
}

export default function AuditPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [targetFilter, setTargetFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [pagination, setPagination] = useState({ page: 1, limit: 25, total: 0, totalPages: 1 });
  const [expandedId, setExpandedId] = useState(null);

  const fetchLogs = useCallback(async (page = 1) => {
    try {
      setLoading(true);
      const params = {
        page,
        limit: pagination.limit,
      };
      if (targetFilter) {
        params.category = targetFilter.toLowerCase();
      }

      const res = await auditApi.list(params);
      const data = res.data?.data;
      if (data) {
        setLogs(data.logs || data.entries || []);
        setPagination({
          page:       data.pagination?.page || 1,
          limit:      data.pagination?.limit || 25,
          total:      data.pagination?.total || 0,
          totalPages: data.pagination?.totalPages || 1,
        });
      }
    } catch {
      // handled
    } finally {
      setLoading(false);
    }
  }, [targetFilter, pagination.limit]);

  useEffect(() => {
    fetchLogs(1);
  }, [fetchLogs]);

  // Client-side search query filter
  const filteredLogs = logs.filter((log) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      log.action?.toLowerCase().includes(q) ||
      log.targetType?.toLowerCase().includes(q) ||
      log.userId?.email?.toLowerCase().includes(q) ||
      log.ip?.toLowerCase().includes(q) ||
      JSON.stringify(log.metadata || {}).toLowerCase().includes(q)
    );
  });

  return (
    <PageWrapper
      title="Analyst Audit Trail"
      subtitle="Immutable compliance log of all analyst actions, triage events, and security settings"
    >
      {/* ── Filter Bar ────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        {/* Category Tabs */}
        <div className="flex bg-surface-800/80 rounded-lg p-1 border border-surface-700/60">
          {CATEGORY_TABS.map((tab) => (
            <button
              key={tab.value}
              onClick={() => setTargetFilter(tab.value)}
              className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                targetFilter === tab.value
                  ? 'bg-surface-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search & Refresh */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search actions, IPs, emails..."
              className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-surface-800 border border-surface-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-500 w-48 lg:w-64"
            />
          </div>
          <button
            onClick={() => fetchLogs(pagination.page)}
            className="p-1.5 rounded-lg bg-surface-800 border border-surface-700 text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh Audit Trail"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-accent-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Table Container ───────────────────────────────────── */}
      <div className="glass-card glow-border overflow-hidden">
        {loading && logs.length === 0 ? (
          <div className="p-12 flex justify-center">
            <Spinner size="lg" />
          </div>
        ) : filteredLogs.length === 0 ? (
          <EmptyState
            icon={ClipboardList}
            title="No audit events found"
            message="Analyst actions like incident notes, threat dismissals, agent pairings, and setting changes will appear here automatically."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-800/70 border-b border-surface-700/60 text-slate-400 uppercase tracking-wider font-mono text-[11px]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Target</th>
                  <th className="py-3 px-4">Analyst</th>
                  <th className="py-3 px-4">Origin IP</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-700/40">
                {filteredLogs.map((log) => {
                  const isExpanded = expandedId === log._id;
                  const dateStr = log.createdAt
                    ? format(new Date(log.createdAt), 'MMM dd, HH:mm:ss')
                    : '—';

                  return (
                    <tr
                      key={log._id}
                      className="hover:bg-surface-700/20 transition-colors group cursor-pointer"
                      onClick={() => setExpandedId(isExpanded ? null : log._id)}
                    >
                      {/* Timestamp */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-slate-500" />
                          <span>{dateStr}</span>
                        </div>
                      </td>

                      {/* Action */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <ActionBadge action={log.action} />
                      </td>

                      {/* Target */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                        <span className="font-semibold">{log.targetType || '—'}</span>
                        {log.targetId && (
                          <span className="ml-1.5 font-mono text-[10px] text-slate-500 bg-surface-800 px-1 py-0.5 rounded border border-surface-700">
                            {String(log.targetId).slice(-6)}
                          </span>
                        )}
                      </td>

                      {/* Analyst */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300 font-mono">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3 h-3 text-slate-500" />
                          <span>{log.userId?.email || log.userId?.name || (typeof log.userId === 'string' ? `analyst#${log.userId.slice(-4)}` : 'SOC Analyst')}</span>
                        </div>
                      </td>

                      {/* Origin IP */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                        {log.ip || '127.0.0.1'}
                      </td>

                      {/* Expand Button */}
                      <td className="py-3 px-4 whitespace-nowrap text-right">
                        <button
                          type="button"
                          className="text-slate-500 group-hover:text-slate-300 p-1 rounded"
                        >
                          {isExpanded ? (
                            <ChevronUp className="w-3.5 h-3.5 text-accent-400" />
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Expanded Metadata Accordion Drawer */}
        {expandedId && (
          <div className="p-4 bg-[#050b14] border-t border-surface-700/80 font-mono text-xs text-slate-300">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400 font-medium">Detailed Event Payload:</span>
              <button
                onClick={() => setExpandedId(null)}
                className="text-slate-500 hover:text-slate-300 text-[11px]"
              >
                Close details [x]
              </button>
            </div>
            <pre className="p-3 bg-surface-900 rounded border border-surface-700/60 overflow-x-auto text-[11px] text-accent-300">
              {JSON.stringify(logs.find((l) => l._id === expandedId)?.metadata || {}, null, 2)}
            </pre>
          </div>
        )}

        {/* Pagination Controls */}
        {pagination.totalPages > 1 && (
          <div className="p-3 border-t border-surface-700/50 bg-surface-800/40">
            <Pagination
              currentPage={pagination.page}
              totalPages={pagination.totalPages}
              onPageChange={(p) => fetchLogs(p)}
            />
          </div>
        )}
      </div>
    </PageWrapper>
  );
}
