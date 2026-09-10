/**
 * ActivityPage.jsx — Continuous Host & User Activity Monitor
 *
 * Provides full, real-time observability into all endpoint activity:
 *  - Every process spawned, executed, and stopped
 *  - Every network socket opened, connected, and closed
 *  - Every system authentication & shell log event
 *  - Live streaming via Socket.IO with pause/resume and deep inspection
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Activity,
  Play,
  Pause,
  RefreshCw,
  Search,
  Filter,
  Cpu,
  Globe,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  User,
  Clock,
  ChevronRight,
  X,
  Trash2,
  ExternalLink,
  Layers,
  Sparkles,
  Copy,
  Check,
  Send,
  Lightbulb,
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';
import toast from 'react-hot-toast';

import PageWrapper from '@/components/layout/PageWrapper';
import { activitiesApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';

export default function ActivityPage() {
  const { subscribe, agentOnline } = useSocket();

  // Data state
  const [activities, setActivities] = useState([]);
  const [stats, setStats] = useState({
    total24h: 0,
    processCount: 0,
    networkCount: 0,
    logCount: 0,
    threatCount: 0,
  });
  const [loading, setLoading] = useState(true);
  const [streaming, setStreaming] = useState(true);

  // Filters
  const [sourceFilter, setSourceFilter] = useState('all');
  const [threatOnly, setThreatOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Selected item for inspection drawer
  const [selectedActivity, setSelectedActivity] = useState(null);
  const [activeDrawerTab, setActiveDrawerTab] = useState('suggestions'); // 'suggestions' | 'details'
  const [suggestions, setSuggestions] = useState(null);
  const [loadingSuggestions, setLoadingSuggestions] = useState(false);
  const [userQuestion, setUserQuestion] = useState('');
  const [askingAi, setAskingAi] = useState(false);
  const [aiAnswers, setAiAnswers] = useState({});
  const [copiedCmd, setCopiedCmd] = useState(null);

  // Buffer ref to avoid closures in socket handler
  const streamingRef = useRef(streaming);
  useEffect(() => {
    streamingRef.current = streaming;
  }, [streaming]);

  // Fetch initial activity data
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [resList, resStats] = await Promise.all([
        activitiesApi.list({
          limit: 100,
          source: sourceFilter === 'all' ? undefined : sourceFilter,
          isThreat: threatOnly ? 'true' : undefined,
          search: searchQuery || undefined,
        }),
        activitiesApi.stats(),
      ]);

      if (resList.data.status === 'success') {
        setActivities(resList.data.data.activities || []);
      }
      if (resStats.data.status === 'success') {
        setStats(resStats.data.data);
      }
    } catch (err) {
      toast.error('Failed to load host activity telemetry');
    } finally {
      setLoading(false);
    }
  }, [sourceFilter, threatOnly, searchQuery]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Real-time Socket.IO ingestion
  useEffect(() => {
    const handleBatch = (batch) => {
      if (!streamingRef.current || !Array.isArray(batch) || batch.length === 0) return;

      setActivities((prev) => {
        // Prepend new activities and maintain max 300 in UI buffer
        const existingIds = new Set(prev.map((a) => a._id));
        const newItems = batch.filter((a) => a && a._id && !existingIds.has(a._id));
        if (newItems.length === 0) return prev;
        return [...newItems, ...prev].slice(0, 300);
      });

      // Update counters locally
      setStats((prev) => ({
        ...prev,
        total24h: prev.total24h + batch.length,
        processCount: prev.processCount + batch.filter((a) => a.source === 'process').length,
        networkCount: prev.networkCount + batch.filter((a) => a.source === 'network').length,
        logCount: prev.logCount + batch.filter((a) => a.source === 'log').length,
        threatCount: prev.threatCount + batch.filter((a) => a.isThreat).length,
      }));
    };

    const unsubscribe = subscribe('activity:batch', handleBatch);
    return () => unsubscribe();
  }, [subscribe]);

  // Clear activities handler
  const handleClear = async () => {
    if (!window.confirm('Are you sure you want to clear host activity history?')) return;
    try {
      await activitiesApi.clear();
      setActivities([]);
      toast.success('Activity log cleared');
      fetchData();
    } catch {
      toast.error('Failed to clear activities');
    }
  };

  // Fetch AI suggestions whenever an activity is selected
  useEffect(() => {
    if (!selectedActivity) {
      setSuggestions(null);
      setUserQuestion('');
      return;
    }

    let isMounted = true;
    const loadSuggestions = async () => {
      try {
        setLoadingSuggestions(true);
        const res = await activitiesApi.suggestions(selectedActivity._id, {
          activity: selectedActivity,
        });
        if (isMounted && res.data.status === 'success') {
          setSuggestions(res.data.data);
        }
      } catch {
        if (isMounted) setSuggestions(null);
      } finally {
        if (isMounted) setLoadingSuggestions(false);
      }
    };

    loadSuggestions();
    return () => {
      isMounted = false;
    };
  }, [selectedActivity]);

  // Ask follow-up question to the AI Assistant
  const handleAskQuestion = async (e) => {
    e?.preventDefault();
    if (!userQuestion.trim() || !selectedActivity || askingAi) return;

    const q = userQuestion.trim();
    setUserQuestion('');
    setAskingAi(true);

    try {
      const res = await activitiesApi.suggestions(selectedActivity._id, {
        activity: selectedActivity,
        question: q,
      });
      if (res.data.status === 'success' && res.data.data.aiAnswer) {
        setAiAnswers((prev) => ({
          ...prev,
          [selectedActivity._id]: [
            ...(prev[selectedActivity._id] || []),
            { question: q, answer: res.data.data.aiAnswer },
          ],
        }));
      }
    } catch {
      toast.error('Failed to get assistant response');
    } finally {
      setAskingAi(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(text);
    toast.success('Command copied to clipboard');
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <PageWrapper title="Host Activity">
      <div className="p-6 space-y-6 max-w-7xl mx-auto">

        {/* ── Page Header ──────────────────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-accent-400/10 border border-accent-400/20">
                <Activity className="w-5 h-5 text-accent-400" />
              </div>
              <h1 className="text-xl font-bold text-slate-100 tracking-tight">Host Activity Monitor</h1>
              {agentOnline && (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Live Streaming
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Real-time audit of every process executed, network connection established, and system event on this endpoint.
            </p>
          </div>

          {/* Stream Controls */}
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setStreaming((prev) => !prev)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
                streaming
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
              }`}
            >
              {streaming ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  Pause Stream
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  Resume Stream
                </>
              )}
            </button>

            <button
              onClick={fetchData}
              title="Refresh telemetry"
              className="p-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-slate-200 border border-white/5 transition-all"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>

            <button
              onClick={handleClear}
              title="Clear activity log"
              className="p-1.5 rounded-lg bg-surface-800 hover:bg-red-500/10 text-slate-400 hover:text-red-400 border border-white/5 transition-all"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Metric Stat Cards ────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3.5">
          <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Total Events (24h)</span>
              <Layers className="w-4 h-4 text-accent-400" />
            </div>
            <div className="text-xl font-bold text-slate-100 mt-2">
              {stats.total24h.toLocaleString()}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Process Events</span>
              <Cpu className="w-4 h-4 text-sky-400" />
            </div>
            <div className="text-xl font-bold text-sky-400 mt-2">
              {stats.processCount.toLocaleString()}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Network Connections</span>
              <Globe className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-xl font-bold text-emerald-400 mt-2">
              {stats.networkCount.toLocaleString()}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>System & Auth Logs</span>
              <Terminal className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-xl font-bold text-purple-400 mt-2">
              {stats.logCount.toLocaleString()}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5">
            <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
              <span>Threat Verdict</span>
              {stats.threatCount > 0 ? (
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              )}
            </div>
            <div className="text-xl font-bold mt-2">
              {stats.threatCount > 0 ? (
                <span className="text-rose-400">{stats.threatCount} Flagged</span>
              ) : (
                <span className="text-emerald-400">100% Safe</span>
              )}
            </div>
          </div>
        </div>

        {/* ── Filters & Search ─────────────────────────────────── */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 p-3 rounded-xl bg-surface-800/50 border border-white/5">
          {/* Source Tabs */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 md:pb-0">
            {[
              { id: 'all', label: 'All Activities' },
              { id: 'process', label: '⚙️ Processes' },
              { id: 'network', label: '🌐 Network' },
              { id: 'log', label: '🔑 System Logs' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSourceFilter(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                  sourceFilter === tab.id
                    ? 'bg-accent-400/20 text-accent-400 border border-accent-400/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search and Threat Toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setThreatOnly((prev) => !prev)}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                threatOnly
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                  : 'bg-surface-800 text-slate-400 border-white/5 hover:text-slate-200'
              }`}
            >
              Flagged Only
            </button>

            <div className="relative flex-1 md:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search commands, PIDs, IPs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-900/80 border border-white/10 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-400/50"
              />
            </div>
          </div>
        </div>

        {/* ── Activity Stream Table ────────────────────────────── */}
        <div className="rounded-xl bg-surface-800/70 border border-white/5 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-white/5 bg-surface-900/50 text-slate-400 font-medium">
                <tr>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Activity Description</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {activities.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                      {loading ? 'Ingesting host activity stream...' : 'No activity recorded matching the current filters.'}
                    </td>
                  </tr>
                ) : (
                  activities.map((act) => (
                    <tr
                      key={act._id}
                      onClick={() => setSelectedActivity(act)}
                      className="hover:bg-white/[0.02] cursor-pointer transition-colors group"
                    >
                      {/* Status / Verdict */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        {act.isThreat ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            <AlertTriangle className="w-3 h-3" />
                            {act.severity.toUpperCase()}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400/90 border border-emerald-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            SAFE
                          </span>
                        )}
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400" title={format(new Date(act.timestamp || act.createdAt), 'PPpp')}>
                        {formatDistanceToNow(new Date(act.timestamp || act.createdAt), { addSuffix: true })}
                      </td>

                      {/* Source */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-300">
                          {act.source === 'process' && <Cpu className="w-3.5 h-3.5 text-sky-400" />}
                          {act.source === 'network' && <Globe className="w-3.5 h-3.5 text-emerald-400" />}
                          {act.source === 'log' && <Terminal className="w-3.5 h-3.5 text-purple-400" />}
                          {act.action}
                        </span>
                      </td>

                      {/* Actor */}
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface-900 border border-white/5 text-[11px]">
                          <User className="w-3 h-3 text-slate-500" />
                          {act.actor || 'system'}
                        </span>
                      </td>

                      {/* Activity Details / Command Line */}
                      <td className="py-3 px-4 max-w-md truncate text-slate-200">
                        <span className="font-mono text-slate-200" title={act.description}>
                          {act.description}
                        </span>
                      </td>

                      {/* Action Chevron & Suggestions Button */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedActivity(act);
                              setActiveDrawerTab('suggestions');
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-accent-400/10 hover:bg-accent-400/20 text-accent-400 border border-accent-400/20 text-[11px] font-medium transition-all"
                          >
                            <Sparkles className="w-3 h-3" />
                            Assist
                          </button>
                          <span className="text-slate-500 group-hover:text-slate-300 transition-colors inline-flex items-center">
                            <ChevronRight className="w-4 h-4" />
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* ── Inspection & AI Assistance Drawer ─────────────────── */}
      {selectedActivity && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-xl h-full bg-surface-900 border-l border-white/10 p-6 flex flex-col space-y-4 overflow-y-auto">
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-accent-400/10 border border-accent-400/20">
                  <Sparkles className="w-5 h-5 text-accent-400" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-100">Activity Telemetry & AI Assistance</h2>
                  <p className="text-[11px] text-slate-400">Contextual security guidance & investigation</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedActivity(null)}
                className="p-1.5 rounded-lg bg-surface-800 hover:bg-surface-700 text-slate-400 hover:text-slate-200 transition-all"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-2 border-b border-white/10 pb-2">
              <button
                onClick={() => setActiveDrawerTab('suggestions')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeDrawerTab === 'suggestions'
                    ? 'bg-accent-400/20 text-accent-400 border border-accent-400/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                AI Assistance & Suggestions
              </button>
              <button
                onClick={() => setActiveDrawerTab('details')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeDrawerTab === 'details'
                    ? 'bg-accent-400/20 text-accent-400 border border-accent-400/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                Raw Telemetry & Technical Details
              </button>
            </div>

            {/* ── TAB 1: AI Suggestions & Assistance ─────────── */}
            {activeDrawerTab === 'suggestions' && (
              <div className="space-y-4">
                {/* Safety Assessment Verdict */}
                <div className={`p-4 rounded-xl border ${
                  selectedActivity.isThreat
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                    : suggestions?.safetyVerdict === 'caution'
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider">
                      {selectedActivity.isThreat ? (
                        <>
                          <AlertTriangle className="w-4 h-4 text-rose-400" />
                          Security Threat Alert ({selectedActivity.severity.toUpperCase()})
                        </>
                      ) : suggestions?.safetyVerdict === 'caution' ? (
                        <>
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          {suggestions?.badgeText || 'Caution / Inspect'}
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-4 h-4 text-emerald-400" />
                          {suggestions?.badgeText || 'Verified Clean Host Activity'}
                        </>
                      )}
                    </div>
                  </div>
                  <p className="text-xs mt-1.5 text-slate-200 leading-relaxed font-medium">
                    {loadingSuggestions ? 'Analyzing activity signature...' : suggestions?.summary || 'Standard system process.'}
                  </p>
                </div>

                {/* Plain-English Explanation */}
                <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                    <Lightbulb className="w-4 h-4 text-amber-400" />
                    What is this activity doing?
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {loadingSuggestions ? 'Consulting Eye SOC assistant...' : suggestions?.explanation || 'Background operating system task.'}
                  </p>
                </div>

                {/* Recommended Defensive Actions */}
                {suggestions?.recommendations && suggestions.recommendations.length > 0 && (
                  <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-2.5">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                      <ShieldCheck className="w-4 h-4 text-accent-400" />
                      Recommended Security Next Steps
                    </div>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {suggestions.recommendations.map((rec, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-accent-400 font-bold mt-0.5">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* 1-Click Remediation Commands */}
                {suggestions?.remediationCommands && suggestions.remediationCommands.length > 0 && (
                  <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-2.5">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                      <Terminal className="w-4 h-4 text-sky-400" />
                      Investigation & Remediation Commands
                    </div>
                    <div className="space-y-2">
                      {suggestions.remediationCommands.map((cmd, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-2.5 rounded-lg bg-surface-950 border border-white/10 font-mono text-xs text-slate-200"
                        >
                          <span className="truncate mr-2">{cmd}</span>
                          <button
                            onClick={() => copyToClipboard(cmd)}
                            className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-slate-200 transition-all shrink-0"
                            title="Copy command"
                          >
                            {copiedCmd === cmd ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Ask AI Copilot Follow-up */}
                <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                    <Sparkles className="w-4 h-4 text-accent-400" />
                    Ask AI Assistant About This Activity
                  </div>

                  {/* Previous Q&A for this activity */}
                  {aiAnswers[selectedActivity._id] && aiAnswers[selectedActivity._id].map((item, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-surface-950 border border-white/5 space-y-1.5 text-xs">
                      <p className="font-semibold text-accent-400">Q: {item.question}</p>
                      <div className="text-slate-300 whitespace-pre-line leading-relaxed">
                        {item.answer}
                      </div>
                    </div>
                  ))}

                  <form onSubmit={handleAskQuestion} className="flex items-center gap-2">
                    <input
                      type="text"
                      placeholder="e.g. Is this process normal? Why is it connecting to this IP?"
                      value={userQuestion}
                      onChange={(e) => setUserQuestion(e.target.value)}
                      disabled={askingAi}
                      className="flex-1 px-3 py-2 rounded-lg bg-surface-950 border border-white/10 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-400"
                    />
                    <button
                      type="submit"
                      disabled={askingAi || !userQuestion.trim()}
                      className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-accent-400/20 hover:bg-accent-400/30 text-accent-400 border border-accent-400/30 text-xs font-semibold disabled:opacity-50 transition-all"
                    >
                      {askingAi ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Send className="w-3.5 h-3.5" />
                      )}
                      Ask
                    </button>
                  </form>
                </div>
              </div>
            )}

            {/* ── TAB 2: Raw Telemetry & Details ──────────────── */}
            {activeDrawerTab === 'details' && (
              <div className="space-y-4">
                {/* Core Fields */}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-surface-800/80 border border-white/5">
                    <span className="text-slate-400 text-[11px] block">Source Category</span>
                    <span className="text-slate-200 font-semibold mt-1 block capitalize">
                      {selectedActivity.source} ({selectedActivity.action})
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-800/80 border border-white/5">
                    <span className="text-slate-400 text-[11px] block">Actor / User</span>
                    <span className="text-slate-200 font-semibold mt-1 block">
                      {selectedActivity.actor || 'system'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-800/80 border border-white/5">
                    <span className="text-slate-400 text-[11px] block">Timestamp</span>
                    <span className="text-slate-200 font-mono mt-1 block">
                      {format(new Date(selectedActivity.timestamp || selectedActivity.createdAt), 'yyyy-MM-dd HH:mm:ss')}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-800/80 border border-white/5">
                    <span className="text-slate-400 text-[11px] block">Remote IP / Socket</span>
                    <span className="text-slate-200 font-mono mt-1 block">
                      {selectedActivity.ip || selectedActivity.entity || 'Local Machine'}
                    </span>
                  </div>
                </div>

                {/* Description / Command Payload */}
                <div>
                  <span className="text-xs font-semibold text-slate-300 mb-2 block">
                    Executed Command or Message
                  </span>
                  <div className="p-3 rounded-lg bg-surface-950 border border-white/10 font-mono text-xs text-slate-200 break-all select-all">
                    {selectedActivity.description}
                  </div>
                </div>

                {/* Raw Metadata JSON */}
                {selectedActivity.metadata && Object.keys(selectedActivity.metadata).length > 0 && (
                  <div>
                    <span className="text-xs font-semibold text-slate-300 mb-2 block">
                      Technical Telemetry Attributes
                    </span>
                    <pre className="p-3 rounded-lg bg-surface-950 border border-white/10 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-56">
                      {JSON.stringify(selectedActivity.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </PageWrapper>
  );
}
