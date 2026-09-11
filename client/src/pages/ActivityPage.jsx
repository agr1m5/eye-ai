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
  ShieldOff,
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
  Power,
  Settings,
  Flame,
  Target,
  Lock,
  Unlock,
  ShieldAlert,
  Zap,
  Radio,
  Briefcase,
  Crosshair,
  AlertCircle,
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';

import PageWrapper from '@/components/layout/PageWrapper';
import { activitiesApi, authApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';

function CiaBadge({ label, level, description, icon: Icon }) {
  const lvlLower = (level || 'none').toLowerCase();
  let badgeStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  let barWidth = 'w-1/12';
  let barColor = 'bg-emerald-400';

  if (lvlLower === 'high' || lvlLower === 'critical') {
    badgeStyle = 'bg-rose-500/20 text-rose-300 border-rose-500/40';
    barWidth = 'w-full';
    barColor = 'bg-rose-500';
  } else if (lvlLower === 'medium') {
    badgeStyle = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    barWidth = 'w-2/3';
    barColor = 'bg-amber-500';
  } else if (lvlLower === 'low') {
    badgeStyle = 'bg-sky-500/20 text-sky-300 border-sky-500/40';
    barWidth = 'w-1/3';
    barColor = 'bg-sky-400';
  }

  return (
    <div className="p-3 rounded-xl bg-surface-950/80 border border-white/5 flex flex-col justify-between space-y-2 group hover:border-white/10 transition-all">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-slate-300 text-xs font-semibold">
          <Icon className="w-3.5 h-3.5 text-accent-400" />
          <span>{label}</span>
        </div>
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${badgeStyle}`}>
          {level || 'None'}
        </span>
      </div>
      <div className="w-full bg-surface-800 h-1.5 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${barWidth} ${barColor}`} />
      </div>
      <p className="text-[11px] text-slate-400 leading-snug">
        {description || 'No direct exposure detected.'}
      </p>
    </div>
  );
}

function resolveAttackImpact(activity, suggestions) {
  if (suggestions?.attackImpact) {
    return suggestions.attackImpact;
  }

  if (!activity) {
    return {
      severity: 'NEGLIGIBLE',
      blastRadius: 'Standard POSIX User Space',
      containmentUrgency: 'None',
      mitreTactic: 'Execution (T1204)',
      cia: {
        confidentiality: { level: 'None', description: 'Zero telemetry exposure.' },
        integrity: { level: 'None', description: 'Append-only logs.' },
        availability: { level: 'None', description: 'Nominal host resources.' },
      },
      potentialConsequences: ['Routine OS telemetry.'],
      businessRisk: 'No business impact.',
    };
  }

  const isThreat = activity.isThreat || (activity.severity && activity.severity !== 'none' && activity.severity !== 'low');
  const sev = (activity.severity || (isThreat ? 'high' : 'low')).toUpperCase();
  const source = activity.source;
  const ip = activity.ip;

  if (isThreat) {
    return {
      severity: sev,
      blastRadius: 'Host Subsystem & User Workspace',
      containmentUrgency: 'Immediate Isolation Required',
      mitreTactic: 'Execution (TA0002) / Defense Evasion (TA0005)',
      cia: {
        confidentiality: { level: 'High', description: 'Severe risk of memory scraping, token exfiltration, or sensitive file harvesting.' },
        integrity: { level: 'High', description: 'Potential for arbitrary binary modification, script tampering, or persistent backdoors.' },
        availability: { level: 'Medium', description: 'Risk of host disruption, killed security daemons, or resource starvation.' },
      },
      potentialConsequences: [
        'Arbitrary Code Execution (RCE) bypassing standard endpoint security policies.',
        'Credential scraping and session token hijacking from memory or environment files.',
        'Establishment of persistent reverse shell or unauthorized background worker.',
        'Lateral movement toward connected internal subnet and peer devices.',
      ],
      businessRisk: 'Critical risk of data compromise, compliance breach (SOC2/GDPR), and host downtime.',
    };
  }

  if (source === 'network') {
    const isLocal = !ip || ip.startsWith('127.') || ip === '::1' || ip === 'localhost';
    if (isLocal) {
      return {
        severity: 'NEGLIGIBLE',
        blastRadius: 'Loopback Interface (127.0.0.1)',
        containmentUrgency: 'None / Normal Operation',
        mitreTactic: 'Inter-Process Communication (IPC)',
        cia: {
          confidentiality: { level: 'None', description: 'Traffic does not traverse external network wires; confined to local kernel socket queues.' },
          integrity: { level: 'None', description: 'Standard message delivery between authorized local processes.' },
          availability: { level: 'None', description: 'Negligible socket overhead on host stack.' },
        },
        potentialConsequences: [
          'No external attack surface exposed.',
          'Standard internal system service communication between desktop tools.',
        ],
        businessRisk: 'Zero business impact. Essential for standard developer and OS workflows.',
      };
    }

    const isPrivate = ip && (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip));
    return {
      severity: isPrivate ? 'LOW' : 'MEDIUM',
      blastRadius: isPrivate ? 'Local Area Subnet (LAN)' : 'External Internet Socket',
      containmentUrgency: isPrivate ? 'Periodic Review' : 'Verify Remote Host Identity',
      mitreTactic: 'Command & Control (TA0011) / Exfiltration (TA0010)',
      cia: {
        confidentiality: { level: isPrivate ? 'Low' : 'Medium', description: isPrivate ? 'Confined to internal subnet traffic.' : 'Remote socket communication; ensure TLS encryption.' },
        integrity: { level: 'Low', description: 'Standard client-server protocol validation.' },
        availability: { level: 'None', description: 'Standard egress network bandwidth utilization.' },
      },
      potentialConsequences: [
        isPrivate ? 'Internal subnet resource querying.' : 'Outbound data egress or API communication.',
        'Potential covert channel if initiating binary is unverified.',
      ],
      businessRisk: isPrivate ? 'Low operational risk on authenticated corporate/home subnets.' : 'Risk of unauthorized data transfer if connection target is unverified.',
    };
  }

  return {
    severity: 'LOW',
    blastRadius: 'Local Process Space (POSIX Sandboxed)',
    containmentUrgency: 'Continuous Baseline',
    mitreTactic: 'Discovery (T1082) / User Execution (T1204)',
    cia: {
      confidentiality: { level: 'Low', description: 'Subject to standard user access rights; cannot view other user files.' },
      integrity: { level: 'None', description: 'Cannot alter system-protected roots without root escalation.' },
      availability: { level: 'None', description: 'Standard process CPU and memory utilization.' },
    },
    potentialConsequences: [
      'Standard application runtime execution.',
      'If process binary is compromised, potential unmonitored background activity.',
    ],
    businessRisk: 'Nominal baseline activity. Zero operational interruption.',
  };
}

export default function ActivityPage() {
  const { subscribe, agentOnline } = useSocket();
  const navigate = useNavigate();

  // Consent gate
  const [consentGranted, setConsentGranted] = useState(null); // null = loading
  const [enablingAgent, setEnablingAgent] = useState(false);

  const fetchConsent = useCallback(async () => {
    try {
      const { data } = await authApi.getConsent();
      setConsentGranted(data?.data?.granted !== false); // treat missing file as granted
    } catch {
      setConsentGranted(true); // fail-open (server error shouldn't block the page)
    }
  }, []);

  useEffect(() => {
    fetchConsent();
    // Re-check whenever the user switches back to this tab
    const onFocus = () => fetchConsent();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [fetchConsent]);

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
    const handleSingle = (item) => {
      if (!streamingRef.current || !item || !item._id) return;

      setActivities((prev) => {
        if (prev.some((a) => a._id === item._id)) return prev;
        return [item, ...prev].slice(0, 300);
      });

      setStats((prev) => ({
        ...prev,
        total24h: prev.total24h + 1,
        processCount: prev.processCount + (item.source === 'process' ? 1 : 0),
        networkCount: prev.networkCount + (item.source === 'network' ? 1 : 0),
        logCount: prev.logCount + (item.source === 'log' ? 1 : 0),
        threatCount: prev.threatCount + (item.isThreat ? 1 : 0),
      }));
    };

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

    const unsubSingle = subscribe('activity:single', handleSingle);
    const unsubBatch = subscribe('activity:batch', handleBatch);
    return () => {
      unsubSingle();
      unsubBatch();
    };
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

  const attackImpact = resolveAttackImpact(selectedActivity, suggestions);

  return (
    <PageWrapper title="Host Activity">
      <div className="p-6 space-y-6 max-w-7xl mx-auto">

        {/* ── Consent Gate ─────────────────────────────────────── */}
        {consentGranted === false && (
          <div className="flex flex-col items-center justify-center min-h-[60vh] text-center gap-6">
            <div className="p-5 rounded-2xl bg-red-950/40 border border-red-700/30">
              <ShieldOff className="w-14 h-14 text-red-400 mx-auto" />
            </div>
            <div className="space-y-2 max-w-md">
              <h2 className="text-xl font-bold text-slate-100">Host Monitoring Paused</h2>
              <p className="text-sm text-slate-400 leading-relaxed">
                Device access permission has been <span className="text-red-400 font-semibold">revoked</span>.
                The Eye agent is not collecting process, network, or system log telemetry.
              </p>
              <p className="text-xs text-slate-500 mt-1">
                To resume monitoring, grant device access in Settings.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <button
                onClick={async () => {
                  setEnablingAgent(true);
                  try {
                    await authApi.toggleAgent(true);
                    toast.success('Agent activated & host monitoring resumed');
                    setConsentGranted(true);
                    fetchData();
                  } catch (err) {
                    toast.error(err.response?.data?.message || 'Failed to activate agent');
                  } finally {
                    setEnablingAgent(false);
                  }
                }}
                disabled={enablingAgent}
                className="btn-primary flex items-center gap-2 px-5 py-2.5 text-sm"
              >
                <Power className="w-4 h-4" />
                {enablingAgent ? 'Starting Agent...' : 'Turn On Agent & Resume Monitoring'}
              </button>
              <button
                onClick={() => navigate('/settings')}
                className="btn-secondary flex items-center gap-2 px-4 py-2.5 text-sm"
              >
                <Settings className="w-4 h-4" />
                Settings
              </button>
            </div>
          </div>
        )}

        {/* ── Main content — only shown when consent is granted ── */}
        {consentGranted !== false && (
          <>

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

        {/* ── Host Device Attack Impact & Blast Radius Overview ──── */}
        <div className={`p-4 rounded-xl border transition-all duration-300 ${
          stats.threatCount > 0
            ? 'bg-rose-950/20 border-rose-500/30 shadow-[0_0_20px_rgba(244,63,94,0.12)]'
            : 'bg-surface-800/60 border-white/5'
        }`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/5">
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-lg border ${
                stats.threatCount > 0
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/30 animate-pulse'
                  : 'bg-accent-400/10 text-accent-400 border-accent-400/20'
              }`}>
                <Flame className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  <span>Impact of Attacks on This Device</span>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${
                    stats.threatCount > 0
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                      : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  }`}>
                    {stats.threatCount > 0 ? `${stats.threatCount} THREATS ON HOST` : '0% COMPROMISE · HOST SAFE'}
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400">Continuous endpoint perimeter and CIA triad exposure telemetry on this host</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400 text-[11px]">Active Blast Radius:</span>
              <span className="font-mono text-accent-400 font-semibold px-2 py-0.5 rounded bg-surface-950 border border-white/5 text-[11px]">
                {stats.threatCount > 0 ? 'Elevated to Host Sockets & Workspace' : 'POSIX Process Sandboxed (Nominal)'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3">
            <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-accent-400" />
                <span className="text-slate-300 font-medium">Confidentiality Impact</span>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                stats.threatCount > 0 ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/10 text-emerald-400'
              }`}>
                {stats.threatCount > 0 ? 'At Risk' : 'Protected'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-accent-400" />
                <span className="text-slate-300 font-medium">Integrity Tamper Risk</span>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                stats.threatCount > 0 ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/10 text-emerald-400'
              }`}>
                {stats.threatCount > 0 ? 'Inspect PIDs' : 'Verified'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-accent-400" />
                <span className="text-slate-300 font-medium">Availability / Load</span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded uppercase bg-emerald-500/10 text-emerald-400">
                100% Operational
              </span>
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
                  <th className="py-3 px-4">Device Impact</th>
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
                    <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
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

                      {/* Device Impact */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        {act.isThreat ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                            <Flame className="w-3 h-3 text-rose-400" />
                            CRITICAL
                          </span>
                        ) : act.source === 'network' && act.ip && !act.ip.startsWith('127.') && act.ip !== '::1' && !act.ip.startsWith('10.') && !act.ip.startsWith('192.168.') ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-amber-500/10 text-amber-300 border border-amber-500/20">
                            <Target className="w-3 h-3 text-amber-400" />
                            MEDIUM
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <ShieldCheck className="w-3 h-3 text-emerald-400" />
                            LOW / SAFE
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

        </>
        )}
      </div>

      {/* ── Inspection & AI Assistance Drawer ─────────────────── */}
      {consentGranted !== false && selectedActivity && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-xl h-full bg-surface-900 border-l border-white/10 p-6 flex flex-col space-y-4 overflow-y-auto">
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded-lg border ${
                  selectedActivity.isThreat
                    ? 'bg-rose-500/10 border-rose-500/20 text-rose-400'
                    : 'bg-accent-400/10 border-accent-400/20 text-accent-400'
                }`}>
                  <Sparkles className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-slate-100">Activity Telemetry & AI Assistance</h2>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                      attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                        : attackImpact.severity === 'MEDIUM'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                    }`}>
                      {attackImpact.severity} Impact
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">Contextual security guidance & attack impact analysis</p>
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
                id="tab-suggestions"
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
                id="tab-attack-impact"
                onClick={() => setActiveDrawerTab('impact')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeDrawerTab === 'impact'
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                Impact of Attack
                {attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH' ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping ml-0.5" />
                ) : null}
              </button>
              <button
                id="tab-details"
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

                {/* ── Impact of Attack Section ──────────────────────── */}
                <div className="p-4 rounded-xl bg-gradient-to-br from-surface-800/90 via-surface-800/70 to-surface-900/90 border border-white/10 space-y-3.5 shadow-lg backdrop-blur-sm">
                  <div className="flex items-center justify-between pb-2.5 border-b border-white/5">
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded-lg border ${
                        attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                          : attackImpact.severity === 'MEDIUM'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      }`}>
                        <Flame className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-1.5">
                          Impact of Attack (Blast Radius)
                        </h3>
                        <span className="text-[10px] text-slate-400 font-mono">
                          {attackImpact.mitreTactic || 'T1204: User Execution'}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                        attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                          : attackImpact.severity === 'MEDIUM'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      }`}>
                        {attackImpact.severity} Impact
                      </span>
                      <button
                        onClick={() => setActiveDrawerTab('impact')}
                        className="text-[11px] text-accent-400 hover:text-accent-300 font-medium hover:underline flex items-center gap-0.5"
                      >
                        Deep Dive <ChevronRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>

                  {/* Blast Radius & Containment */}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5">
                      <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                        Host Blast Radius
                      </span>
                      <div className="flex items-center gap-1.5 mt-1 text-slate-200 font-medium text-xs">
                        <Target className="w-3.5 h-3.5 text-accent-400 shrink-0" />
                        <span className="truncate" title={attackImpact.blastRadius}>{attackImpact.blastRadius}</span>
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5">
                      <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                        Containment Urgency
                      </span>
                      <div className="flex items-center gap-1.5 mt-1 text-slate-200 font-medium text-xs">
                        <ShieldAlert className={`w-3.5 h-3.5 shrink-0 ${
                          attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                            ? 'text-rose-400'
                            : attackImpact.severity === 'MEDIUM'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`} />
                        <span className="truncate" title={attackImpact.containmentUrgency}>{attackImpact.containmentUrgency}</span>
                      </div>
                    </div>
                  </div>

                  {/* CIA Triad Matrix */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] font-semibold text-slate-300">
                      <span className="flex items-center gap-1.5">
                        <Lock className="w-3 h-3 text-slate-400" />
                        CIA Triad Exposure Breakdown
                      </span>
                      <span className="text-[10px] text-slate-500 font-normal">Confidentiality • Integrity • Availability</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <CiaBadge
                        label="Confidentiality"
                        level={attackImpact.cia?.confidentiality?.level}
                        description={attackImpact.cia?.confidentiality?.description}
                        icon={Lock}
                      />
                      <CiaBadge
                        label="Integrity"
                        level={attackImpact.cia?.integrity?.level}
                        description={attackImpact.cia?.integrity?.description}
                        icon={ShieldAlert}
                      />
                      <CiaBadge
                        label="Availability"
                        level={attackImpact.cia?.availability?.level}
                        description={attackImpact.cia?.availability?.description}
                        icon={Zap}
                      />
                    </div>
                  </div>

                  {/* Potential Exploitation Consequences */}
                  {attackImpact.potentialConsequences && attackImpact.potentialConsequences.length > 0 && (
                    <div className="p-3 rounded-xl bg-surface-950/70 border border-white/5 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
                          <Crosshair className="w-3.5 h-3.5 text-rose-400" />
                          Worst-Case Threat Consequences
                        </div>
                        <span className="text-[10px] text-slate-500">Adversary Exploitation Chain</span>
                      </div>
                      <ul className="space-y-1 text-xs text-slate-300">
                        {attackImpact.potentialConsequences.map((c, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-rose-400 font-bold mt-0.5 text-xs">›</span>
                            <span className="text-[11px] text-slate-300 leading-snug">{c}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Business Risk Summary */}
                  {attackImpact.businessRisk && (
                    <div className="p-2.5 rounded-lg bg-surface-950/60 border border-white/5 flex items-start gap-2">
                      <Briefcase className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        <span className="font-semibold text-slate-300">Operational Risk: </span>
                        {attackImpact.businessRisk}
                      </p>
                    </div>
                  )}
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
                      placeholder="e.g. Is this process normal? What is the blast radius?"
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

            {/* ── TAB 2: Dedicated Impact of Attack Analysis ─── */}
            {activeDrawerTab === 'impact' && (
              <div className="space-y-4">
                {/* Blast Radius Visual Matrix */}
                <div className="p-4 rounded-xl bg-gradient-to-br from-surface-800/90 via-surface-800/60 to-surface-900/90 border border-white/10 space-y-3.5 shadow-xl">
                  <div className="flex items-center justify-between pb-2 border-b border-white/5">
                    <div className="flex items-center gap-2">
                      <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        <Flame className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                          Attack Impact & Blast Radius Matrix
                        </h3>
                        <p className="text-[11px] text-slate-400">Endpoint vulnerability perimeter & exploit scope</p>
                      </div>
                    </div>
                    <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase border ${
                      attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                        : attackImpact.severity === 'MEDIUM'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                    }`}>
                      {attackImpact.severity} Severity
                    </span>
                  </div>

                  {/* Visual Blast Radius Hierarchy Spectrum */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-[11px] font-semibold text-slate-300">
                      <span className="flex items-center gap-1.5">
                        <Target className="w-3.5 h-3.5 text-accent-400" />
                        Blast Radius Hierarchy:
                      </span>
                      <span className="text-[11px] text-accent-400 font-mono font-bold">
                        {attackImpact.blastRadius}
                      </span>
                    </div>

                    <div className="grid grid-cols-5 gap-1.5 pt-1">
                      {[
                        { step: 1, label: 'Process', desc: 'PID Sandbox' },
                        { step: 2, label: 'Filesystem', desc: 'User Space' },
                        { step: 3, label: 'Socket', desc: 'Host Network' },
                        { step: 4, label: 'LAN Subnet', desc: 'Peer Devices' },
                        { step: 5, label: 'Kernel/Root', desc: 'Full System' },
                      ].map((item) => {
                        const isHit =
                          (attackImpact.severity === 'CRITICAL' && item.step <= 5) ||
                          (attackImpact.severity === 'HIGH' && item.step <= 3) ||
                          (attackImpact.severity === 'MEDIUM' && item.step <= 3) ||
                          (attackImpact.severity === 'LOW' && item.step <= 2) ||
                          (item.step === 1);
                        const isBorder =
                          (attackImpact.severity === 'CRITICAL' && item.step === 5) ||
                          (attackImpact.severity === 'HIGH' && item.step === 3) ||
                          (attackImpact.severity === 'MEDIUM' && item.step === 3) ||
                          (attackImpact.severity === 'LOW' && item.step === 2) ||
                          (item.step === 1 && attackImpact.severity === 'NEGLIGIBLE');

                        return (
                          <div
                            key={item.step}
                            className={`p-2 rounded-lg border text-center transition-all ${
                              isBorder
                                ? 'bg-accent-400/20 border-accent-400 text-accent-300 ring-1 ring-accent-400/40'
                                : isHit
                                ? 'bg-surface-800/80 border-white/10 text-slate-300'
                                : 'bg-surface-950/40 border-white/5 text-slate-600 opacity-60'
                            }`}
                          >
                            <span className="text-[10px] font-bold block">{item.label}</span>
                            <span className="text-[9px] text-slate-400 block mt-0.5 truncate">{item.desc}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Summary Indicators */}
                  <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                    <div className="p-3 rounded-lg bg-surface-950/80 border border-white/5">
                      <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                        MITRE ATT&CK Classification
                      </span>
                      <span className="text-xs text-slate-200 font-mono font-medium mt-1 block">
                        {attackImpact.mitreTactic || 'T1204 - User Execution'}
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-surface-950/80 border border-white/5">
                      <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                        Recommended Containment Urgency
                      </span>
                      <span className="text-xs text-slate-200 font-medium mt-1 flex items-center gap-1.5">
                        <ShieldAlert className={`w-3.5 h-3.5 shrink-0 ${
                          attackImpact.severity === 'CRITICAL' || attackImpact.severity === 'HIGH'
                            ? 'text-rose-400'
                            : attackImpact.severity === 'MEDIUM'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`} />
                        {attackImpact.containmentUrgency}
                      </span>
                    </div>
                  </div>
                </div>

                {/* CIA Triad Impact Deep Dive */}
                <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                      <Lock className="w-4 h-4 text-accent-400" />
                      CIA Triad Exposure Assessment
                    </div>
                    <span className="text-[10px] text-slate-500">Industry Standard Triad Evaluation</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    <CiaBadge
                      label="Confidentiality"
                      level={attackImpact.cia?.confidentiality?.level}
                      description={attackImpact.cia?.confidentiality?.description}
                      icon={Lock}
                    />
                    <CiaBadge
                      label="Integrity"
                      level={attackImpact.cia?.integrity?.level}
                      description={attackImpact.cia?.integrity?.description}
                      icon={ShieldAlert}
                    />
                    <CiaBadge
                      label="Availability"
                      level={attackImpact.cia?.availability?.level}
                      description={attackImpact.cia?.availability?.description}
                      icon={Zap}
                    />
                  </div>
                </div>

                {/* Exploit Chain & Adversary Consequences */}
                {attackImpact.potentialConsequences && attackImpact.potentialConsequences.length > 0 && (
                  <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                        <Crosshair className="w-4 h-4 text-rose-400" />
                        Worst-Case Exploitation Scenario
                      </div>
                      <span className="text-[10px] text-slate-500">Threat Consequences</span>
                    </div>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {attackImpact.potentialConsequences.map((c, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 p-2 rounded-lg bg-surface-950/60 border border-white/5">
                          <span className="text-rose-400 font-bold text-xs mt-0.5">•</span>
                          <span className="text-xs text-slate-300 leading-relaxed font-sans">{c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Business & Regulatory Risk */}
                {attackImpact.businessRisk && (
                  <div className="p-4 rounded-xl bg-surface-800/80 border border-white/5 space-y-2">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                      <Briefcase className="w-4 h-4 text-sky-400" />
                      Business, Legal & Compliance Impact
                    </div>
                    <div className="p-3 rounded-lg bg-surface-950/80 border border-white/5">
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {attackImpact.businessRisk}
                      </p>
                      <div className="flex items-center gap-2 mt-2 pt-2 border-t border-white/5 text-[10px] text-slate-500">
                        <span>Compliance Frameworks:</span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-800 text-slate-400 border border-white/5">SOC2 Type II</span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-800 text-slate-400 border border-white/5">ISO 27001</span>
                        <span className="px-1.5 py-0.5 rounded bg-surface-800 text-slate-400 border border-white/5">GDPR Art. 32</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── TAB 3: Raw Telemetry & Details ──────────────── */}
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
