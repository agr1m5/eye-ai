/**
 * DefensePage.jsx — Active Defense & SOAR Command Grid
 *
 * Centralized dashboard for managing active countermeasures,
 * live firewall IP blocklists, terminated process trees, and honeytokens.
 */
import { useState, useEffect } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import Spinner from '@/components/common/Spinner';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Terminal,
  Server,
  Lock,
  Unlock,
  Radio,
  RefreshCw,
  Clock,
  Trash2,
  Plus,
  Flame,
  FileWarning,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { defenseApi } from '@/services/api';
import { tacticalAudio } from '@/utils/tacticalAudio';

export default function DefensePage() {
  const [actions, setActions] = useState([]);
  const [stats, setStats] = useState({ total: 0, active: 0, isolatedHosts: 0, quarantinedFiles: 0, killedProcesses: 0 });
  const [loading, setLoading] = useState(true);
  const [dispatchType, setDispatchType] = useState('isolate_host');
  const [dispatchTarget, setDispatchTarget] = useState('');
  const [dispatchReason, setDispatchReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchActions = async () => {
    try {
      setLoading(true);
      const res = await defenseApi.actions();
      if (res.data?.status === 'success') {
        setActions(res.data.data.actions || []);
        setStats(res.data.data.stats || {});
      }
    } catch {
      toast.error('Failed to load active defense actions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, []);

  const handleManualContain = async (e) => {
    e.preventDefault();
    if (!dispatchTarget.trim()) {
      toast.error('Please enter a target (PID, hostname, or file path)');
      return;
    }

    try {
      setSubmitting(true);
      const res = await defenseApi.contain({
        actionType: dispatchType,
        target: dispatchTarget.trim(),
        pid: dispatchType === 'kill_process' ? Number(dispatchTarget.trim()) : undefined,
        filePath: dispatchType === 'quarantine_file' ? dispatchTarget.trim() : null,
        reason: dispatchReason.trim() || 'Manual SOAR countermeasure initiated by analyst',
        executedBy: 'analyst',
      });

      if (res.data?.status === 'success') {
        tacticalAudio.playNeutralized();
        toast.success(`⚡ Countermeasure Executed: ${dispatchType} on ${dispatchTarget}`);
        setDispatchTarget('');
        setDispatchReason('');
        fetchActions();
      }
    } catch (err) {
      toast.error(`Countermeasure failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRelease = async (id, target) => {
    try {
      const res = await defenseApi.release(id);
      if (res.data?.status === 'success') {
        toast.success(`✓ Containment released for ${target}`);
        fetchActions();
      }
    } catch (err) {
      toast.error(`Release failed: ${err.response?.data?.message || err.message}`);
    }
  };

  const quarantinedList = actions.filter((a) => a.actionType === 'quarantine_file' && a.status === 'active');
  const activeEnforcements = actions.filter((a) => (a.actionType === 'quarantine_file' || a.actionType === 'isolate_host') && a.status === 'active');

  return (
    <PageWrapper
      title="Active Defense & SOAR Grid"
      subtitle="Autonomous countermeasure enforcement · process isolation · file quarantine · honeytokens"
    >
      {/* ── Top Metric Cards ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="stat-card accent-top">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 font-medium">Quarantined Files</span>
            <div className="p-1.5 rounded-lg bg-amber-950/60 text-amber-400 border border-amber-800/40">
              <FileWarning className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold font-mono text-amber-400">{stats.quarantinedFiles || quarantinedList.length}</p>
          <span className="text-[11px] text-slate-500 font-mono">Vaulted & Stripped to 0400</span>
        </div>

        <div className="stat-card accent-top">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 font-medium">Terminated PIDs</span>
            <div className="p-1.5 rounded-lg bg-orange-950/60 text-orange-400 border border-orange-800/40">
              <Terminal className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold font-mono text-orange-400">{stats.killedProcesses || 0}</p>
          <span className="text-[11px] text-slate-500 font-mono">SIGKILL Process Trees</span>
        </div>

        <div className="stat-card accent-top">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 font-medium">Host Guard</span>
            <div className="p-1.5 rounded-lg bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold font-mono text-cyan-400">
            {stats.isolatedHosts > 0 ? 'ISOLATED' : 'ARMED'}
          </p>
          <span className="text-[11px] text-slate-500 font-mono">
            {stats.isolatedHosts > 0 ? 'Egress Restricted' : 'Full Telemetry Streaming'}
          </span>
        </div>

        <div className="stat-card accent-top">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 font-medium">Canary Tripwire</span>
            <div className="p-1.5 rounded-lg bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-400">ARMED</p>
          <span className="text-[11px] text-slate-500 font-mono">~/.eye/canary.env Active</span>
        </div>
      </div>

      {/* ── Manual Containment Dispatcher Form ───────────────────── */}
      <div className="glass-card glow-border p-5 mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Zap className="w-4 h-4 text-accent-400" />
          <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wide font-mono">
            Dispatch Countermeasure Command
          </h2>
        </div>
        <form onSubmit={handleManualContain} className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Action Type</label>
            <select
              value={dispatchType}
              onChange={(e) => setDispatchType(e.target.value)}
              className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-500"
            >
              <option value="isolate_host">Isolate Host Network</option>
              <option value="quarantine_file">Quarantine Suspicious Binary</option>
              <option value="kill_process">Terminate Process (PID)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Target (PID / Path / Host)
            </label>
            <input
              type="text"
              placeholder={dispatchType === 'kill_process' ? 'e.g. 4921' : dispatchType === 'quarantine_file' ? '/tmp/malware.sh' : 'soc-collector-01'}
              value={dispatchTarget}
              onChange={(e) => setDispatchTarget(e.target.value)}
              className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Reason / Notes</label>
            <input
              type="text"
              placeholder="e.g. Active C2 connection observed"
              value={dispatchReason}
              onChange={(e) => setDispatchReason(e.target.value)}
              className="w-full bg-surface-800 border border-surface-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-500"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-red-700 hover:bg-red-600 text-white font-mono font-bold text-xs py-2 px-4 rounded-lg flex items-center justify-center gap-1.5 shadow-lg shadow-red-950/60 transition-all"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>{submitting ? 'Enforcing...' : 'Execute Countermeasure'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* ── Active Firewall Blocklist & Containment Tables ──────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left 2 Cols: Active Firewall Blocklist */}
        <div className="xl:col-span-2 glass-card glow-border overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-surface-700/80 bg-surface-800/40">
            <div className="flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-amber-400" />
              <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wide font-mono">
                Active Quarantine & Isolation ({activeEnforcements.length})
              </h3>
            </div>
            <button
              onClick={fetchActions}
              className="p-1.5 rounded-lg bg-surface-800 border border-surface-700 text-slate-400 hover:text-slate-200"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-accent-400' : ''}`} />
            </button>
          </div>

          {loading && actions.length === 0 ? (
            <div className="p-8 flex justify-center"><Spinner /></div>
          ) : activeEnforcements.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs">
              <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-1.5" />
              <p>No active quarantine or host isolation countermeasures currently enforced.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-800/60 text-slate-400 uppercase font-mono text-[11px] border-b border-surface-700/50">
                  <tr>
                    <th className="py-2.5 px-4">Action</th>
                    <th className="py-2.5 px-4">Target</th>
                    <th className="py-2.5 px-4">Enforced At</th>
                    <th className="py-2.5 px-4">Reason</th>
                    <th className="py-2.5 px-4">Initiator</th>
                    <th className="py-2.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-700/40">
                  {activeEnforcements.map((item) => (
                    <tr key={item._id} className="hover:bg-surface-800/30 font-mono">
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          item.actionType === 'isolate_host'
                            ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/40'
                            : 'bg-amber-950/80 text-amber-300 border border-amber-800/40'
                        }`}>
                          {item.actionType.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-200 font-bold flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${item.actionType === 'isolate_host' ? 'bg-cyan-400' : 'bg-amber-400'} animate-pulse`} />
                        <span className="truncate max-w-[200px]">{item.target}</span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(item.createdAt).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-4 text-slate-300 font-sans text-xs truncate max-w-[180px]">
                        {item.reason}
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        <span className="px-1.5 py-0.5 rounded bg-surface-800 border border-surface-700">
                          {item.executedBy}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleRelease(item._id, item.target)}
                          className="px-2.5 py-1 text-[11px] rounded bg-surface-800 hover:bg-emerald-950/80 text-slate-300 hover:text-emerald-300 border border-surface-700 hover:border-emerald-700/60 transition-all"
                        >
                          {item.actionType === 'quarantine_file' ? 'Restore File' : 'Release Isolation'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Col: Complete SOAR Action Audit Trail */}
        <div className="glass-card glow-border overflow-hidden">
          <div className="p-4 border-b border-surface-700/80 bg-surface-800/40 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wide font-mono">
              Containment History Log
            </h3>
          </div>

          <div className="p-3 divide-y divide-surface-700/40 max-h-[420px] overflow-y-auto">
            {actions.length === 0 ? (
              <p className="text-center text-slate-500 text-xs py-6">No containment actions recorded yet.</p>
            ) : (
              actions.slice(0, 15).map((act) => (
                <div key={act._id} className="py-2.5 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] font-semibold text-accent-300 uppercase">
                      {act.actionType}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                        act.status === 'active'
                          ? 'bg-red-950/60 border-red-800 text-red-300'
                          : 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                      }`}
                    >
                      {act.status}
                    </span>
                  </div>
                  <p className="font-mono text-slate-200 text-xs font-bold">{act.target}</p>
                  <p className="text-slate-400 text-[11px] truncate">{act.reason}</p>
                  <span className="text-slate-500 text-[10px] font-mono">
                    {new Date(act.createdAt).toLocaleString()} · {act.executedBy}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </PageWrapper>
  );
}
