/**
 * DashboardPage — Live Operations Dashboard.
 *
 * Real-time SOC dashboard: stat cards, live event feed, severity distribution,
 * 30-minute event-rate sparkline, and live agent telemetry sentinel panels.
 */
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import PageWrapper from '@/components/layout/PageWrapper';
import LiveEventFeed   from '@/components/dashboard/LiveEventFeed';
import SeverityChart   from '@/components/dashboard/SeverityChart';
import EventRateChart  from '@/components/dashboard/EventRateChart';
import ThreatWorldMap  from '@/components/dashboard/ThreatWorldMap';
import AttackChainGraph from '@/components/dashboard/AttackChainGraph';
import AttackSimulatorModal from '@/components/dashboard/AttackSimulatorModal';
import { useLiveStats } from '@/hooks/useLiveStats';
import { useSocket } from '@/context/SocketContext';
import { threatApi, defenseApi } from '@/services/api';
import { tacticalAudio } from '@/utils/tacticalAudio';
import {
  Activity,
  Skull,
  GitBranch,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Network,
  Radio,
  ExternalLink,
  Zap,
  Volume2,
  VolumeX,
} from 'lucide-react';

function StatCard({ icon: Icon, label, value, color = 'text-accent-400', subtext, onClick }) {
  return (
    <div
      onClick={onClick}
      className={`stat-card accent-top transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:border-slate-600 hover:shadow-lg hover:shadow-black/30' : ''
      }`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-slate-500">{label}</span>
        <div className="flex items-center gap-1.5">
          {onClick && (
            <ExternalLink className="w-3 h-3 text-slate-700 group-hover:text-slate-500 transition-opacity" />
          )}
          <div className={`p-1.5 rounded-lg bg-surface-700/60 ${color}`}>
            <Icon className="w-3.5 h-3.5" />
          </div>
        </div>
      </div>
      <span className={`text-3xl font-bold tracking-tight ${color}`}>{value}</span>
      {subtext && <p className="text-xs text-slate-500 mt-1">{subtext}</p>}
    </div>
  );
}

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  const hrs  = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (hrs > 0)  return `${hrs}h ${mins}m`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

function formatMemory(bytes) {
  if (!bytes) return null;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [drillModalOpen, setDrillModalOpen] = useState(false);
  const [autopilot, setAutopilot] = useState(() => localStorage.getItem('rakshak_autopilot') === 'true');
  const [isMuted, setIsMuted] = useState(() => (tacticalAudio ? tacticalAudio.isMuted() : false));
  const { subscribe } = useSocket();

  const {
    threatCount,
    openIncidentCount,
    eventsPerMin,
    agentOnline,
    agentLastSeen,
    agentMetrics,
  } = useLiveStats(0);

  // Toggle Autopilot mode with audio feedback and persistence
  const handleToggleAutopilot = () => {
    const next = !autopilot;
    setAutopilot(next);
    localStorage.setItem('rakshak_autopilot', String(next));
    if (next) {
      tacticalAudio.playNeutralized();
      toast.success('🛡️ ADG Autopilot ARMED: Critical & High threats will be auto-neutralized!', {
        icon: '⚡',
        duration: 4000,
      });
    } else {
      toast('Autopilot Disarmed (Manual Containment Mode)', { icon: 'ℹ️' });
    }
  };

  // Toggle tactical audio synthesizer
  const handleToggleAudio = () => {
    const muted = tacticalAudio.toggleMute();
    setIsMuted(muted);
  };

  // Execute Red Team Drill simulation
  const handleLaunchDrill = async (scenario) => {
    await threatApi.simulate(scenario);
  };

  // Real-time audio cue & Autopilot containment subscriber
  useEffect(() => {
    const unsub = subscribe('finding:new', async (finding) => {
      if (!finding) return;

      if (finding.severity === 'critical') {
        tacticalAudio.playAlarm();
      } else {
        tacticalAudio.playRadarPing();
      }

      // Autopilot autonomous containment
      if (autopilot && (finding.severity === 'critical' || finding.severity === 'high')) {
        const targetIp = finding.source?.ip;
        const targetPid = finding.source?.pid;
        if (targetIp || targetPid) {
          try {
            const actionType = targetPid ? 'kill_process' : 'block_ip';
            const target = targetPid ? String(targetPid) : targetIp;
            await defenseApi.contain({
              actionType,
              target,
              threatId: finding._id,
              reason: `Autopilot containment: ${finding.type} (${finding.severity})`,
              autoApproved: true,
            });
            tacticalAudio.playNeutralized();
            toast.success(`⚡ Autopilot Countermeasure: Neutralized ${actionType.replace('_', ' ').toUpperCase()} (${target})`, {
              duration: 5000,
            });
          } catch (err) {
            console.error('[Autopilot containment error]:', err);
          }
        }
      }
    });

    return () => {
      if (typeof unsub === 'function') unsub();
    };
  }, [subscribe, autopilot]);

  const dashboardActions = (
    <div className="flex items-center gap-2">
      {/* Audio Mute/Unmute */}
      <button
        onClick={handleToggleAudio}
        title={isMuted ? 'Unmute tactical audio' : 'Mute tactical audio'}
        className={`p-1.5 rounded-lg border text-xs transition-colors ${
          isMuted
            ? 'bg-surface-800 border-surface-700 text-slate-500 hover:text-slate-300'
            : 'bg-surface-800 border-accent-400/40 text-accent-400 hover:bg-surface-700'
        }`}
      >
        {isMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
      </button>

      {/* Autopilot Switch */}
      <button
        onClick={handleToggleAutopilot}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono font-semibold transition-all ${
          autopilot
            ? 'bg-emerald-950/80 border-emerald-500/60 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.3)] animate-pulse'
            : 'bg-surface-800 border-surface-700 text-slate-400 hover:text-slate-300'
        }`}
        title="Autonomous Cyber Defense Grid Autopilot (Auto-neutralize critical threats)"
      >
        <Zap className={`w-3.5 h-3.5 ${autopilot ? 'text-emerald-400 fill-emerald-400' : 'text-slate-500'}`} />
        <span>AUTOPILOT: {autopilot ? 'ARMED' : 'MANUAL'}</span>
      </button>

      {/* Red Team Attack Drill Simulator */}
      <button
        onClick={() => setDrillModalOpen(true)}
        className="flex items-center gap-1.5 px-3 py-1 rounded-lg border border-red-800/70 bg-red-950/60 hover:bg-red-900/80 text-red-300 text-xs font-mono font-semibold shadow-md shadow-red-950/40 transition-all"
      >
        <Skull className="w-3.5 h-3.5 text-red-400" />
        <span>Simulate Attack</span>
      </button>
    </div>
  );

  return (
    <PageWrapper
      title="Live Dashboard"
      subtitle="Real-time security operations center · autonomous agent correlation"
      actions={dashboardActions}
    >
      {/* ── Stat Row ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={Skull}
          label="Threats Detected"
          value={threatCount}
          color="text-red-400"
          subtext="click to view findings"
          onClick={() => navigate('/threats')}
        />
        <StatCard
          icon={GitBranch}
          label="Open Incidents"
          value={openIncidentCount}
          color={openIncidentCount > 0 ? 'text-orange-400' : 'text-slate-400'}
          subtext={openIncidentCount === 1 ? '1 correlated cluster' : `${openIncidentCount} correlated clusters`}
          onClick={() => navigate('/incidents')}
        />
        <StatCard
          icon={Activity}
          label="Events / min"
          value={eventsPerMin}
          color="text-accent-400"
          subtext="rolling stream rate"
        />
        <StatCard
          icon={agentOnline ? ShieldCheck : ShieldAlert}
          label="Agent Status"
          value={agentOnline ? 'ONLINE' : 'OFFLINE'}
          color={agentOnline ? 'text-emerald-400' : 'text-slate-500'}
          subtext={agentOnline ? 'paired & streaming' : 'agent daemon offline'}
          onClick={() => navigate('/settings')}
        />
      </div>

      {/* ── Event Rate Sparkline ───────────────────────────────── */}
      <div className="mb-4">
        <EventRateChart />
      </div>

      {/* ── Live Global Threat Origin Map ───────────────────────── */}
      <div className="mb-4">
        <ThreatWorldMap />
      </div>

      {/* ── Interactive Kill-Chain Attack Graph & SOAR Panel ─────── */}
      <div className="mb-4">
        <AttackChainGraph />
      </div>

      {/* ── Main Panels ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <div className="xl:col-span-2">
          <LiveEventFeed />
        </div>
        <SeverityChart />
      </div>

      {/* ── Dynamic Sentinel Monitors ─────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Host Process Sentinel */}
        <div className="glass-card glow-border p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-slate-300 text-xs font-semibold">
              <Cpu className="w-4 h-4 text-accent-400" />
              <span>Host Process Sentinel</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${agentOnline ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
              <span className="text-[11px] font-mono text-slate-400">
                {agentOnline ? 'ACTIVE SENSOR' : 'OFFLINE'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 my-2 py-2 border-y border-surface-700/50 text-center">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Agent RSS</p>
              <p className="text-sm font-mono font-medium text-slate-200">
                {formatMemory(agentMetrics?.memory) || (agentOnline ? '~34 MB' : '—')}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Uptime</p>
              <p className="text-sm font-mono font-medium text-slate-200">
                {formatUptime(agentMetrics?.uptime)}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Scan Cadence</p>
              <p className="text-sm font-mono font-medium text-accent-400">10s Poll</p>
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
            <span>Heuristics: Suspicious child spawns & ransomware</span>
            <span className="font-mono text-slate-400">PID Inspection On</span>
          </div>
        </div>

        {/* Network Sentinel */}
        <div className="glass-card glow-border p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-slate-300 text-xs font-semibold">
              <Network className="w-4 h-4 text-accent-400" />
              <span>Network Sentinel</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Radio className={`w-3.5 h-3.5 ${agentOnline ? 'text-accent-400 animate-pulse' : 'text-slate-600'}`} />
              <span className="text-[11px] font-mono text-slate-400">
                {agentOnline ? 'SOCKET PROBE' : 'STANDBY'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 my-2 py-2 border-y border-surface-700/50 text-center">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Protocols</p>
              <p className="text-sm font-mono font-medium text-slate-200">TCP / UDP</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Port Range</p>
              <p className="text-sm font-mono font-medium text-slate-200">1 – 65535</p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Last Heartbeat</p>
              <p className="text-sm font-mono font-medium text-emerald-400">
                {agentLastSeen
                  ? agentLastSeen.toLocaleTimeString()
                  : (agentOnline ? 'Live' : '—')}
              </p>
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
            <span>Detection: Port scans, brute force, C2 beacons</span>
            <span className="font-mono text-slate-400">Zero-Exfiltration</span>
          </div>
        </div>
      </div>

      {/* ── Red Team Drill Simulator Modal ─────────────────────── */}
      <AttackSimulatorModal
        isOpen={drillModalOpen}
        onClose={() => setDrillModalOpen(false)}
        onLaunchDrill={handleLaunchDrill}
      />
    </PageWrapper>
  );
}
