/**
 * AttackChainGraph.jsx — Interactive Kill-Chain Visualizer & Active Defense SOAR Panel
 *
 * Renders the full attack progression chain from Ingress Attacker IP to Compromised Asset,
 * with real-time containment triggers (Kill Process, Block IP, Isolate Host).
 */
import { useState, useEffect, useMemo } from 'react';
import {
  GitBranch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Radio,
  Zap,
  Lock,
  Skull,
  Server,
  Terminal,
  Database,
  ArrowRight,
  AlertTriangle,
  Flame,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { defenseApi, incidentApi, threatApi } from '@/services/api';
import { useSocket } from '@/context/SocketContext';

export default function AttackChainGraph() {
  const { lastFinding } = useSocket();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [containmentStates, setContainmentStates] = useState({}); // id -> { blocked: bool, killed: bool, isolated: bool }
  const [executingAction, setExecutingAction] = useState(null);

  // Load active incidents
  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await incidentApi.list({ limit: 10 });
      const items = res.data?.data?.incidents || [];
      setIncidents(items);
      if (items.length > 0 && !selectedIncident) {
        setSelectedIncident(items[0]);
      }
    } catch {
      // handled
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  // Real-time update if socket emits new finding
  useEffect(() => {
    if (!lastFinding) return;
    fetchIncidents();
  }, [lastFinding]);

  // Derive graph nodes from the selected incident
  const chainData = useMemo(() => {
    if (!selectedIncident) {
      return {
        attackerIp: '198.51.100.9',
        attackerLocation: 'Amsterdam, Netherlands (AS16276)',
        protocol: 'TCP / 443 (HTTPS POST Payload)',
        processName: 'bash -i',
        processPid: 4921,
        technique: 'T1059.004 Command Injection',
        action: 'Arbitrary Shell Execution',
        targetAsset: 'Host Endpoint & Decoy Honeytoken',
        severity: 'critical',
      };
    }

    const threat = selectedIncident.threatIds?.[0] || {};
    const ip = threat.source?.ip || threat.geo?.ip || '198.51.100.42';
    const loc = threat.geo?.country ? `${threat.geo?.city ? threat.geo.city + ', ' : ''}${threat.geo.country}` : 'External Botnet C2';
    const pid = threat.source?.pid || 4921;
    const processName = threat.source?.processName || 'bash';

    return {
      attackerIp: ip,
      attackerLocation: loc,
      protocol: 'TCP / 443 (Reverse Shell / HTTP Beacon)',
      processName,
      processPid: pid,
      technique: selectedIncident.mitreTechniques?.[0] || 'T1059 Command & Scripting',
      action: threat.type || selectedIncident.title || 'Multi-stage exploit sequence',
      targetAsset: 'Local Host Sensor (soc-collector-01)',
      severity: selectedIncident.severity || 'high',
    };
  }, [selectedIncident]);

  const activeKey = selectedIncident?._id || 'default';
  const currentState = containmentStates[activeKey] || {};

  // Trigger Active Defense Countermeasure
  const handleContainment = async (actionType, target, label) => {
    try {
      setExecutingAction(actionType);
      const res = await defenseApi.contain({
        actionType,
        target,
        reason: `SOAR Kill-Chain Defense Trigger for ${chainData.action}`,
        incidentId: selectedIncident?._id || null,
        executedBy: 'analyst',
      });

      if (res.data?.status === 'success') {
        toast.success(`🛡️ Countermeasure Executed: ${label}`);
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

  const isFullyNeutralized = currentState.kill_process && (currentState.block_ip || currentState.isolate_host);

  return (
    <div className="glass-card glow-border p-4 relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-purple-950/60 border border-purple-800/40 text-purple-400">
            <GitBranch className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-100 tracking-wide">
                Live Kill-Chain Attack Graph
              </span>
              {isFullyNeutralized ? (
                <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded-full border border-emerald-700/50">
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  THREAT NEUTRALIZED
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] font-mono text-red-400 bg-red-950/60 px-2 py-0.5 rounded-full border border-red-800/60 animate-pulse">
                  <Flame className="w-3 h-3 text-red-400" />
                  ACTIVE KILL-CHAIN
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Interactive node-link progression from ingress origin to target asset with one-click SOAR countermeasures
            </p>
          </div>
        </div>

        {/* Incident Selector */}
        {incidents.length > 1 && (
          <div className="flex items-center gap-1.5 bg-surface-800/80 px-2.5 py-1 rounded-lg border border-surface-700/60 text-xs">
            <span className="text-slate-500 font-mono text-[11px]">Incident:</span>
            <select
              value={selectedIncident?._id || ''}
              onChange={(e) => {
                const inc = incidents.find((i) => i._id === e.target.value);
                if (inc) setSelectedIncident(inc);
              }}
              className="bg-transparent text-slate-200 text-xs font-mono focus:outline-none cursor-pointer"
            >
              {incidents.map((inc) => (
                <option key={inc._id} value={inc._id} className="bg-surface-900 text-slate-200">
                  {inc.title?.slice(0, 30)} ({inc.severity})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Graph Visual Canvas */}
      <div className="bg-[#030712] rounded-lg border border-surface-700/60 p-4 overflow-x-auto select-none relative">
        {/* Subtle grid background */}
        <div
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, #00f0ff 1px, transparent 0)`,
            backgroundSize: '24px 24px',
          }}
        />

        <div className="min-w-[820px] flex items-center justify-between gap-3 relative z-10 py-3">
          {/* 1. Attacker Node */}
          <div
            className={`flex-1 rounded-lg border p-3 transition-all ${
              currentState.block_ip
                ? 'bg-slate-900/80 border-slate-700 text-slate-400 opacity-60'
                : 'bg-red-950/40 border-red-800/70 shadow-lg shadow-red-950/30'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-red-300">
                <Skull className="w-3.5 h-3.5 text-red-400" />
                <span>1. Ingress Origin</span>
              </div>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                  currentState.block_ip
                    ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                    : 'bg-red-900/60 border-red-700 text-red-300'
                }`}
              >
                {currentState.block_ip ? 'BLOCKED' : 'MALICIOUS'}
              </span>
            </div>
            <p className="font-mono text-xs font-bold text-slate-100">{chainData.attackerIp}</p>
            <p className="text-[11px] text-slate-400 mt-0.5 truncate">{chainData.attackerLocation}</p>

            <button
              onClick={() => handleContainment('block_ip', chainData.attackerIp, `Blocked IP ${chainData.attackerIp}`)}
              disabled={currentState.block_ip || executingAction === 'block_ip'}
              className={`mt-2.5 w-full py-1 px-2 rounded text-[11px] font-mono flex items-center justify-center gap-1 transition-all ${
                currentState.block_ip
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-red-900/80 hover:bg-red-800 text-red-100 border border-red-700/80 hover:shadow-md'
              }`}
            >
              <Zap className="w-3 h-3 text-red-400" />
              <span>{currentState.block_ip ? 'Firewall Blocked ✓' : 'Block IP via SOAR'}</span>
            </button>
          </div>

          {/* Arrow Link */}
          <div className="flex flex-col items-center justify-center text-slate-600 px-1">
            <span className="text-[9px] font-mono text-slate-500 mb-0.5">EXPLOIT</span>
            <ArrowRight className={`w-4 h-4 ${isFullyNeutralized ? 'text-slate-600' : 'text-red-400 animate-pulse'}`} />
          </div>

          {/* 2. Vector / Protocol Node */}
          <div className="flex-1 rounded-lg border border-amber-900/50 bg-amber-950/30 p-3">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                <Server className="w-3.5 h-3.5 text-amber-400" />
                <span>2. Attack Vector</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-900/60 border border-amber-800 text-amber-300 uppercase">
                PAYLOAD
              </span>
            </div>
            <p className="font-mono text-xs font-medium text-slate-100">{chainData.protocol}</p>
            <p className="text-[11px] text-slate-400 mt-0.5 truncate">{chainData.technique}</p>

            <div className="mt-2.5 py-1 px-2 rounded bg-amber-950/60 border border-amber-800/40 text-[10px] font-mono text-amber-300 text-center">
              WAF / IDS Interception
            </div>
          </div>

          {/* Arrow Link */}
          <div className="flex flex-col items-center justify-center text-slate-600 px-1">
            <span className="text-[9px] font-mono text-slate-500 mb-0.5">SPAWN</span>
            <ArrowRight className={`w-4 h-4 ${isFullyNeutralized ? 'text-slate-600' : 'text-amber-400 animate-pulse'}`} />
          </div>

          {/* 3. Host Process Node */}
          <div
            className={`flex-1 rounded-lg border p-3 transition-all ${
              currentState.kill_process
                ? 'bg-slate-900/80 border-slate-700 text-slate-400 opacity-60'
                : 'bg-orange-950/40 border-orange-800/70 shadow-lg shadow-orange-950/30'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-orange-300">
                <Terminal className="w-3.5 h-3.5 text-orange-400" />
                <span>3. Compromised PID</span>
              </div>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                  currentState.kill_process
                    ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                    : 'bg-orange-900/60 border-orange-700 text-orange-300'
                }`}
              >
                {currentState.kill_process ? 'KILLED' : 'EXECUTING'}
              </span>
            </div>
            <p className="font-mono text-xs font-bold text-slate-100">PID {chainData.processPid}</p>
            <p className="text-[11px] text-slate-400 mt-0.5 font-mono truncate">{chainData.processName}</p>

            <button
              onClick={() => handleContainment('kill_process', `PID: ${chainData.processPid}`, `Killed PID ${chainData.processPid}`)}
              disabled={currentState.kill_process || executingAction === 'kill_process'}
              className={`mt-2.5 w-full py-1 px-2 rounded text-[11px] font-mono flex items-center justify-center gap-1 transition-all ${
                currentState.kill_process
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : 'bg-orange-900/80 hover:bg-orange-800 text-orange-100 border border-orange-700/80 hover:shadow-md'
              }`}
            >
              <Zap className="w-3 h-3 text-orange-400" />
              <span>{currentState.kill_process ? 'Process Killed ✓' : 'SIGKILL Process'}</span>
            </button>
          </div>

          {/* Arrow Link */}
          <div className="flex flex-col items-center justify-center text-slate-600 px-1">
            <span className="text-[9px] font-mono text-slate-500 mb-0.5">TARGET</span>
            <ArrowRight className={`w-4 h-4 ${isFullyNeutralized ? 'text-slate-600' : 'text-cyan-400 animate-pulse'}`} />
          </div>

          {/* 4. Target Asset Node */}
          <div
            className={`flex-1 rounded-lg border p-3 transition-all ${
              currentState.isolate_host
                ? 'bg-cyan-950/60 border-cyan-600 shadow-md shadow-cyan-950/40'
                : 'bg-surface-900/80 border-surface-700/80'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-cyan-300">
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                <span>4. Targeted Asset</span>
              </div>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.2 rounded border uppercase ${
                  currentState.isolate_host
                    ? 'bg-cyan-900/80 border-cyan-600 text-cyan-200'
                    : 'bg-surface-800 border-surface-700 text-slate-400'
                }`}
              >
                {currentState.isolate_host ? 'ISOLATED' : 'PROTECTED'}
              </span>
            </div>
            <p className="font-mono text-xs font-bold text-slate-200 truncate">{chainData.targetAsset}</p>
            <p className="text-[11px] text-slate-400 mt-0.5 truncate">Honeytoken Tripwire Armed</p>

            <button
              onClick={() => handleContainment('isolate_host', chainData.targetAsset, `Isolated Host ${chainData.targetAsset}`)}
              disabled={currentState.isolate_host || executingAction === 'isolate_host'}
              className={`mt-2.5 w-full py-1 px-2 rounded text-[11px] font-mono flex items-center justify-center gap-1 transition-all ${
                currentState.isolate_host
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 cursor-not-allowed'
                  : 'bg-surface-800 hover:bg-surface-700 text-slate-300 hover:text-white border border-surface-600'
              }`}
            >
              <Lock className="w-3 h-3 text-cyan-400" />
              <span>{currentState.isolate_host ? 'Host Isolated ✓' : 'Isolate Host Network'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
