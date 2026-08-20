/**
 * DashboardPage — Live Operations Dashboard.
 *
 * Real-time SOC dashboard streaming live findings, threat distributions,
 * and agent connection statuses.
 */
import PageWrapper from '@/components/layout/PageWrapper';
import LiveEventFeed from '@/components/dashboard/LiveEventFeed';
import SeverityChart from '@/components/dashboard/SeverityChart';
import { useLiveStats } from '@/hooks/useLiveStats';
import { Activity, Skull, GitBranch, ShieldCheck, ShieldAlert, Cpu, Network } from 'lucide-react';

function StatCard({ icon: Icon, label, value, color = 'text-accent-400', subtext }) {
  return (
    <div className="stat-card accent-top">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-slate-500">{label}</span>
        <div className={`p-1.5 rounded-lg bg-surface-700/60 ${color}`}>
          <Icon className="w-3.5 h-3.5" />
        </div>
      </div>
      <span className={`text-3xl font-bold ${color}`}>{value}</span>
      {subtext && <p className="text-xs text-slate-600 mt-1">{subtext}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const { threatCount, eventsPerMin, agentOnline } = useLiveStats(0);

  return (
    <PageWrapper
      title="Live Dashboard"
      subtitle="Real-time security monitoring · local agent"
    >
      {/* Stat row */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={Skull}
          label="Threats Detected"
          value={threatCount}
          color="text-red-400"
          subtext="live session total"
        />
        <StatCard
          icon={GitBranch}
          label="Open Incidents"
          value="0"
          color="text-orange-400"
          subtext="correlated clusters"
        />
        <StatCard
          icon={Activity}
          label="Events / min"
          value={eventsPerMin}
          color="text-accent-400"
          subtext="rolling rate"
        />
        <StatCard
          icon={agentOnline ? ShieldCheck : ShieldAlert}
          label="Agent Status"
          value={agentOnline ? 'ONLINE' : 'OFFLINE'}
          color={agentOnline ? 'text-emerald-400' : 'text-slate-400'}
          subtext={agentOnline ? 'receiving telemetry' : 'start agent to connect'}
        />
      </div>

      {/* Main panels */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 mb-4">
        <div className="xl:col-span-2">
          <LiveEventFeed />
        </div>
        <SeverityChart />
      </div>

      {/* Secondary monitors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="glass-card glow-border h-48 flex flex-col p-4 justify-between">
          <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold">
            <Cpu className="w-4 h-4 text-accent-400" />
            <span>Process Monitor</span>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center text-slate-600 text-xs">
            <p>System process telemetry active</p>
            <span className="text-[11px] text-slate-700 mt-1 font-mono">Agent will report anomalous PIDs</span>
          </div>
        </div>

        <div className="glass-card glow-border h-48 flex flex-col p-4 justify-between">
          <div className="flex items-center gap-2 text-slate-400 text-xs font-semibold">
            <Network className="w-4 h-4 text-accent-400" />
            <span>Network Sentinel</span>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center text-slate-600 text-xs">
            <p>Inbound / Outbound socket monitoring</p>
            <span className="text-[11px] text-slate-700 mt-1 font-mono">Monitoring suspicious ports & IPs</span>
          </div>
        </div>
      </div>
    </PageWrapper>
  );
}
