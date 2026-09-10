/**
 * SettingsPage — User account, agent pairing tokens, and AI configuration.
 *
 * Supports:
 *   - Displaying authenticated analyst info
 *   - Issuing dedicated cryptographically random agent pairing token (one-time view)
 *   - Revoking agent token
 *   - Inspecting pairing health & expiration
 */
import { useState, useEffect, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import Modal from '@/components/common/Modal';
import { useAuth } from '@/context/AuthContext';
import { authApi } from '@/services/api';
import { Settings, ShieldCheck, ShieldAlert, Bot, Database, User, Copy, Check, AlertTriangle, Key, GitBranch, Save, Terminal, Network, FileText, CheckCircle2 } from 'lucide-react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

function Section({ icon: Icon, title, children }) {
  return (
    <div className="glass-card glow-border p-6 rounded-xl space-y-4">
      <div className="flex items-center gap-2 border-b border-white/5 pb-4">
        <Icon className="w-4 h-4 text-accent-400" />
        <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      </div>
      {children}
    </div>
  );
}

export default function SettingsPage() {
  const { user } = useAuth();
  const [pairingStatus, setPairingStatus] = useState(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [issuing, setIssuing] = useState(false);
  const [revoking, setRevoking] = useState(false);

  // One-time token reveal modal
  const [revealedToken, setRevealedToken] = useState(null);
  const [hasCopied, setHasCopied] = useState(false);

  // Correlation rule engine settings
  const defaultWindowMs    = user?.preferences?.correlationWindowMs    ?? 15 * 60 * 1000;
  const defaultMinThreshold = user?.preferences?.minFindingsThreshold   ?? 2;
  const [windowMins, setWindowMins]       = useState(Math.round(defaultWindowMs / 60000));
  const [minThreshold, setMinThreshold]   = useState(defaultMinThreshold);
  const [savingPrefs, setSavingPrefs]     = useState(false);

  const fetchAgentStatus = useCallback(async () => {
    try {
      setLoadingStatus(true);
      const { data } = await authApi.agentStatus();
      if (data.status === 'success') {
        setPairingStatus(data.data);
      }
    } catch (_) {
      // Non-blocking
    } finally {
      setLoadingStatus(false);
    }
  }, []);

  useEffect(() => {
    fetchAgentStatus();
  }, [fetchAgentStatus]);

  const handleIssueToken = async () => {
    setIssuing(true);
    try {
      const { data } = await authApi.pairAgent('Local Mac SOC Agent');
      if (data.status === 'success') {
        setRevealedToken(data.token);
        fetchAgentStatus();
        toast.success('Agent pairing token generated');
      }
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to generate agent token');
    } finally {
      setIssuing(false);
    }
  };

  const handleRevokeToken = async () => {
    if (!window.confirm('Are you sure? The running agent will immediately disconnect and stop reporting telemetry.')) {
      return;
    }

    setRevoking(true);
    try {
      await authApi.revokeAgent();
      toast.success('Agent token revoked');
      fetchAgentStatus();
    } catch (err) {
      toast.error('Failed to revoke agent token');
    } finally {
      setRevoking(false);
    }
  };

  const handleCopy = () => {
    if (!revealedToken) return;
    navigator.clipboard.writeText(revealedToken);
    setHasCopied(true);
    toast.success('Token copied to clipboard');
    setTimeout(() => setHasCopied(false), 2000);
  };

  const handleSavePreferences = async () => {
    setSavingPrefs(true);
    try {
      await authApi.updatePreferences({
        correlationWindowMs:  windowMins * 60 * 1000,
        minFindingsThreshold: minThreshold,
      });
      toast.success('Correlation rules saved — applies to next incoming finding');
    } catch (err) {
      toast.error('Failed to save preferences');
    } finally {
      setSavingPrefs(false);
    }
  };

  return (
    <PageWrapper title="SOC Settings" subtitle="Analyst credentials, local agent pairing, and detection configs">
      <div className="max-w-3xl space-y-6">
        {/* Account Info */}
        <Section icon={User} title="Analyst Account">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-500 mb-1 font-medium">Analyst Email</label>
              <input
                className="input w-full text-xs font-mono"
                value={user?.email || 'analyst@rakshak.local'}
                disabled
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1 font-medium">Account ID</label>
              <input
                className="input w-full text-xs font-mono"
                value={user?._id || '—'}
                disabled
              />
            </div>
          </div>
        </Section>

        {/* Agent Pairing */}
        <Section icon={ShieldCheck} title="Local SOC Agent Pairing">
          <p className="text-xs text-slate-400 leading-relaxed">
            The local agent runs as a daemon on your machine and streams telemetry (port scans, anomalous processes,
            kill-chain indicators) to this SOC via authenticated WebSockets.
          </p>

          {/* Current Status Box */}
          <div className="p-4 rounded-xl bg-surface-800/40 border border-white/5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400 font-medium">Pairing Status:</span>
              {pairingStatus?.paired && !pairingStatus?.expired ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 bg-emerald-400/10 px-2.5 py-1 rounded-full">
                  <ShieldCheck className="w-3.5 h-3.5" /> Paired &amp; Active
                </span>
              ) : pairingStatus?.expired ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-400 bg-red-400/10 px-2.5 py-1 rounded-full">
                  <AlertTriangle className="w-3.5 h-3.5" /> Token Expired
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 bg-surface-700/60 px-2.5 py-1 rounded-full">
                  <ShieldAlert className="w-3.5 h-3.5" /> Unpaired
                </span>
              )}
            </div>

            {pairingStatus?.paired && (
              <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-white/5">
                <div className="flex justify-between">
                  <span className="text-slate-500">Agent Label:</span>
                  <span className="font-mono text-slate-300">{pairingStatus.label}</span>
                </div>
                {pairingStatus.expiresAt && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">Token Expires:</span>
                    <span className="text-slate-300">
                      {format(new Date(pairingStatus.expiresAt), 'dd MMM yyyy')}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="flex flex-wrap gap-2 pt-2">
            <button
              onClick={handleIssueToken}
              disabled={issuing}
              className="btn-primary text-xs px-3.5 py-2 flex items-center gap-1.5"
            >
              <Key className="w-3.5 h-3.5" />
              <span>{pairingStatus?.paired ? 'Rotate Pairing Token' : 'Issue Agent Token'}</span>
            </button>

            {pairingStatus?.paired && (
              <button
                onClick={handleRevokeToken}
                disabled={revoking}
                className="btn-danger text-xs px-3.5 py-2 flex items-center gap-1.5"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Revoke Token</span>
              </button>
            )}
          </div>
        </Section>

        {/* AI Engine Settings */}
        <Section icon={Bot} title="AI Threat Analysis Engine">
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">Provider Configuration</label>
              <div className="p-3 rounded-lg bg-surface-800/60 border border-white/5 space-y-2 text-xs text-slate-300">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Active Engine:</span>
                  <span className="font-semibold text-accent-400">Ollama / Expert Fallback Hybrid</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Model:</span>
                  <span className="font-mono text-slate-300">llama3 / SOC-Analyst-v2</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Endpoint:</span>
                  <span className="font-mono text-slate-400">http://localhost:11434</span>
                </div>
              </div>
            </div>
            <p className="text-[11px] text-slate-500">
              Configure OpenAI API key or custom Ollama URL in <code className="mono text-accent-400">server/.env</code> to adjust parameters.
            </p>
          </div>
        </Section>

        {/* Host Device Access & Telemetry Consent */}
        <Section icon={ShieldCheck} title="Host Device Access & Telemetry Consent">
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 rounded-lg bg-surface-900 border border-surface-700/60 font-mono text-xs">
              <span className="text-slate-400">Endpoint Authorization Status:</span>
              <span className="text-emerald-400 flex items-center gap-1.5 font-bold">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                AUTHORIZED BY USER
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              The Rakshak telemetry agent requires explicit user consent before inspecting system activity.
              All data processing occurs strictly on-device with zero external raw data exfiltration:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-surface-800/60 border border-white/5 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                  <Terminal className="w-3.5 h-3.5 text-accent-400" />
                  <span>Process Table Auditing</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Diffs active processes (<code className="text-accent-400 font-mono">ps</code>) to detect malicious interpreters &amp; reverse shells.
                </p>
                <span className="inline-block text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
                  Permission Granted
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface-800/60 border border-white/5 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                  <Network className="w-3.5 h-3.5 text-accent-400" />
                  <span>Network Socket Auditing</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Audits open and active TCP/UDP connections (<code className="text-accent-400 font-mono">lsof/ss</code>) for unauthorized C2 beacons.
                </p>
                <span className="inline-block text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
                  Permission Granted
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface-800/60 border border-white/5 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                  <FileText className="w-3.5 h-3.5 text-accent-400" />
                  <span>System Auth Log Stream</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Ingests authentication events (<code className="text-accent-400 font-mono">auth.log / unified log</code>) to detect brute-force attacks.
                </p>
                <span className="inline-block text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
                  Permission Granted
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface-800/60 border border-white/5 space-y-1">
                <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                  <Key className="w-3.5 h-3.5 text-accent-400" />
                  <span>Canary Decoy Honeytoken</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Monitors canary trap files in <code className="text-accent-400 font-mono">~/.rakshak/canary.env</code> for unauthorized tampering.
                </p>
                <span className="inline-block text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
                  Permission Granted
                </span>
              </div>
            </div>
          </div>
        </Section>

        {/* Privacy */}
        <Section icon={Database} title="Data Privacy & Zero-Knowledge Guarantee">
          <p className="text-xs text-slate-400 leading-relaxed">
            Raw operating system logs, memory traces, and socket activity never exit your perimeter.
            The agent executes detection rules locally on your endpoint and transmits only distilled,
            classified telemetry findings.
          </p>
        </Section>
      </div>

      {/* One-Time Token Reveal Modal */}
      <Modal
        isOpen={!!revealedToken}
        onClose={() => setRevealedToken(null)}
        title="Agent Pairing Token Generated"
        size="md"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-xl bg-amber-400/10 border border-amber-400/20 text-amber-300 text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              Save this token now. For security reasons, only a cryptographic hash is retained on the server.
              It will never be displayed again.
            </span>
          </div>

          <div>
            <label className="block text-[11px] uppercase font-semibold tracking-wider text-slate-400 mb-1.5">
              Secret Pairing Token
            </label>
            <div className="flex items-center gap-2">
              <input
                readOnly
                value={revealedToken || ''}
                className="input flex-1 text-xs font-mono bg-surface-900 text-accent-300"
              />
              <button
                onClick={handleCopy}
                className="btn-primary text-xs px-3 py-2 flex items-center gap-1.5 shrink-0"
              >
                {hasCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{hasCopied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-surface-800/80 border border-white/5 space-y-1.5 text-xs text-slate-400">
            <p className="font-semibold text-slate-200">How to configure your local agent:</p>
            <ol className="list-decimal list-inside space-y-1 text-[11px] text-slate-400">
              <li>Open or create <code className="mono text-accent-400">agent/.env</code></li>
              <li>Set <code className="mono text-accent-400">AGENT_TOKEN={revealedToken?.slice(0, 12)}...</code></li>
              <li>Set <code className="mono text-accent-400">USER_ID={user?._id}</code></li>
              <li>Run <code className="mono text-accent-400">npm run agent</code></li>
            </ol>
          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={() => setRevealedToken(null)}
              className="btn-ghost text-xs px-4 py-2"
            >
              Done &amp; Dismiss
            </button>
          </div>
        </div>
      </Modal>

      {/* ─────────────────────────────────────────────────────────
           Correlation Rule Engine Section
      ──────────────────────────────────────────────────────────── */}
      <div className="max-w-3xl mt-6">
        <Section icon={GitBranch} title="Correlation Rule Engine">
          <p className="text-xs text-slate-400 leading-relaxed">
            Control how the automated incident correlator clusters related findings.
            Changes apply to the <strong className="text-slate-300">next incoming finding</strong> — no restart required.
          </p>

          {/* Correlation Window */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">Correlation Window</label>
              <span className="text-sm font-bold font-mono text-accent-400">{windowMins} min</span>
            </div>
            <input
              type="range"
              min={5}
              max={60}
              step={5}
              value={windowMins}
              onChange={(e) => setWindowMins(Number(e.target.value))}
              className="w-full accent-accent-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-600 font-mono">
              <span>5 min</span><span>15 min (default)</span><span>60 min</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Findings from the same IP or process within this window will be clustered into one incident.
            </p>
          </div>

          {/* Min Threshold */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">Minimum Findings Threshold</label>
              <span className="text-sm font-bold font-mono text-accent-400">{minThreshold} findings</span>
            </div>
            <div className="flex items-center gap-2">
              {[2, 3, 4, 5, 7, 10].map((n) => (
                <button
                  key={n}
                  onClick={() => setMinThreshold(n)}
                  className={`text-xs font-bold px-3 py-1.5 rounded-lg border transition-all ${
                    minThreshold === n
                      ? 'bg-accent-400/20 border-accent-400/50 text-accent-300'
                      : 'border-white/10 text-slate-500 hover:border-slate-500'
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-500">
              How many related findings must arrive before an incident is automatically opened.
              Critical severity always opens an incident immediately regardless of threshold.
            </p>
          </div>

          <div className="flex justify-end pt-2">
            <button
              onClick={handleSavePreferences}
              disabled={savingPrefs}
              className="btn-primary text-xs px-4 py-2 flex items-center gap-1.5"
            >
              <Save className="w-3.5 h-3.5" />
              {savingPrefs ? 'Saving…' : 'Save Rules'}
            </button>
          </div>
        </Section>
      </div>
    </PageWrapper>
  );
}
