/**
 * ThreatDetailDrawer.jsx — Slide-in side panel for full threat details
 * with integrated Threat Intelligence (VirusTotal IP lookup + MITRE ATT&CK mapping).
 *
 * Props:
 *   threat   {object|null} — Threat document, or null to close
 *   onClose  {function}    — close callback
 *   onDismiss {function}   — dismiss threat callback
 *   onAck     {function}   — acknowledge threat callback
 */
import { useState, useEffect } from 'react';
import { format } from 'date-fns';
import {
  X,
  Cpu,
  Globe,
  Terminal,
  Hash,
  Calendar,
  Tag,
  AlertOctagon,
  ShieldCheck,
  ShieldAlert,
  Search,
  BookOpen,
  ExternalLink,
  Loader2,
  Filter,
  Flame,
  Target,
  Lock,
  Zap,
  Crosshair,
  Briefcase,
} from 'lucide-react';
import SeverityBadge from '@/components/common/SeverityBadge';
import { tiApi } from '@/services/api';
import { getHumanThreat, getHumanSource, getHumanStatus } from '@/utils/threatFormatter';

function Field({ label, value, mono = false }) {
  if (!value) return null;
  return (
    <div className="space-y-0.5">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">{label}</p>
      <p className={`text-xs text-slate-300 ${mono ? 'font-mono' : ''} break-all`}>{value}</p>
    </div>
  );
}

function inferMitreId(type = '') {
  const t = type.toLowerCase();
  if (t.includes('port scan') || t.includes('scan')) return 'T1046';
  if (t.includes('brute') || t.includes('login')) return 'T1110';
  if (t.includes('command') || t.includes('powershell') || t.includes('bash')) return 'T1059';
  if (t.includes('sql') || t.includes('xss') || t.includes('injection')) return 'T1190';
  if (t.includes('ransom')) return 'T1486';
  if (t.includes('c2') || t.includes('malware')) return 'T1071';
  if (t.includes('privilege') || t.includes('root')) return 'T1068';
  return null;
}

function CiaPillar({ label, level, description, icon: Icon }) {
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
    <div className="p-3 rounded-xl bg-surface-950/80 border border-white/5 flex flex-col justify-between space-y-2">
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
        {description}
      </p>
    </div>
  );
}

function getDeviceThreatImpact(threat) {
  if (!threat) return null;
  const type = (threat.type || '').toLowerCase();
  const sev = (threat.severity || 'high').toUpperCase();

  if (type.includes('ransom')) {
    return {
      severity: 'CRITICAL',
      blastRadius: 'Host Filesystem & Local Storage Volumes',
      containmentUrgency: 'Immediate Endpoint Isolation',
      cia: {
        confidentiality: { level: 'Medium', description: 'Adversary scanning user files for high-value documents before encryption.' },
        integrity: { level: 'Critical', description: 'Mass unrecoverable file encryption and Volume Shadow Copy deletion.' },
        availability: { level: 'Critical', description: 'Full denial of local endpoint services and application access.' },
      },
      consequences: [
        'Mass cryptographic locking of user workspace, projects, and documents.',
        'Deletion of local OS recovery points and Volume Shadow Copies.',
        'Extortion attempt demanding cryptocurrency for decryption keys.',
        'Potential lateral spread across connected network shares and mapped drives.',
      ],
      businessRisk: 'Catastrophic endpoint operational outage and permanent data loss without backups.',
    };
  }

  if (type.includes('command') || type.includes('injection') || type.includes('shell')) {
    return {
      severity: 'CRITICAL',
      blastRadius: 'Process Memory & Shell Subsystem',
      containmentUrgency: 'Immediate PID Termination & Network Block',
      cia: {
        confidentiality: { level: 'High', description: 'Adversary can read local environment secrets, AWS/API keys, and bash history.' },
        integrity: { level: 'High', description: 'Arbitrary bash command execution and unauthorized script creation.' },
        availability: { level: 'Medium', description: 'Host can be commandeered for secondary cryptomining or DDoS attacks.' },
      },
      consequences: [
        'Interactive remote shell established to external adversary C2 server.',
        'Credential harvesting from /etc/passwd, ~/.ssh, and keychain files.',
        'Privilege escalation attempt targeting root/sudo binaries.',
        'Background deployment of secondary malicious payloads and rootkits.',
      ],
      businessRisk: 'Complete device takeover; high risk of credential exposure and compliance penalties.',
    };
  }

  if (type.includes('honeytoken') || type.includes('credential')) {
    return {
      severity: 'HIGH',
      blastRadius: 'Host Credential Store & User Environment',
      containmentUrgency: 'Rotate Compromised Secrets Immediately',
      cia: {
        confidentiality: { level: 'High', description: 'Direct unauthorized access to sensitive decoys, tokens, or API credentials.' },
        integrity: { level: 'Medium', description: 'Attacker may use stolen credentials to modify cloud or database assets.' },
        availability: { level: 'Low', description: 'Minimal direct disruption to local host CPU/memory.' },
      },
      consequences: [
        'Adversary actively hunting for secrets in local file directories.',
        'Compromised credentials can be replayed against production cloud APIs.',
        'Tripwire triggered: indicates host has an active intruder or rogue process.',
      ],
      businessRisk: 'Imminent breach of connected cloud accounts and internal production infrastructure.',
    };
  }

  if (type.includes('sql') || type.includes('database')) {
    return {
      severity: 'HIGH',
      blastRadius: 'Application Data Tier & Local Database Sockets',
      containmentUrgency: 'Apply WAF Rule & Patch Query Bindings',
      cia: {
        confidentiality: { level: 'High', description: 'Exfiltration of sensitive customer records, password hashes, and PII.' },
        integrity: { level: 'High', description: 'Unauthorized database table updates, drops, or admin account injection.' },
        availability: { level: 'Medium', description: 'Resource exhaustion on local database engine through heavy union queries.' },
      },
      consequences: [
        'Unauthorized exfiltration of user tables and password hashes.',
        'Database tampering or administrative privilege grant injection.',
        'Potential xp_cmdshell / UDF execution leading to host shell compromise.',
      ],
      businessRisk: 'Major data breach liability under GDPR/CCPA and mandatory regulatory notification.',
    };
  }

  return {
    severity: sev,
    blastRadius: 'Endpoint Host Subsystem',
    containmentUrgency: sev === 'CRITICAL' ? 'Immediate Containment' : 'Investigate & Quarantine',
    cia: {
      confidentiality: { level: sev === 'CRITICAL' ? 'High' : 'Medium', description: 'Potential exposure of host memory and local user data.' },
      integrity: { level: sev === 'CRITICAL' ? 'High' : 'Medium', description: 'Potential file or registry configuration tampering.' },
      availability: { level: sev === 'CRITICAL' ? 'Medium' : 'Low', description: 'Host process disruption or elevated background resource usage.' },
    },
    consequences: [
      'Anomalous behavior detected by host endpoint monitoring sensors.',
      'Potential unauthorized execution or lateral network communication.',
      'Investigation required to determine adversary intent and root cause.',
    ],
    businessRisk: 'Elevated security risk requiring triage to prevent escalation.',
  };
}

export default function ThreatDetailDrawer({ threat, onClose, onDismiss, onAck, onFilterType }) {
  const [ipData, setIpData] = useState(null);
  const [loadingIp, setLoadingIp] = useState(false);
  const [ipError, setIpError] = useState(null);

  const [mitreData, setMitreData] = useState(null);
  const [loadingMitre, setLoadingMitre] = useState(false);

  // Reset TI state when drawer threat changes
  useEffect(() => {
    setIpData(null);
    setIpError(null);
    setMitreData(null);
  }, [threat?._id]);

  if (!threat) return null;

  const raw = threat.rawData
    ? (typeof threat.rawData === 'string' ? threat.rawData : JSON.stringify(threat.rawData, null, 2))
    : null;

  const sourceIp = threat.source?.ip;
  const inferredMitre = inferMitreId(threat.type);

  const handleLookupIP = async () => {
    if (!sourceIp || loadingIp) return;
    setLoadingIp(true);
    setIpError(null);
    try {
      const res = await tiApi.ip(sourceIp);
      setIpData(res.data);
    } catch (err) {
      setIpError(err.response?.data?.message || 'Failed to fetch threat intelligence');
    } finally {
      setLoadingIp(false);
    }
  };

  const handleLookupMitre = async () => {
    if (!inferredMitre || loadingMitre) return;
    setLoadingMitre(true);
    try {
      const res = await tiApi.mitre(inferredMitre);
      setMitreData(res.data?.data);
    } catch (err) {
      console.error('Failed to lookup MITRE info:', err);
    } finally {
      setLoadingMitre(false);
    }
  };

  const human = getHumanThreat(threat.type, threat);
  const humanSource = getHumanSource(threat.source);
  const statusInfo = getHumanStatus(threat.status);
  const deviceImpact = getDeviceThreatImpact(threat);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div
        className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-surface-900 border-l border-white/5
                   shadow-2xl flex flex-col animate-[slideInRight_0.22s_ease-out]"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-white/5">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-accent-400" />
            <h2 className="text-base font-semibold text-slate-100">Threat Investigation & Analysis</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Severity + Title */}
          <div className="glass-card p-4 rounded-xl border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <SeverityBadge severity={threat.severity} />
              <span className={`text-xs font-medium px-2.5 py-0.5 rounded-full border ${statusInfo.color}`}>
                {statusInfo.label}
              </span>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">{human.title}</h3>
              <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{human.subtitle}</p>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-white/5 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <span>Code: <strong className="text-slate-400">{threat.type}</strong></span>
                <span>·</span>
                <span>Event ID: {threat._id}</span>
              </div>
              {onFilterType && (
                <button
                  type="button"
                  onClick={() => onFilterType(threat.type)}
                  className="flex items-center gap-1 text-[11px] font-sans font-medium text-brand-400 hover:text-brand-300 transition-colors"
                >
                  <Filter className="w-3 h-3" />
                  <span>Filter all of this type</span>
                </button>
              )}
            </div>
          </div>

          {/* Plain-English "What Happened" Card */}
          <div className="glass-card p-4 rounded-xl border border-cyan-500/20 bg-cyan-950/10 space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
              💡 What Happened & Why This Triggered
            </p>
            <p className="text-xs text-slate-300 leading-relaxed">
              {human.whatHappened}
            </p>
          </div>

          {/* ── Impact of Attack on This Device ──────────────── */}
          {deviceImpact && (
            <div className="glass-card p-4 rounded-xl border border-rose-500/30 bg-gradient-to-br from-rose-950/20 via-surface-900 to-surface-900 space-y-3.5 shadow-xl">
              <div className="flex items-center justify-between pb-2.5 border-b border-white/5">
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded-lg border ${
                    deviceImpact.severity === 'CRITICAL' || deviceImpact.severity === 'HIGH'
                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  }`}>
                    <Flame className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                      Impact of Attack on This Device
                    </h4>
                    <span className="text-[10px] text-slate-400">Host Blast Radius & CIA Compromise Analysis</span>
                  </div>
                </div>
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                  deviceImpact.severity === 'CRITICAL' || deviceImpact.severity === 'HIGH'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                }`}>
                  {deviceImpact.severity} Impact
                </span>
              </div>

              {/* Host Blast Radius & Containment Urgency */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-surface-950/80 border border-white/5">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                    Host Blast Radius
                  </span>
                  <div className="flex items-center gap-1.5 mt-1 text-slate-200 font-medium text-xs">
                    <Target className="w-3.5 h-3.5 text-accent-400 shrink-0" />
                    <span className="truncate" title={deviceImpact.blastRadius}>{deviceImpact.blastRadius}</span>
                  </div>
                </div>
                <div className="p-2.5 rounded-lg bg-surface-950/80 border border-white/5">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400 block font-semibold">
                    Containment Urgency
                  </span>
                  <div className="flex items-center gap-1.5 mt-1 text-slate-200 font-medium text-xs">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span className="truncate" title={deviceImpact.containmentUrgency}>{deviceImpact.containmentUrgency}</span>
                  </div>
                </div>
              </div>

              {/* CIA Triad Breakdown */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] font-semibold text-slate-300">
                  <span className="flex items-center gap-1.5">
                    <Lock className="w-3 h-3 text-slate-400" />
                    CIA Triad Exposure Breakdown
                  </span>
                  <span className="text-[10px] text-slate-500">Confidentiality • Integrity • Availability</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <CiaPillar
                    label="Confidentiality"
                    level={deviceImpact.cia?.confidentiality?.level}
                    description={deviceImpact.cia?.confidentiality?.description}
                    icon={Lock}
                  />
                  <CiaPillar
                    label="Integrity"
                    level={deviceImpact.cia?.integrity?.level}
                    description={deviceImpact.cia?.integrity?.description}
                    icon={ShieldAlert}
                  />
                  <CiaPillar
                    label="Availability"
                    level={deviceImpact.cia?.availability?.level}
                    description={deviceImpact.cia?.availability?.description}
                    icon={Zap}
                  />
                </div>
              </div>

              {/* Threat Consequences on Host */}
              {deviceImpact.consequences && deviceImpact.consequences.length > 0 && (
                <div className="p-3 rounded-xl bg-surface-950/80 border border-white/5 space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
                    <Crosshair className="w-3.5 h-3.5 text-rose-400" />
                    Worst-Case Consequences on This Device
                  </div>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {deviceImpact.consequences.map((c, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-rose-400 font-bold mt-0.5 text-xs">›</span>
                        <span className="text-[11px] text-slate-300 leading-snug">{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Business & Host Damage */}
              {deviceImpact.businessRisk && (
                <div className="p-2.5 rounded-lg bg-surface-950/70 border border-white/5 flex items-start gap-2">
                  <Briefcase className="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    <span className="font-semibold text-slate-300">Operational Risk: </span>
                    {deviceImpact.businessRisk}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Description if present */}
          {threat.description && (
            <div className="glass-card p-3 rounded-xl border border-white/5">
              <p className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Sensor Log Excerpt</p>
              <p className="text-xs text-slate-300 font-mono leading-relaxed whitespace-pre-wrap">
                {threat.description}
              </p>
            </div>
          )}

          {/* Origin & Location */}
          <div className="glass-card p-4 rounded-xl border border-white/5 space-y-2.5">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Origin & Telemetry</p>
            <div className="flex items-center gap-2 text-xs text-slate-200">
              <Globe className="w-4 h-4 text-accent-400 shrink-0" />
              <span className="font-medium">{humanSource}</span>
            </div>
            <div className="grid grid-cols-2 gap-2 pt-1 border-t border-white/5 text-xs text-slate-400">
              {threat.source?.hostname && (
                <div>Host: <span className="text-slate-200 font-mono">{threat.source.hostname}</span></div>
              )}
              {threat.source?.processName && (
                <div>Process: <span className="text-slate-200 font-mono">{threat.source.processName}</span></div>
              )}
              {threat.source?.pid && (
                <div>PID: <span className="text-slate-200 font-mono">{threat.source.pid}</span></div>
              )}
              {threat.source?.port && (
                <div>Port: <span className="text-slate-200 font-mono">:{threat.source.port}</span></div>
              )}
            </div>
          </div>

          {/* Threat Classification & MITRE ATT&CK in Plain English */}
          <div className="glass-card p-4 rounded-xl border border-purple-500/20 bg-purple-950/10 space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                  <BookOpen className="w-3.5 h-3.5 text-purple-400" />
                  <span>Attack Classification (MITRE ATT&CK)</span>
                </div>
                {!mitreData && (
                  <button
                    onClick={handleLookupMitre}
                    disabled={loadingMitre}
                    className="text-[11px] text-accent-400 hover:underline flex items-center gap-1 font-medium"
                  >
                    {loadingMitre ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Read Full Playbook'}
                  </button>
                )}
              </div>
              <div className="mt-2 text-xs">
                <p className="font-semibold text-purple-200">
                  {human.mitreName} <span className="font-mono text-accent-400">({inferredMitre || human.mitreCode})</span>
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Tactic: <strong className="text-slate-300">{human.tactic}</strong>
                </p>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                  {human.mitrePlain}
                </p>
              </div>
            </div>

            {/* In-depth MITRE info if fetched */}
            {mitreData && (
              <div className="p-3 rounded-lg bg-surface-900 border border-white/10 space-y-2 text-xs">
                <p className="text-slate-300 leading-relaxed text-[11px]">{mitreData.description}</p>
                {mitreData.detection && (
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-white/5">
                    <span className="font-semibold text-accent-400">Detection Guideline: </span>
                    {mitreData.detection}
                  </div>
                )}
                {mitreData.url && (
                  <a
                    href={mitreData.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] text-accent-400 hover:underline pt-1"
                  >
                    View Official MITRE Encyclopedia <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            )}
          </div>

          {/* Recommended Response */}
          <div className="glass-card p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
              🛡️ Recommended Action
            </p>
            <p className="text-xs text-slate-300 leading-relaxed">
              {human.remediation}
            </p>
          </div>

          {/* External IP Reputation if public IP present */}
          {sourceIp && (
            <div className="glass-card p-4 rounded-xl border border-surface-700/60 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs text-slate-300">
                  <Search className="w-3.5 h-3.5 text-accent-400" />
                  <span>Public IP Threat Reputation</span>
                </div>
                {!ipData && (
                  <button
                    onClick={handleLookupIP}
                    disabled={loadingIp}
                    className="text-[11px] text-accent-400 hover:underline"
                  >
                    {loadingIp ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Check VirusTotal'}
                  </button>
                )}
              </div>
              {ipData && (
                <div className="grid grid-cols-3 gap-2 text-center text-xs pt-1">
                  <div className="p-2 rounded bg-surface-800 border border-red-500/20">
                    <p className="text-[10px] text-red-400">Malicious</p>
                    <p className="text-sm font-bold text-red-400 font-mono">{ipData.data?.malicious ?? 0}</p>
                  </div>
                  <div className="p-2 rounded bg-surface-800 border border-amber-500/20">
                    <p className="text-[10px] text-amber-400">Suspicious</p>
                    <p className="text-sm font-bold text-amber-400 font-mono">{ipData.data?.suspicious ?? 0}</p>
                  </div>
                  <div className="p-2 rounded bg-surface-800 border border-emerald-500/20">
                    <p className="text-[10px] text-emerald-400">Clean</p>
                    <p className="text-sm font-bold text-emerald-400 font-mono">{ipData.data?.harmless ?? 0}</p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Incident / Import Context */}
          <div className="space-y-1.5 text-xs text-slate-400">
            <div className="flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-slate-500" />
              <span>Detected: {threat.createdAt ? format(new Date(threat.createdAt), 'dd MMM yyyy, HH:mm:ss') : '—'}</span>
            </div>
            {threat.fromImport && (
              <div className="flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-slate-500" />
                <span className="text-[11px] text-slate-400">Extracted from offline log file</span>
              </div>
            )}
            {threat.incidentId && (
              <div className="p-3 rounded-xl bg-orange-950/20 border border-orange-500/30 space-y-1.5">
                <div className="flex items-center gap-1.5 text-orange-400">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span className="text-xs font-semibold text-orange-300">Correlated into Active Incident Cluster</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  This threat is linked to an active incident. Actions taken here (acknowledge, dismiss, or delete) automatically synchronize with the parent incident so you never need to repeat them on both.
                </p>
                <div className="pt-0.5">
                  <a
                    href="/incidents"
                    className="inline-flex items-center gap-1 text-[11px] text-brand-400 hover:text-brand-300 underline font-medium"
                  >
                    <span>View Correlated Incident</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            )}
          </div>

          {/* Raw data */}
          {raw && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Raw Telemetry Dump</p>
              <pre className="text-[10px] font-mono text-slate-400 bg-surface-800/80 border border-white/5
                              rounded-xl p-3 overflow-auto max-h-40 leading-relaxed">
                {raw}
              </pre>
            </div>
          )}
        </div>

        {/* Actions */}
        {threat.status !== 'dismissed' && (
          <div className="px-6 py-4 border-t border-white/5 flex gap-2">
            {threat.status !== 'acknowledged' && (
              <button
                onClick={() => { onAck(threat._id); onClose(); }}
                className="btn-ghost text-xs flex-1 text-amber-400 hover:border-amber-400/30"
              >
                Acknowledge
              </button>
            )}
            <button
              onClick={() => { onDismiss(threat._id); onClose(); }}
              className="btn-danger text-xs flex-1"
            >
              Dismiss
            </button>
          </div>
        )}
      </div>
    </>
  );
}
