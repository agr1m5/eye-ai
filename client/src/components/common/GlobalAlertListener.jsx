/**
 * GlobalAlertListener.jsx — Real-time SOC Critical Alerts & Notifications.
 *
 * Subscribes to global Socket.IO events and triggers actionable notifications:
 *   - Critical Threat Detections -> High-priority security toast
 *   - Correlated Incidents Opened -> Incident alert toast with direct navigation
 */
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useSocket } from '@/context/SocketContext';
import { AlertOctagon, GitBranch, ArrowRight, ShieldCheck } from 'lucide-react';

export default function GlobalAlertListener() {
  const { subscribe } = useSocket();
  const navigate = useNavigate();
  const hasAnnouncedAgentRef = useRef(false);

  useEffect(() => {
    // 1. Critical threat alerts
    const unsubFinding = subscribe('finding:new', (threat) => {
      if (threat?.severity === 'critical') {
        // Native desktop notification if running inside desktop app
        window.electronAPI?.showNotification({
          title: `CRITICAL THREAT: ${threat.type}`,
          body: threat.description || `Source: ${threat.source?.ip || 'Local Host'}`,
        });

        toast.custom((t) => (
          <div
            className={`${
              t.visible ? 'animate-enter' : 'animate-leave'
            } max-w-md w-full bg-red-950/90 border border-red-500/50 shadow-2xl shadow-red-950/50 rounded-xl pointer-events-auto flex ring-1 ring-black ring-opacity-5 p-3.5 backdrop-blur-md`}
          >
            <div className="flex-1 w-0">
              <div className="flex items-start gap-2.5">
                <div className="p-1 rounded bg-red-500/20 text-red-400 mt-0.5">
                  <AlertOctagon className="w-4 h-4 animate-pulse" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-red-400 font-mono">
                      Critical Detection
                    </span>
                    {threat.source?.ip && (
                      <span className="text-[10px] font-mono text-slate-400">
                        {threat.source.ip}
                      </span>
                    )}
                  </div>
                  <p className="text-xs font-semibold text-slate-100 mt-0.5 line-clamp-1">
                    {threat.type}
                  </p>
                  <p className="text-[11px] text-slate-300 mt-0.5 line-clamp-1">
                    {threat.description || 'Immediate analyst response required.'}
                  </p>
                </div>
              </div>
            </div>
            <div className="flex border-l border-red-500/20 pl-2 ml-2 items-center">
              <button
                onClick={() => {
                  toast.dismiss(t.id);
                  navigate('/threats');
                }}
                className="btn-ghost text-xs text-red-300 hover:text-white flex items-center gap-1 py-1 px-2 hover:bg-red-500/20"
              >
                <span>Triage</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        ), { duration: 8000 });
      }
    });

    // 2. Correlated Incident Alerts
    const unsubIncident = subscribe('incident:new', (incident) => {
      // Native desktop notification if running inside desktop app
      window.electronAPI?.showNotification({
        title: `INCIDENT OPENED: ${incident?.title || 'Security Incident'}`,
        body: incident?.summary || 'Correlated security incident requires investigation.',
      });

      toast.custom((t) => (
        <div
          className={`${
            t.visible ? 'animate-enter' : 'animate-leave'
          } max-w-md w-full bg-orange-950/90 border border-orange-500/50 shadow-2xl shadow-orange-950/50 rounded-xl pointer-events-auto flex ring-1 ring-black ring-opacity-5 p-3.5 backdrop-blur-md`}
        >
          <div className="flex-1 w-0">
            <div className="flex items-start gap-2.5">
              <div className="p-1 rounded bg-orange-500/20 text-orange-400 mt-0.5">
                <GitBranch className="w-4 h-4 animate-pulse" />
              </div>
              <div className="flex-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-orange-400 font-mono">
                  New Incident Opened
                </span>
                <p className="text-xs font-semibold text-slate-100 mt-0.5 line-clamp-1">
                  {incident.title}
                </p>
                <p className="text-[11px] text-slate-300 mt-0.5 line-clamp-1">
                  {incident.summary || 'Correlated cluster requires triage.'}
                </p>
              </div>
            </div>
          </div>
          <div className="flex border-l border-orange-500/20 pl-2 ml-2 items-center">
            <button
              onClick={() => {
                toast.dismiss(t.id);
                navigate('/incidents');
              }}
              className="btn-ghost text-xs text-orange-300 hover:text-white flex items-center gap-1 py-1 px-2 hover:bg-orange-500/20"
            >
              <span>Inspect</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      ), { duration: 9000 });
    });

    // 3. Agent status connection alert
    const unsubAgent = subscribe('agent:status', ({ connected }) => {
      if (connected && !hasAnnouncedAgentRef.current) {
        hasAnnouncedAgentRef.current = true;
        toast((t) => (
          <div className="flex items-center gap-2 text-xs text-emerald-300">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Telemetry agent online & streaming</span>
          </div>
        ), { id: 'agent-online-toast', duration: 4000 });
      }
    });

    return () => {
      unsubFinding();
      unsubIncident();
      unsubAgent();
    };
  }, [subscribe, navigate]);

  return null;
}
