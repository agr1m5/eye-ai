/**
 * Sidebar — the main navigation rail.
 *
 * Renders:
 *  - Rakshak Live brand mark
 *  - Live agent status badge
 *  - Primary nav links (Dashboard, Threats, Incidents, Chat, Reports, Log Import)
 *  - Bottom section: Settings, Logout
 *
 * The `active` state is derived from React Router's `useLocation` so no prop
 * drilling is needed — each link knows whether it's current.
 */
import { NavLink, useNavigate } from 'react-router-dom';
import {
  ShieldCheck, LayoutDashboard, Skull, GitBranch,
  MessageSquare, FileText, Upload, Settings, LogOut,
  Radio, Wifi, WifiOff, Crosshair, Target, ClipboardList, Activity, Zap,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { useSocket } from '@/context/SocketContext';
import { formatDistanceToNow } from 'date-fns';

/* ── Nav link definitions ───────────────────────────────────── */
const NAV_ITEMS = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'     },
  { to: '/activity',   icon: Activity,        label: 'Host Activity' },
  { to: '/threats',    icon: Skull,           label: 'Threats'       },
  { to: '/incidents',  icon: GitBranch,       label: 'Incidents'     },
  { to: '/defense',    icon: Zap,             label: 'Active Defense' },
  { to: '/chat',       icon: MessageSquare,   label: 'AI Chat'       },
  { to: '/reports',    icon: FileText,        label: 'Reports'       },
  { to: '/import',     icon: Upload,          label: 'Log Import'    },
];

const INTEL_ITEMS = [
  { to: '/hunt',       icon: Crosshair,       label: 'Threat Hunt' },
  { to: '/mitre',      icon: Target,          label: 'MITRE Matrix' },
];

export default function Sidebar() {
  const { logout } = useAuth();
  const { agentOnline, agentLastSeen, connected } = useSocket();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <aside className="flex flex-col w-64 min-h-screen bg-surface-900 border-r border-white/5 shrink-0">

      {/* ── Brand ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-white/5">
        <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-accent-400/10 border border-accent-400/30">
          <ShieldCheck className="w-5 h-5 text-accent-400" />
          {/* Pulse ring when agent is online */}
          {agentOnline && (
            <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent-400 opacity-60" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent-400" />
            </span>
          )}
        </div>
        <div>
          <h1 className="text-sm font-bold text-slate-100 leading-tight">Rakshak Live</h1>
          <p className="text-[10px] text-slate-500 leading-tight">Security Operations Center</p>
        </div>
      </div>

      {/* ── Agent status card ────────────────────────────────── */}
      <div className="mx-3 mt-4 p-3 rounded-lg bg-surface-800/60 border border-white/5">
        <div className="flex items-center gap-2">
          {agentOnline ? (
            <Wifi className="w-3.5 h-3.5 text-accent-400 shrink-0" />
          ) : (
            <WifiOff className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          )}
          <span className={`text-xs font-semibold ${agentOnline ? 'text-accent-400' : 'text-slate-500'}`}>
            Agent {agentOnline ? 'Connected' : 'Offline'}
          </span>
          {connected && (
            <Radio className="w-3 h-3 text-slate-600 ml-auto" />
          )}
        </div>
        {agentLastSeen && (
          <p className="text-[10px] text-slate-600 mt-1 ml-5">
            Last seen {formatDistanceToNow(agentLastSeen, { addSuffix: true })}
          </p>
        )}
        {!agentOnline && !agentLastSeen && (
          <p className="text-[10px] text-slate-600 mt-1 ml-5">
            Start the agent to begin monitoring
          </p>
        )}
      </div>

      {/* ── Primary Navigation ───────────────────────────────── */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        <p className="section-heading px-2 mb-2">Operations</p>
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `nav-item ${isActive ? 'active' : ''}`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}

        <p className="section-heading px-2 mb-2 mt-4">Intelligence</p>
        {INTEL_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `nav-item ${isActive ? 'active' : ''}`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* ── Bottom: Audit + Settings + Logout ──────────────── */}
      <div className="px-3 py-4 border-t border-white/5 space-y-0.5">
        <NavLink
          to="/audit"
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <ClipboardList className="w-4 h-4 shrink-0" />
          Audit Log
        </NavLink>
        <NavLink
          to="/settings"
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <Settings className="w-4 h-4 shrink-0" />
          Settings
        </NavLink>
        <button
          onClick={handleLogout}
          className="nav-item w-full text-red-400/70 hover:text-red-400 hover:bg-red-500/10"
        >
          <LogOut className="w-4 h-4 shrink-0" />
          Logout
        </button>
      </div>
    </aside>
  );
}
