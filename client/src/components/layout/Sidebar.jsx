/**
 * Sidebar — the main navigation rail.
 *
 * Renders:
 *  - Eye Live brand mark
 *  - Live agent status badge
 *  - Primary nav links (Dashboard, Threats, Incidents, Chat, Reports, Log Import)
 *  - Bottom section: Settings, Logout
 *
 * The `active` state is derived from React Router's `useLocation` so no prop
 * drilling is needed — each link knows whether it's current.
 */
import { useState, useEffect } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import {
  ShieldCheck, LayoutDashboard, Skull, GitBranch,
  MessageSquare, FileText, Upload, Settings, LogOut,
  Wifi, WifiOff, Crosshair, Target, ClipboardList, Activity, Zap,
  Power, Loader2, ChevronDown, ChevronRight,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { useAuth } from '@/context/AuthContext';
import { useSocket } from '@/context/SocketContext';
import { authApi } from '@/services/api';
import { formatDistanceToNow } from 'date-fns';

/* ── Nav link definitions ───────────────────────────────────── */
const PRIMARY_ITEMS = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'      },
  { to: '/threats',    icon: Skull,           label: 'Threats'        },
  { to: '/incidents',  icon: GitBranch,       label: 'Incidents'      },
  { to: '/defense',    icon: Zap,             label: 'Active Defense' },
];

const SECONDARY_ITEMS = [
  { to: '/activity',   icon: Activity,        label: 'Host Activity'  },
  { to: '/chat',       icon: MessageSquare,   label: 'AI Chat'        },
  { to: '/reports',    icon: FileText,        label: 'Reports'        },
  { to: '/import',     icon: Upload,          label: 'Log Import'     },
  { to: '/hunt',       icon: Crosshair,       label: 'Threat Hunt'    },
  { to: '/mitre',      icon: Target,          label: 'MITRE Matrix'   },
];

export default function Sidebar() {
  const { logout } = useAuth();
  const { agentOnline, setAgentOnline, agentLastSeen, connected } = useSocket();
  const navigate = useNavigate();
  const location = useLocation();
  const [toggling, setToggling] = useState(false);

  // Check if current route is inside the secondary items
  const isSecondaryActive = SECONDARY_ITEMS.some(
    (item) => location.pathname === item.to || location.pathname.startsWith(`${item.to}/`)
  );

  const [moreExpanded, setMoreExpanded] = useState(() => {
    // If user lands directly on a secondary route, auto-expand
    if (typeof window !== 'undefined' && SECONDARY_ITEMS.some((item) => window.location.pathname === item.to || window.location.pathname.startsWith(`${item.to}/`))) {
      return true;
    }
    const saved = typeof window !== 'undefined' ? localStorage.getItem('eye_sidebar_more_expanded') : null;
    return saved === 'true';
  });

  // Auto-expand if user navigates to a secondary route
  useEffect(() => {
    if (isSecondaryActive && !moreExpanded) {
      setMoreExpanded(true);
      localStorage.setItem('eye_sidebar_more_expanded', 'true');
    }
  }, [isSecondaryActive]);

  const toggleMore = () => {
    setMoreExpanded((prev) => {
      const next = !prev;
      localStorage.setItem('eye_sidebar_more_expanded', String(next));
      return next;
    });
  };

  const handleToggleAgent = async (forcedState) => {
    if (toggling) return;
    const targetState = typeof forcedState === 'boolean' ? forcedState : !agentOnline;
    setToggling(true);
    try {
      const { data } = await authApi.toggleAgent(targetState);
      if (targetState) {
        if (data?.data?.connected && setAgentOnline) {
          setAgentOnline(true);
        }
        toast.success('Agent activated & permissions granted');
      } else {
        if (setAgentOnline) setAgentOnline(false);
        toast.success('Agent monitoring paused');
      }
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to toggle agent');
    } finally {
      setToggling(false);
    }
  };

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
          <h1 className="text-sm font-bold text-slate-100 leading-tight">Eye Live</h1>
          <p className="text-[10px] text-slate-500 leading-tight">Security Operations Center</p>
        </div>
      </div>

      {/* ── Agent status card ────────────────────────────────── */}
      <div className="mx-3 mt-4 p-3 rounded-lg bg-surface-800/60 border border-white/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {agentOnline ? (
              <Wifi className="w-3.5 h-3.5 text-accent-400 shrink-0" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-slate-500 shrink-0" />
            )}
            <span className={`text-xs font-semibold ${agentOnline ? 'text-accent-400' : 'text-slate-500'}`}>
              Agent {agentOnline ? 'Online' : 'Offline'}
            </span>
          </div>

          {/* Quick Toggle Switch */}
          <button
            type="button"
            role="switch"
            aria-checked={agentOnline}
            onClick={() => handleToggleAgent()}
            disabled={toggling}
            title={agentOnline ? 'Click to turn off agent' : 'Click to turn on agent'}
            className={`relative inline-flex h-4 w-7 shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
              agentOnline ? 'bg-emerald-500' : 'bg-surface-700'
            } ${toggling ? 'opacity-50 cursor-wait' : ''}`}
          >
            <span
              className={`pointer-events-none inline-block h-3 w-3 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                agentOnline ? 'translate-x-3' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        {agentLastSeen && (
          <p className="text-[10px] text-slate-500 mt-1 ml-5">
            Last seen {formatDistanceToNow(agentLastSeen, { addSuffix: true })}
          </p>
        )}

        {/* Prominent Turn On Button when Agent is Offline */}
        {!agentOnline && (
          <button
            onClick={() => handleToggleAgent(true)}
            disabled={toggling}
            className="mt-2.5 w-full flex items-center justify-center gap-1.5 py-1.5 px-2 rounded-md bg-accent-500/10 hover:bg-accent-500/20 text-accent-400 border border-accent-500/30 text-[11px] font-semibold transition-all shadow-sm"
          >
            {toggling ? (
              <Loader2 className="w-3 h-3 animate-spin" />
            ) : (
              <Power className="w-3 h-3" />
            )}
            {toggling ? 'Starting Agent...' : 'Turn On Agent'}
          </button>
        )}
      </div>

      {/* ── Primary Navigation ───────────────────────────────── */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {/* Primary Navigation (Always Visible) */}
        {PRIMARY_ITEMS.map(({ to, icon: Icon, label }) => (
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

        {/* Secondary Navigation (Collapsible Disclosure) */}
        <div className="pt-2">
          <button
            type="button"
            onClick={toggleMore}
            aria-expanded={moreExpanded}
            aria-controls="secondary-nav"
            className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-lg transition-colors group cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent-400/50"
          >
            <span className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wider text-slate-500 group-hover:text-slate-400 font-semibold">
                More Tools
              </span>
              {isSecondaryActive && !moreExpanded && (
                <span className="w-1.5 h-1.5 rounded-full bg-accent-400 animate-pulse" title="Active destination inside" />
              )}
            </span>
            {moreExpanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-300 transition-transform" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-300 transition-transform" />
            )}
          </button>

          {moreExpanded && (
            <div id="secondary-nav" className="mt-1 space-y-0.5 pl-1 border-l border-white/5 ml-2.5 animate-fade-in">
              {SECONDARY_ITEMS.map(({ to, icon: Icon, label }) => (
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
            </div>
          )}
        </div>
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
