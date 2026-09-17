/**
 * SocketContext — manages a single Socket.IO connection for the entire app.
 *
 * Why a context? Because multiple components (LiveEventFeed, AgentStatusBadge,
 * SeverityChart) need to subscribe to the same socket without creating
 * independent connections. The context creates one connection and exposes
 * the socket instance + a convenience `on/off` surface.
 *
 * The socket is lazily initialized when the user is authenticated (token exists).
 * It is destroyed on logout.
 *
 * Events we listen for (from architecture §5.2):
 *   finding:new     — a new Threat or CorrelatedIncident arrived
 *   agent:status    — agent connected / disconnected
 *   incident:updated — backend updated a correlated incident
 */
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useRef,
  useCallback,
} from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';
import { authApi } from '@/services/api';

const SocketContext = createContext(null);

export function SocketProvider({ children }) {
  const { token } = useAuth();
  const socketRef  = useRef(null);
  const [connected, setConnected]   = useState(false);
  const [agentOnline, setAgentOnline] = useState(false);
  const [agentLastSeen, setAgentLastSeen] = useState(null);
  const [agentMetrics, setAgentMetrics] = useState(null);

  // Initialize / teardown socket when auth token changes
  useEffect(() => {
    if (!token) {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
        setConnected(false);
      }
      setAgentOnline(false);
      return;
    }

    // Check initial agent connectivity status via REST
    authApi.getAgentStatus().then(({ data }) => {
      if (data?.status === 'success' && data.data) {
        if (typeof data.data.connected === 'boolean') {
          setAgentOnline(data.data.connected);
        }
      }
    }).catch(() => {});

    // Create connection with JWT in handshake auth
    const socket = io('/', {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });

    socketRef.current = socket;

    socket.on('connect',    () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));

    // Agent heartbeat / status events (§5.2)
    socket.on('agent:status', ({ connected: agentConn, lastSeen, metrics }) => {
      setAgentOnline(Boolean(agentConn));
      if (lastSeen) setAgentLastSeen(new Date(lastSeen));
      if (metrics) setAgentMetrics(metrics);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
      setConnected(false);
    };
  }, [token]);

  /**
   * subscribe — attach an event listener to the underlying socket.
   * Returns a cleanup function (for use in useEffect).
   *
   * Usage:
   *   useEffect(() => subscribe('finding:new', handler), []);
   */
  const subscribe = useCallback((event, handler) => {
    const s = socketRef.current;
    if (!s) return () => {};
    s.on(event, handler);
    return () => s.off(event, handler);
  }, []);

  const value = {
    socket: socketRef.current,
    connected,
    agentOnline,
    setAgentOnline,
    agentLastSeen,
    agentMetrics,
    subscribe,
  };


  return <SocketContext.Provider value={value}>{children}</SocketContext.Provider>;
}

export function useSocket() {
  const ctx = useContext(SocketContext);
  if (!ctx) throw new Error('useSocket must be used within a SocketProvider');
  return ctx;
}
