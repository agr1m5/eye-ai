/**
 * AuthContext — provides authentication state globally.
 *
 * Persists analyst session token and user profile in localStorage so
 * socket subscriptions and protected API calls survive page refreshes.
 */
import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import api from '@/services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const storedUser = localStorage.getItem('eye_user');
      return storedUser ? JSON.parse(storedUser) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(() => {
    try {
      const storedToken = localStorage.getItem('eye_token');
      if (storedToken) {
        api.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
      }
      return storedToken || null;
    } catch {
      return null;
    }
  });

  const [loading, setLoading] = useState(false);

  /**
   * login — calls POST /api/auth/login, stores returned JWT,
   * sets Axios header, and persists to localStorage.
   */
  const login = useCallback(async (email, password) => {
    setLoading(true);
    try {
      const { data } = await api.post('/auth/login', { email, password });
      setUser(data.user);
      setToken(data.token);
      localStorage.setItem('eye_user', JSON.stringify(data.user));
      localStorage.setItem('eye_token', data.token);
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      return data.user;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * signup — calls POST /api/auth/signup then auto-logs in.
   */
  const signup = useCallback(async (email, password) => {
    setLoading(true);
    try {
      await api.post('/auth/signup', { email, password });
      return login(email, password);
    } finally {
      setLoading(false);
    }
  }, [login]);

  /**
   * logout — clears all auth state, localStorage, and Axios headers.
   */
  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // Best-effort — always clear locally
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem('eye_user');
      localStorage.removeItem('eye_token');
      delete api.defaults.headers.common['Authorization'];
    }
  }, []);

  // Handle unauthorized event dispatched by Axios interceptor
  useEffect(() => {
    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('eye:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('eye:unauthorized', handleUnauthorized);
  }, [logout]);

  const value = { user, token, loading, login, signup, logout, isAuthenticated: !!token };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * useAuth — convenience hook for consuming AuthContext.
 * Throws if used outside of <AuthProvider>.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
