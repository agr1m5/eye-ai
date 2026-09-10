/**
 * App.jsx — root application component.
 *
 * Responsibilities:
 *  1. Wraps everything in AuthProvider + SocketProvider
 *  2. Declares all React Router routes
 *  3. Implements a ProtectedRoute guard — unauthenticated users go to /login
 *  4. Listens for the 'eye:unauthorized' event (from Axios interceptor)
 *     and forces logout/redirect without a circular import
 *
 * Route structure:
 *   /login        → LoginPage         (public)
 *   /signup       → SignupPage        (public)
 *   /             → redirect → /dashboard
 *   /dashboard    → DashboardPage     (protected)
 *   /threats      → ThreatsPage       (protected)
 *   /incidents    → IncidentsPage     (protected)
 *   /hunt         → HuntPage          (protected)
 *   /mitre        → MitreMatrixPage   (protected)
 *   /chat         → ChatPage          (protected)
 *   /reports      → ReportsPage       (protected)
 *   /import       → LogImportPage     (protected)
 *   /settings     → SettingsPage      (protected)
 *   *             → 404 redirect
 */
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { Toaster } from 'react-hot-toast';

import { AuthProvider, useAuth } from '@/context/AuthContext';
import { SocketProvider }        from '@/context/SocketContext';

import LoginPage     from '@/pages/LoginPage';
import SignupPage    from '@/pages/SignupPage';
import DashboardPage from '@/pages/DashboardPage';
import ThreatsPage   from '@/pages/ThreatsPage';
import IncidentsPage from '@/pages/IncidentsPage';
import HuntPage      from '@/pages/HuntPage';
import MitreMatrixPage from '@/pages/MitreMatrixPage';
import ChatPage      from '@/pages/ChatPage';
import ReportsPage   from '@/pages/ReportsPage';
import LogImportPage from '@/pages/LogImportPage';
import SettingsPage  from '@/pages/SettingsPage';
import AuditPage     from '@/pages/AuditPage';
import ActivityPage  from '@/pages/ActivityPage';
import DefensePage   from '@/pages/DefensePage';
import GlobalAlertListener from '@/components/common/GlobalAlertListener';
import ErrorBoundary from '@/components/common/ErrorBoundary';

/* ── ProtectedRoute ─────────────────────────────────────────
   Redirects to /login if the user is not authenticated.
   Must be inside AuthProvider to read the auth context.
───────────────────────────────────────────────────────────── */
function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

/* ── UnauthorizedWatcher ────────────────────────────────────
   Listens for the 'eye:unauthorized' custom event fired
   by the Axios response interceptor on a 401 response.
   Clears auth state and redirects to login.
───────────────────────────────────────────────────────────── */
function UnauthorizedWatcher() {
  const { logout }  = useAuth();
  const navigate    = useNavigate();

  useEffect(() => {
    const handler = async () => {
      await logout();
      navigate('/login', { replace: true });
    };
    window.addEventListener('eye:unauthorized', handler);
    return () => window.removeEventListener('eye:unauthorized', handler);
  }, [logout, navigate]);

  return null;
}

/* ── AppRoutes ──────────────────────────────────────────── */
function AppRoutes() {
  return (
    <>
      <UnauthorizedWatcher />
      <Routes>
        {/* Public routes */}
        <Route path="/login"  element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />

        {/* Root redirect */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        {/* Protected routes */}
        <Route path="/dashboard" element={
          <ProtectedRoute><DashboardPage /></ProtectedRoute>
        } />
        <Route path="/activity" element={
          <ProtectedRoute><ActivityPage /></ProtectedRoute>
        } />
        <Route path="/threats" element={
          <ProtectedRoute><ThreatsPage /></ProtectedRoute>
        } />
        <Route path="/incidents" element={
          <ProtectedRoute><IncidentsPage /></ProtectedRoute>
        } />
        <Route path="/hunt" element={
          <ProtectedRoute><HuntPage /></ProtectedRoute>
        } />
        <Route path="/mitre" element={
          <ProtectedRoute><MitreMatrixPage /></ProtectedRoute>
        } />
        <Route path="/chat" element={
          <ProtectedRoute><ChatPage /></ProtectedRoute>
        } />
        <Route path="/reports" element={
          <ProtectedRoute><ReportsPage /></ProtectedRoute>
        } />
        <Route path="/import" element={
          <ProtectedRoute><LogImportPage /></ProtectedRoute>
        } />
        <Route path="/settings" element={
          <ProtectedRoute><SettingsPage /></ProtectedRoute>
        } />
        <Route path="/audit" element={
          <ProtectedRoute><AuditPage /></ProtectedRoute>
        } />

        {/* Catch-all */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </>
  );
}

/* ── Root App ────────────────────────────────────────────── */
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        {/*
          SocketProvider is inside AuthProvider so it can read the token.
          SocketProvider is outside AppRoutes so the socket persists
          across route changes without re-connecting.
        */}
        <SocketProvider>
          <GlobalAlertListener />
          <ErrorBoundary>
            <AppRoutes />
          </ErrorBoundary>

          {/* Global toast notification container */}
          <Toaster
            position="bottom-right"
            toastOptions={{
              style: {
                background: '#0d1624',
                color: '#e2e8f0',
                border: '1px solid rgba(255,255,255,0.08)',
                fontSize: '13px',
              },
              success: { iconTheme: { primary: '#00d4ff', secondary: '#050b14' } },
              error:   { iconTheme: { primary: '#ef4444', secondary: '#050b14' } },
            }}
          />
        </SocketProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
