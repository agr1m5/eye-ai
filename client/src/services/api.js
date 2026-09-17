/**
 * api.js — Axios instance for all backend communication.
 *
 * Why a singleton instance (not bare axios)?
 *   • Single place to set baseURL — change one env var, everything follows.
 *   • Request interceptor can attach the latest Bearer token.
 *   • Response interceptor centralises 401 handling (redirect to /login).
 *   • Easy to mock in tests.
 */
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',            // resolved by the Vite dev proxy to http://localhost:5000/api
  timeout: 30_000,            // 30 s — generous for AI streaming calls
  headers: { 'Content-Type': 'application/json' },
});

/* ── Request interceptor ────────────────────────────────────── */
api.interceptors.request.use((reqConfig) => {
  try {
    const token = typeof window !== 'undefined' ? localStorage.getItem('eye_token') : null;
    if (token) {
      reqConfig.headers['Authorization'] = `Bearer ${token}`;
    }
  } catch {}
  return reqConfig;
});

/* ── Response interceptor ───────────────────────────────────── */
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      // Let AuthContext handle the state; just navigate away.
      // We post a custom event so AuthContext can react without a circular import.
      window.dispatchEvent(new Event('eye:unauthorized'));
    }
    return Promise.reject(err);
  }
);

/* ── Typed API helpers ──────────────────────────────────────── */

// Auth
export const authApi = {
  signup:            (data)    => api.post('/auth/signup', data),
  login:             (data)    => api.post('/auth/login', data),
  logout:            ()        => api.post('/auth/logout'),
  me:                ()        => api.get('/auth/me'),
  updatePreferences: (prefs)   => api.patch('/auth/preferences', prefs),
  pairAgent:         (label)   => api.post('/agent/pair', { label }),
  revokeAgent:       ()        => api.delete('/agent/pair'),
  agentStatus:       ()        => api.get('/agent/status'),
  getAgentStatus:    ()        => api.get('/agent/status'),
  getConsent:        ()        => api.get('/agent/consent'),
  setConsent:        (granted) => api.patch('/agent/consent', { granted }),
  toggleAgent:       (enable)  => api.post('/agent/toggle', { enable }),
};

// Threats
export const threatApi = {
  list:         (params)         => api.get('/threats', { params }),
  stats:        ()               => api.get('/threats/stats'),
  timeline:     (window = 60)    => api.get('/threats/timeline', { params: { window } }),
  get:          (id)             => api.get(`/threats/${id}`),
  updateStatus: (id, status)     => api.patch(`/threats/${id}/status`, { status }),
  dismiss:      (id)             => api.delete(`/threats/${id}`),
  simulate:     (data)           => api.post('/threats/simulate', data),
  types:        ()               => api.get('/threats/types'),
  bulkStatus:   (data)           => api.patch('/threats/bulk/status', data),
  bulkDelete:   (data)           => api.delete('/threats/bulk', { data }),
};

// Correlated Incidents
export const incidentApi = {
  list:         (params)        => api.get('/incidents', { params }),
  create:       (body)          => api.post('/incidents', body),
  get:          (id)            => api.get(`/incidents/${id}`),
  updateStatus: (id, status)    => api.patch(`/incidents/${id}/status`, { status }),
  updateNotes:  (id, notes)     => api.patch(`/incidents/${id}/notes`, { notes }),
  delete:       (id, params)    => api.delete(`/incidents/${id}`, { params }),
};

// Chat
export const chatApi = {
  list:    ()           => api.get('/chat'),
  create:  ()           => api.post('/chat'),
  get:     (id)         => api.get(`/chat/${id}`),
  message: (id, content) => api.post(`/chat/${id}/message`, { content }),
  remove:  (id)         => api.delete(`/chat/${id}`),
};

// Reports
export const reportApi = {
  list:     ()       => api.get('/reports'),
  generate: (body)   => api.post('/reports', body),
  download: (id)     => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
  remove:   (id)     => api.delete(`/reports/${id}`),
};

// Threat Intelligence
export const tiApi = {
  ip:     (ip)          => api.get(`/ti/ip/${ip}`),
  cve:    (cveId)       => api.get(`/ti/cve/${cveId}`),
  mitre:  (techniqueId) => api.get(`/ti/mitre/${techniqueId}`),
  owasp:  (category)    => api.get(`/ti/owasp/${category}`),
};

// Log Import (secondary path)
export const logApi = {
  upload:  (formData) => api.post('/logs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  list:    ()         => api.get('/logs'),
  threats: (id)       => api.get(`/logs/${id}/threats`),
};

// Analyst Audit Log
export const auditApi = {
  list: (params) => api.get('/audit', { params }),
};

export const activitiesApi = {
  list:        (params) => api.get('/activities', { params }),
  stats:       ()       => api.get('/activities/stats'),
  clear:       ()       => api.delete('/activities'),
  suggestions: (id, data) => api.post(`/activities/${id}/suggestions`, data),
  analyze:     (data)   => api.post('/activities/suggestions', data),
};

// Active Defense & SOAR Containment
export const defenseApi = {
  contain: (data)   => api.post('/defense/contain', data),
  actions: (params) => api.get('/defense/actions', { params }),
  release: (id)     => api.post(`/defense/${id}/release`),
};

export default api;
