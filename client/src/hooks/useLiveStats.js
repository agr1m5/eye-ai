/**
 * useLiveStats.js — Hook for live SOC dashboard statistics.
 *
 * Tracks:
 *   - Total threats detected in real time (hydrated from DB + live stream)
 *   - Open incident count (hydrated from DB + live stream)
 *   - Rolling events-per-minute rate
 *   - Agent connection status and live host telemetry metrics
 */
import { useState, useEffect, useRef } from 'react';
import { useSocket } from '@/context/SocketContext';
import { threatApi, incidentApi } from '@/services/api';

export function useLiveStats(initialThreatCount = 0) {
  const { subscribe, agentOnline, agentLastSeen, agentMetrics } = useSocket();
  const [threatCount, setThreatCount] = useState(initialThreatCount);
  const [openIncidentCount, setOpenIncidentCount] = useState(0);
  const [eventsPerMin, setEventsPerMin] = useState(0);
  const eventTimestampsRef = useRef([]);

  // Hydrate initial stats from backend API
  useEffect(() => {
    let isMounted = true;

    async function loadInitialStats() {
      try {
        const [statsRes, incRes] = await Promise.all([
          threatApi.stats().catch(() => null),
          incidentApi.list({ status: 'open' }).catch(() => null),
        ]);

        if (!isMounted) return;

        if (statsRes?.data?.data) {
          const s = statsRes.data.data;
          const total = (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0) + (s.info || 0);
          setThreatCount((prev) => Math.max(prev, total));
        }

        if (incRes?.data?.data?.pagination) {
          setOpenIncidentCount(incRes.data.data.pagination.total);
        } else if (Array.isArray(incRes?.data?.data?.incidents)) {
          setOpenIncidentCount(incRes.data.data.incidents.length);
        }
      } catch (err) {
        console.error('Failed to hydrate live stats:', err);
      }
    }

    loadInitialStats();
    return () => { isMounted = false; };
  }, []);

  // Rolling events-per-minute rate calculation
  useEffect(() => {
    const interval = setInterval(() => {
      const cutoff = Date.now() - 60_000;
      eventTimestampsRef.current = eventTimestampsRef.current.filter((t) => t > cutoff);
      setEventsPerMin(eventTimestampsRef.current.length);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // Live socket subscriptions
  useEffect(() => {
    const unsubFinding = subscribe('finding:new', () => {
      setThreatCount((prev) => prev + 1);
      eventTimestampsRef.current.push(Date.now());
      setEventsPerMin(eventTimestampsRef.current.length);
    });

    const unsubIncidentNew = subscribe('incident:new', () => {
      setOpenIncidentCount((prev) => prev + 1);
    });

    const unsubIncidentUpdate = subscribe('incident:updated', (updated) => {
      if (updated && (updated.status === 'resolved' || updated.status === 'closed')) {
        setOpenIncidentCount((prev) => Math.max(0, prev - 1));
      }
    });

    return () => {
      unsubFinding();
      unsubIncidentNew();
      unsubIncidentUpdate();
    };
  }, [subscribe]);

  return {
    threatCount,
    openIncidentCount,
    eventsPerMin,
    agentOnline,
    agentLastSeen,
    agentMetrics,
  };
}
