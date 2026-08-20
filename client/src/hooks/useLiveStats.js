/**
 * useLiveStats.js — Hook for live SOC dashboard statistics.
 *
 * Tracks:
 *   - Total threats detected in real time
 *   - Rolling events-per-minute rate
 *   - Agent connection status and metadata
 */
import { useState, useEffect, useRef } from 'react';
import { useSocket } from '@/context/SocketContext';

export function useLiveStats(initialThreatCount = 0) {
  const { subscribe, agentOnline, agentLastSeen } = useSocket();
  const [threatCount, setThreatCount] = useState(initialThreatCount);
  const [eventsPerMin, setEventsPerMin] = useState(0);
  const eventTimestampsRef = useRef([]);

  useEffect(() => {
    // Clean up timestamps older than 60 seconds every 2 seconds
    const interval = setInterval(() => {
      const cutoff = Date.now() - 60_000;
      eventTimestampsRef.current = eventTimestampsRef.current.filter((t) => t > cutoff);
      setEventsPerMin(eventTimestampsRef.current.length);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const unsubscribe = subscribe('finding:new', () => {
      setThreatCount((prev) => prev + 1);
      eventTimestampsRef.current.push(Date.now());
      setEventsPerMin(eventTimestampsRef.current.length);
    });

    return () => unsubscribe();
  }, [subscribe]);

  return {
    threatCount,
    eventsPerMin,
    agentOnline,
    agentLastSeen,
  };
}
