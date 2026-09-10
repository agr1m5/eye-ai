/**
 * EventRateChart.jsx — Live rolling sparkline for the SOC Event Rate.
 *
 * Shows a smooth time-series line chart of events per minute over the last 60 minutes.
 * Hydrates historical data from GET /api/threats/timeline on mount,
 * then tracks incoming Socket.IO events in real time.
 *
 * Chart color adapts to threat rate:
 *   • ≥ 10 events/min → red (attack in progress)
 *   •  5–9 events/min → amber (elevated activity)
 *   •  < 5 events/min → teal/accent (nominal)
 */
import { useEffect, useRef, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import { useSocket } from '@/context/SocketContext';
import { threatApi } from '@/services/api';
import { TrendingUp, Zap } from 'lucide-react';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip);

const WINDOW_MINS  = 30;   // rolling window size shown on chart
const BUCKET_COUNT = 30;   // number of 1-minute buckets displayed

/** Build an empty bucket array for the last BUCKET_COUNT minutes */
function makeEmptyBuckets() {
  const now = Date.now();
  return Array.from({ length: BUCKET_COUNT }, (_, i) => ({
    ts:    new Date(now - (BUCKET_COUNT - 1 - i) * 60_000),
    count: 0,
  }));
}

/** Format a Date as "HH:MM" */
function fmtTime(d) {
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

export default function EventRateChart() {
  const { subscribe } = useSocket();
  const bucketsRef   = useRef(makeEmptyBuckets());
  const [chartData, setChartData] = useState(null);
  const [rate, setRate]           = useState(0); // events in last minute
  const mountedRef = useRef(true);

  // Rebuild chart data from current buckets
  const rebuildChart = (buckets) => {
    if (!mountedRef.current) return;
    const counts = buckets.map((b) => b.count);
    const total1m = counts[counts.length - 1] || 0;
    setRate(total1m);

    const isHot    = total1m >= 10;
    const isWarm   = total1m >= 5;
    const color    = isHot ? '#ef4444' : isWarm ? '#f59e0b' : '#00d4ff';
    const colorBg  = isHot ? 'rgba(239,68,68,0.12)' : isWarm ? 'rgba(245,158,11,0.10)' : 'rgba(0,212,255,0.08)';

    setChartData({
      labels: buckets.map((b) => fmtTime(b.ts)),
      datasets: [{
        data:               counts,
        borderColor:        color,
        backgroundColor:    colorBg,
        borderWidth:        2,
        fill:               true,
        tension:            0.4,
        pointRadius:        0,
        pointHoverRadius:   4,
        pointHoverBackgroundColor: color,
      }],
    });
  };

  // Hydrate historical data on mount
  useEffect(() => {
    mountedRef.current = true;
    threatApi.timeline(WINDOW_MINS)
      .then((res) => {
        if (!mountedRef.current) return;
        const history = res.data?.data?.timeline || [];
        if (history.length > 0) {
          const buckets = makeEmptyBuckets();
          history.forEach((point) => {
            const ptTime = new Date(point.timestamp);
            const idx = buckets.findIndex((b) => Math.abs(b.ts - ptTime) < 60_000);
            if (idx !== -1) buckets[idx].count = point.count;
          });
          bucketsRef.current = buckets;
        }
        rebuildChart(bucketsRef.current);
      })
      .catch(() => rebuildChart(bucketsRef.current));

    return () => { mountedRef.current = false; };
  }, []); // eslint-disable-line

  // Tick every minute — rotate bucket window
  useEffect(() => {
    const interval = setInterval(() => {
      bucketsRef.current = [
        ...bucketsRef.current.slice(1),
        { ts: new Date(), count: 0 },
      ];
      rebuildChart(bucketsRef.current);
    }, 60_000);
    return () => clearInterval(interval);
  }, []);

  // Live: append incoming events to current (last) bucket
  useEffect(() => {
    const unsub = subscribe('finding:new', () => {
      const last = bucketsRef.current[bucketsRef.current.length - 1];
      if (last) last.count += 1;
      rebuildChart([...bucketsRef.current]);
    });
    return () => unsub();
  }, [subscribe]);

  const isHot  = rate >= 10;
  const isWarm = rate >= 5;
  const rateColor = isHot ? 'text-red-400' : isWarm ? 'text-amber-400' : 'text-accent-400';

  const options = {
    responsive:          true,
    maintainAspectRatio: false,
    animation:           { duration: 400 },
    interaction:         { intersect: false, mode: 'index' },
    plugins: {
      legend:  { display: false },
      tooltip: {
        backgroundColor: 'rgba(13,22,36,0.95)',
        borderColor:     'rgba(255,255,255,0.08)',
        borderWidth:     1,
        titleColor:      '#94a3b8',
        bodyColor:       '#e2e8f0',
        padding:         10,
        callbacks: {
          title:  (items) => items[0]?.label,
          label:  (item)  => ` ${item.raw} event${item.raw !== 1 ? 's' : ''}`,
        },
      },
    },
    scales: {
      x: {
        grid:  { display: false },
        border: { display: false },
        ticks: {
          color:     '#475569',
          font:      { size: 9, family: 'monospace' },
          maxTicksLimit: 8,
          maxRotation:   0,
        },
      },
      y: {
        grid:    { color: 'rgba(255,255,255,0.04)' },
        border:  { display: false },
        ticks:   { color: '#475569', font: { size: 9 }, stepSize: 1 },
        min:     0,
        suggestedMax: Math.max(5, (rate || 0) + 2),
      },
    },
  };

  return (
    <div className="glass-card glow-border flex flex-col overflow-hidden" style={{ height: '13rem' }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-surface-900/40 shrink-0">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-accent-400" />
          <span className="text-xs font-semibold text-slate-200">Event Rate Timeline</span>
          <span className="text-[10px] text-slate-500 font-mono">30-min rolling window</span>
        </div>
        <div className="flex items-center gap-1.5">
          {isHot && <Zap className="w-3.5 h-3.5 text-red-400 animate-pulse" />}
          <span className={`text-sm font-bold font-mono ${rateColor}`}>{rate}</span>
          <span className="text-[10px] text-slate-500">/ min</span>
        </div>
      </div>

      {/* Chart */}
      <div className="flex-1 px-3 py-2">
        {chartData ? (
          <Line data={chartData} options={options} />
        ) : (
          <div className="h-full flex items-center justify-center text-slate-600 text-xs font-mono">
            Loading telemetry history…
          </div>
        )}
      </div>
    </div>
  );
}
