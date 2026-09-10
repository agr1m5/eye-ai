/**
 * Pagination.jsx — Reusable pagination control.
 *
 * Props:
 *   page         {number}   — current page (1-indexed)
 *   totalPages   {number}   — total number of pages
 *   onPageChange {function} — called with new page number
 */
import { ChevronLeft, ChevronRight } from 'lucide-react';

export default function Pagination({ page, totalPages, onPageChange }) {
  if (!totalPages || totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-center gap-2 mt-4">
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page <= 1}
        aria-label="Previous page"
        className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/5
                   disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
      >
        <ChevronLeft className="w-4 h-4" />
      </button>

      {/* Page numbers — show at most 5 */}
      {Array.from({ length: totalPages }, (_, i) => i + 1)
        .filter((p) => {
          if (totalPages <= 5) return true;
          if (p === 1 || p === totalPages) return true;
          return Math.abs(p - page) <= 1;
        })
        .reduce((acc, p, idx, arr) => {
          if (idx > 0 && arr[idx - 1] !== p - 1) {
            acc.push('...');
          }
          acc.push(p);
          return acc;
        }, [])
        .map((p, idx) =>
          p === '...' ? (
            <span key={`ellipsis-${idx}`} className="text-slate-600 text-xs px-1">…</span>
          ) : (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              aria-label={`Page ${p}`}
              aria-current={p === page ? 'page' : undefined}
              className={`min-w-[2rem] h-8 text-xs rounded-lg transition-colors ${
                p === page
                  ? 'bg-accent-400/20 text-accent-300 border border-accent-400/30'
                  : 'text-slate-500 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              {p}
            </button>
          )
        )}

      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page >= totalPages}
        aria-label="Next page"
        className="p-1.5 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/5
                   disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
      >
        <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  );
}
