/**
 * ReportsPage — AI and SOC incident PDF reports generation and archives.
 *
 * Supports:
 *   - Listing generated and pending reports
 *   - Live polling while reports are in 'generating' state
 *   - Triggering PDF generation via GenerateReportModal
 *   - Direct PDF download to browser
 *   - Deleting reports
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import GenerateReportModal from '@/components/reports/GenerateReportModal';
import EmptyState from '@/components/common/EmptyState';
import Spinner from '@/components/common/Spinner';
import { reportApi, incidentApi } from '@/services/api';
import { FileText, Plus, Download, Trash2, Clock, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '—';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);
  const pollIntervalRef = useRef(null);

  const fetchReports = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const { data } = await reportApi.list();
      if (data.status === 'success') {
        setReports(data.data || []);
      }
    } catch (err) {
      if (!quiet) toast.error('Failed to load reports');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  const fetchIncidentsForModal = async () => {
    try {
      const { data } = await incidentApi.list({ limit: 50 });
      if (data.status === 'success') {
        setIncidents(data.data.incidents || []);
      }
    } catch (_) {
      // Non-blocking
    }
  };

  useEffect(() => {
    fetchReports();
    fetchIncidentsForModal();
  }, [fetchReports]);

  // Poll if any report is generating
  useEffect(() => {
    const hasGenerating = reports.some((r) => r.status === 'generating' || r.status === 'pending');
    if (hasGenerating) {
      if (!pollIntervalRef.current) {
        pollIntervalRef.current = setInterval(() => {
          fetchReports(true);
        }, 3000);
      }
    } else if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [reports, fetchReports]);

  const handleGenerate = async (payload) => {
    try {
      const { data } = await reportApi.generate(payload);
      if (data.status === 'success') {
        toast.success('Report generation started');
        setReports((prev) => [data.data, ...prev]);
      }
    } catch (err) {
      toast.error('Failed to initiate report generation');
      throw err;
    }
  };

  const handleDownload = async (report) => {
    setDownloadingId(report._id);
    try {
      const res = await reportApi.download(report._id);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${report.title.replace(/[^a-z0-9]/gi, '_')}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('Download started');
    } catch (err) {
      toast.error('Failed to download report');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (id) => {
    try {
      await reportApi.remove(id);
      setReports((prev) => prev.filter((r) => r._id !== id));
      toast.success('Report removed');
    } catch (err) {
      toast.error('Failed to delete report');
    }
  };

  return (
    <PageWrapper
      title="Security Reports"
      subtitle="Automated PDF briefings, executive summaries, and forensics exports"
      actions={
        <button
          onClick={() => setIsModalOpen(true)}
          className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Generate Report</span>
        </button>
      }
    >
      <div className="glass-card glow-border overflow-hidden rounded-xl">
        {/* Table Header */}
        <div className="grid grid-cols-12 px-4 py-3 border-b border-white/5 text-[10px] font-semibold uppercase tracking-widest text-slate-500 bg-surface-800/40">
          <span className="col-span-5">Report Title</span>
          <span className="col-span-2">Status</span>
          <span className="col-span-2">Created</span>
          <span className="col-span-1">Size</span>
          <span className="col-span-2 text-right">Actions</span>
        </div>

        {/* Content */}
        {loading ? (
          <div className="py-20 flex justify-center">
            <Spinner size="lg" />
          </div>
        ) : reports.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No reports generated"
            message="Click 'Generate Report' to compile an incident briefing or date-range threat summary into an exportable PDF."
          />
        ) : (
          <div className="divide-y divide-white/5">
            {reports.map((report) => (
              <div
                key={report._id}
                className="grid grid-cols-12 items-center px-4 py-3 text-xs hover:bg-white/[0.02] transition-colors"
              >
                {/* Title */}
                <div className="col-span-5 flex items-center gap-3 pr-2">
                  <div className="p-2 rounded-lg bg-surface-800 border border-white/5 text-accent-400 shrink-0">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div className="truncate">
                    <p className="font-semibold text-slate-200 truncate">{report.title}</p>
                    <p className="text-[10px] text-slate-500 font-mono">
                      {report.incidentId ? 'Incident Scoped' : 'Time Range Scoped'}
                    </p>
                  </div>
                </div>

                {/* Status */}
                <div className="col-span-2">
                  {report.status === 'done' ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded-full">
                      <CheckCircle2 className="w-3 h-3" /> Ready
                    </span>
                  ) : report.status === 'generating' || report.status === 'pending' ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-accent-400 bg-accent-400/10 px-2 py-0.5 rounded-full">
                      <Loader2 className="w-3 h-3 animate-spin" /> Generating
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-red-400 bg-red-400/10 px-2 py-0.5 rounded-full">
                      <AlertTriangle className="w-3 h-3" /> Failed
                    </span>
                  )}
                </div>

                {/* Created Date */}
                <div className="col-span-2 text-slate-500 text-[11px]">
                  {report.createdAt ? format(new Date(report.createdAt), 'dd MMM yyyy, HH:mm') : '—'}
                </div>

                {/* Size */}
                <div className="col-span-1 text-slate-400 font-mono text-[11px]">
                  {formatBytes(report.fileSize)}
                </div>

                {/* Actions */}
                <div className="col-span-2 flex items-center justify-end gap-2">
                  <button
                    onClick={() => handleDownload(report)}
                    disabled={report.status !== 'done' || downloadingId === report._id}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-accent-300 hover:bg-white/5
                               disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                    title="Download PDF"
                  >
                    {downloadingId === report._id ? (
                      <Loader2 className="w-4 h-4 animate-spin text-accent-400" />
                    ) : (
                      <Download className="w-4 h-4" />
                    )}
                  </button>
                  <button
                    onClick={() => handleDelete(report._id)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-400/10 transition-colors"
                    title="Delete Report"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      <GenerateReportModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onGenerate={handleGenerate}
        incidents={incidents}
      />
    </PageWrapper>
  );
}
