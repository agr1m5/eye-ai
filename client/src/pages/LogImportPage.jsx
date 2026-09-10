/**
 * LogImportPage — Offline log ingestion and retroactive threat analysis.
 *
 * Supports:
 *   - Drag-and-drop or file picker upload for .log / .txt / .json / .csv / .gz
 *   - Automatic backend regex analysis across 10 common threat patterns
 *   - Processing status tracking (uploaded -> processing -> done)
 *   - Extracted threat inspection drawer
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import PageWrapper from '@/components/layout/PageWrapper';
import Modal from '@/components/common/Modal';
import SeverityBadge from '@/components/common/SeverityBadge';
import Spinner from '@/components/common/Spinner';
import EmptyState from '@/components/common/EmptyState';
import { logApi } from '@/services/api';
import { Upload, FileUp, CheckCircle2, AlertTriangle, Loader2, Clock, ShieldAlert, Eye, File } from 'lucide-react';
import { format } from 'date-fns';
import toast from 'react-hot-toast';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export default function LogImportPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const pollRef = useRef(null);

  // Extracted Threats Modal
  const [selectedLog, setSelectedLog] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loadingThreats, setLoadingThreats] = useState(false);

  const fetchLogs = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const { data } = await logApi.list();
      if (data.status === 'success') {
        setLogs(data.data || []);
      }
    } catch (err) {
      if (!quiet) toast.error('Failed to load log imports');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Polling while any log is processing
  useEffect(() => {
    const hasProcessing = logs.some((l) => l.status === 'uploaded' || l.status === 'processing');
    if (hasProcessing) {
      if (!pollRef.current) {
        pollRef.current = setInterval(() => {
          fetchLogs(true);
        }, 3000);
      }
    } else if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [logs, fetchLogs]);

  const handleFileUpload = async (file) => {
    if (!file) return;

    const ext = file.name.split('.').pop().toLowerCase();
    const validExtensions = ['log', 'txt', 'json', 'csv', 'gz'];
    if (!validExtensions.includes(ext)) {
      toast.error('Supported formats: .log, .txt, .json, .csv, .gz');
      return;
    }

    const formData = new FormData();
    formData.append('logfile', file);

    setUploading(true);
    try {
      const { data } = await logApi.upload(formData);
      if (data.status === 'success') {
        toast.success(`Log "${file.name}" uploaded. Parsing threats...`);
        setLogs((prev) => [data.data, ...prev]);
      }
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to upload log file');
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileUpload(file);
  };

  const handleOpenThreats = async (log) => {
    setSelectedLog(log);
    setLoadingThreats(true);
    try {
      const { data } = await logApi.threats(log._id);
      if (data.status === 'success') {
        setThreats(data.data || []);
      }
    } catch (err) {
      toast.error('Failed to fetch extracted threats');
    } finally {
      setLoadingThreats(false);
    }
  };

  return (
    <PageWrapper
      title="Log File Ingestion"
      subtitle="Upload offline syslogs, server dumps, and event logs for automatic threat extraction"
    >
      {/* Informational Banner */}
      <div className="mb-6 px-4 py-3 rounded-lg bg-accent-400/5 border border-accent-400/15 text-xs text-accent-300 flex items-start gap-2.5">
        <Upload className="w-4 h-4 shrink-0 mt-0.5" />
        <span>
          Secondary Ingestion Pipeline: Parse exported auth logs, Nginx/Apache logs, or firewall telemetry.
          Rakshak inspects entries for SQLi, XSS, Brute Force, Command Injections, and anomalous reconnaissance.
        </span>
      </div>

      {/* Drag and Drop Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`glass-card border-2 border-dashed rounded-xl py-12 px-6 flex flex-col items-center justify-center cursor-pointer transition-all duration-200 mb-8 ${
          isDragOver
            ? 'border-accent-400 bg-accent-400/10 scale-[1.01]'
            : 'border-white/10 hover:border-accent-400/40 hover:bg-surface-800/40'
        } ${uploading ? 'opacity-50 pointer-events-none' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".log,.txt,.json,.csv,.gz"
          onChange={(e) => handleFileUpload(e.target.value ? e.target.files[0] : null)}
          className="hidden"
        />

        {uploading ? (
          <div className="flex flex-col items-center gap-2">
            <Loader2 className="w-8 h-8 text-accent-400 animate-spin" />
            <p className="text-xs font-semibold text-slate-300">Uploading and streaming file...</p>
          </div>
        ) : (
          <div className="flex flex-col items-center text-center">
            <div className="p-3 rounded-2xl bg-surface-800/80 border border-white/5 text-accent-400 mb-3">
              <FileUp className="w-6 h-6" />
            </div>
            <p className="text-sm font-semibold text-slate-200">
              Drag and drop your log file here, or <span className="text-accent-400 underline">browse</span>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Supports .log, .txt, .json, .csv, .gz (Max 50MB)
            </p>
          </div>
        )}
      </div>

      {/* History Table */}
      <div className="space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Imported Files ({logs.length})
        </h3>

        <div className="glass-card glow-border overflow-hidden rounded-xl">
          <div className="grid grid-cols-12 px-4 py-3 border-b border-white/5 text-[10px] font-semibold uppercase tracking-widest text-slate-500 bg-surface-800/40">
            <span className="col-span-4">File Name</span>
            <span className="col-span-2">Size</span>
            <span className="col-span-2">Uploaded</span>
            <span className="col-span-2">Status</span>
            <span className="col-span-2 text-right">Threats</span>
          </div>

          {loading ? (
            <div className="py-16 flex justify-center">
              <Spinner size="md" />
            </div>
          ) : logs.length === 0 ? (
            <EmptyState
              icon={File}
              title="No logs imported yet"
              message="Drag and drop or upload a log file above to test the offline detection pipeline."
            />
          ) : (
            <div className="divide-y divide-white/5">
              {logs.map((log) => (
                <div
                  key={log._id}
                  className="grid grid-cols-12 items-center px-4 py-3 text-xs hover:bg-white/[0.02] transition-colors"
                >
                  {/* Name */}
                  <div className="col-span-4 flex items-center gap-2.5 truncate pr-2">
                    <File className="w-4 h-4 text-slate-500 shrink-0" />
                    <span className="font-medium text-slate-200 truncate">{log.originalName}</span>
                  </div>

                  {/* Size */}
                  <div className="col-span-2 text-slate-400 font-mono text-[11px]">
                    {formatBytes(log.fileSize)}
                  </div>

                  {/* Date */}
                  <div className="col-span-2 text-slate-500 text-[11px]">
                    {log.createdAt ? format(new Date(log.createdAt), 'dd MMM, HH:mm') : '—'}
                  </div>

                  {/* Status */}
                  <div className="col-span-2">
                    {log.status === 'done' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded-full">
                        <CheckCircle2 className="w-3 h-3" /> Processed
                      </span>
                    ) : log.status === 'processing' || log.status === 'uploaded' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-accent-400 bg-accent-400/10 px-2 py-0.5 rounded-full">
                        <Loader2 className="w-3 h-3 animate-spin" /> Analyzing
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-red-400 bg-red-400/10 px-2 py-0.5 rounded-full">
                        <AlertTriangle className="w-3 h-3" /> Failed
                      </span>
                    )}
                  </div>

                  {/* Threats Count + Action */}
                  <div className="col-span-2 flex items-center justify-end gap-2">
                    <span className="font-mono text-xs font-bold text-accent-400">
                      {log.threatCount}
                    </span>
                    {log.threatCount > 0 && (
                      <button
                        onClick={() => handleOpenThreats(log)}
                        className="btn-ghost text-xs px-2 py-1 flex items-center gap-1 text-slate-400 hover:text-slate-100"
                        title="View Extracted Findings"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">View</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Extracted Threats Inspection Modal */}
      <Modal
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title={`Extracted Findings: ${selectedLog?.originalName}`}
        size="lg"
      >
        {loadingThreats ? (
          <div className="py-12 flex justify-center">
            <Spinner size="md" />
          </div>
        ) : threats.length === 0 ? (
          <p className="py-8 text-center text-xs text-slate-500">No threats detected in this log.</p>
        ) : (
          <div className="glass-card divide-y divide-white/5 rounded-xl max-h-[60vh] overflow-y-auto">
            {threats.map((th) => (
              <div key={th._id} className="p-3 text-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={th.severity} />
                    <span className="font-semibold text-slate-200">{th.type}</span>
                  </div>
                  {th.source?.ip && (
                    <span className="font-mono text-[11px] text-accent-400">
                      IP: {th.source.ip}
                    </span>
                  )}
                </div>
                {th.description && (
                  <p className="text-[11px] text-slate-400 font-mono bg-surface-900/60 p-2 rounded border border-white/5 whitespace-pre-wrap">
                    {th.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </Modal>
    </PageWrapper>
  );
}
