/**
 * ErrorBoundary.jsx — Prevents catastrophic unmounting of the SOC dashboard.
 */
import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[SOC ErrorBoundary]', error, errorInfo);
  }

  handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-surface-950 flex items-center justify-center p-6 text-slate-100">
          <div className="max-w-md w-full glass-card p-6 border border-red-500/40 shadow-2xl rounded-2xl text-center space-y-4">
            <div className="inline-flex p-3 rounded-xl bg-red-950/80 text-red-400 border border-red-800/60">
              <AlertTriangle className="w-8 h-8 animate-bounce" />
            </div>
            <h2 className="text-lg font-bold font-mono text-slate-100 uppercase tracking-wide">
              Interface Render Exception
            </h2>
            <p className="text-xs text-slate-400 font-mono bg-surface-900/90 p-3 rounded-lg border border-surface-700 break-words text-left">
              {this.state.error?.message || 'An unexpected rendering error occurred.'}
            </p>
            <button
              onClick={this.handleReload}
              className="inline-flex items-center gap-2 px-4 py-2 bg-accent-400 text-surface-950 font-bold text-xs rounded-lg shadow-lg hover:bg-accent-300 transition-all font-mono"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reload Interface</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
