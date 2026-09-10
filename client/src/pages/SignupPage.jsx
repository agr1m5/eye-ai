/**
 * SignupPage — registration form.
 *
 * Validates that passwords match before calling AuthContext.signup().
 * On success, navigates to /dashboard (signup auto-logs in).
 */
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck, Eye, EyeOff, UserPlus } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import Spinner from '@/components/common/Spinner';

export default function SignupPage() {
  const { signup } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail]     = useState('');
  const [password, setPass]   = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPass, setShow]   = useState(false);
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (password !== confirm) {
      return setError('Passwords do not match.');
    }
    if (password.length < 8) {
      return setError('Password must be at least 8 characters.');
    }
    setLoading(true);
    try {
      await signup(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.response?.data?.message ?? 'Signup failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">

      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2
                      w-96 h-96 bg-accent-400/5 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md animate-slide-in-up">

        {/* Brand */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center w-14 h-14 rounded-2xl
                          bg-accent-400/10 border border-accent-400/30 mb-4 shadow-glow">
            <ShieldCheck className="w-7 h-7 text-accent-400" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Eye Live</h1>
          <p className="text-sm text-slate-500 mt-1">Create your SOC account</p>
        </div>

        {/* Card */}
        <div className="glass-card glow-border p-8">
          <h2 className="text-lg font-semibold text-slate-100 mb-6">Create account</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">
                Email address
              </label>
              <input
                id="signup-email"
                type="email"
                autoComplete="email"
                required
                className="input"
                placeholder="analyst@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">
                Password <span className="text-slate-600">(min. 8 characters)</span>
              </label>
              <div className="relative">
                <input
                  id="signup-password"
                  type={showPass ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  className="input pr-10"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPass(e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShow(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500
                             hover:text-slate-300 transition-colors"
                  aria-label={showPass ? 'Hide password' : 'Show password'}
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">
                Confirm password
              </label>
              <input
                id="signup-confirm"
                type={showPass ? 'text' : 'password'}
                autoComplete="new-password"
                required
                className="input"
                placeholder="••••••••"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20
                            rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              id="btn-signup"
              type="submit"
              disabled={loading}
              className="btn-primary w-full justify-center mt-2"
            >
              {loading ? <Spinner size="sm" /> : <UserPlus className="w-4 h-4" />}
              {loading ? 'Creating account…' : 'Create account'}
            </button>
          </form>

          <p className="text-xs text-slate-500 text-center mt-6">
            Already have an account?{' '}
            <Link to="/login" className="text-accent-400 hover:text-accent-300 font-medium">
              Sign in
            </Link>
          </p>
        </div>

        <p className="text-center text-[10px] text-slate-700 mt-6">
          Eye Live · All detection runs locally on your machine
        </p>
      </div>
    </div>
  );
}
