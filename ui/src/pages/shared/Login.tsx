/**
 * Sign in.
 *
 * There is no role selector, and there never will be. The role is whatever
 * `/users/me` returns for these credentials — a dropdown offering "admin" would
 * be an invitation to misunderstand what this interface controls.
 *
 * There is also no self-registration. `POST /users` is an administrator creating
 * an account (decision D25: the backend ships no sessions, registration or
 * password reset, deliberately), so offering a sign-up form would produce a 403
 * every time. The screen says so instead.
 */
import { AlertCircle, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { Button } from '@/components/ui/Primitives';
import { useAuth } from '@/hooks/useAuth';
import { describeError } from '@/services/api';

export function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  const from = (location.state as { from?: string } | null)?.from ?? '/dashboard';

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (thrown) {
      setError(describeError(thrown));
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-6">
          <ShieldCheck className="h-7 w-7 text-accent" aria-hidden="true" />
          <div>
            <h1 className="text-[20px] font-semibold tracking-tight text-ink leading-none">
              NIRIKSHAK
            </h1>
            <p className="text-[13px] text-muted mt-1 leading-none">
              Self-learning, vendor-agnostic network compliance auditor
            </p>
          </div>
        </div>

        <form onSubmit={onSubmit} className="card p-5 space-y-4">
          <div>
            <label htmlFor="username" className="label block mb-1">
              Username
            </label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full h-9 px-3 rounded border border-border-strong bg-paper
                         text-[13px] text-ink placeholder:text-muted"
            />
          </div>

          <div>
            <label htmlFor="password" className="label block mb-1">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-9 px-3 rounded border border-border-strong bg-paper
                         text-[13px] text-ink placeholder:text-muted"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded border border-fail-br bg-fail-bg px-3 py-2"
            >
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0 text-fail" aria-hidden="true" />
              <p className="text-[13px] text-ink-2">{error}</p>
            </div>
          )}

          <Button type="submit" variant="primary" className="w-full" disabled={pending}>
            {pending ? 'Signing in…' : 'Sign in'}
          </Button>

          <p className="text-2xs text-muted leading-relaxed pt-1 border-t border-border">
            Accounts are created by an administrator — there is no self-registration.
            Authentication is HTTP Basic; your role is decided by the server, never by this
            page.
          </p>
        </form>

        <p className="mt-4 text-2xs text-muted text-center">AI suggests. Rules decide.</p>
      </div>
    </div>
  );
}
