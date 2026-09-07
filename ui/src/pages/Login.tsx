/**
 * Sign in.
 *
 * There is no role selector: the role is whatever `/users/me` returns for these
 * credentials. There is no self-registration either — `POST /users` is an
 * administrator creating an account — so the page says so rather than offering
 * a form that would 403 every time.
 */
import { AlertCircle, ArrowLeft } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';

import { Button } from '@/components/ui/Primitives';
import { useAuth } from '@/hooks/useAuth';
import { describeError } from '@/services/api';

const HOME = '/devices';

export function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  if (isAuthenticated) return <Navigate to={HOME} replace />;

  const from = (location.state as { from?: string } | null)?.from ?? HOME;

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
    <div className="relative flex min-h-screen items-center justify-center bg-paper p-4">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(50rem 26rem at 50% -10%, rgba(35,82,124,0.10), transparent 70%)',
        }}
      />

      <div className="relative w-full max-w-sm">
        <Link
          to="/"
          className="mb-6 inline-flex items-center gap-1.5 text-muted hover:text-ink"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          Back
        </Link>

        <h1 className="font-display text-[2.75rem] leading-none text-ink">Nirikshak</h1>
        <p className="mt-2 text-muted">Sign in to continue.</p>

        <form onSubmit={onSubmit} className="card mt-6 space-y-4 p-5">
          <div>
            <label htmlFor="username" className="label mb-1 block">
              Username
            </label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="h-10 w-full rounded border border-border-strong bg-paper px-3 text-ink"
            />
          </div>

          <div>
            <label htmlFor="password" className="label mb-1 block">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="h-10 w-full rounded border border-border-strong bg-paper px-3 text-ink"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded border border-fail-br bg-fail-bg px-3 py-2"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-fail" aria-hidden="true" />
              <p className="text-ink-2">{error}</p>
            </div>
          )}

          <Button type="submit" variant="primary" className="h-10 w-full" disabled={pending}>
            {pending ? 'Signing in…' : 'Sign in'}
          </Button>

          <p className="border-t border-border pt-3 text-micro text-muted">
            Accounts are created by an administrator. There is no self-registration.
          </p>
        </form>
      </div>
    </div>
  );
}
