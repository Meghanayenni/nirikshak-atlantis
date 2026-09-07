/**
 * The application shell.
 *
 * The navigation is a drawer, closed until it is asked for. An operator working
 * through one device should see that device, not a permanent list of the six
 * places they are not looking.
 */
import { LogOut, Menu, UserRound, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { Toaster } from '@/components/ui/Toaster';
import { useAuth } from '@/hooks/useAuth';
import { PIPELINE_NAV, SUPPORT_NAV } from './navigation';

function NavList({ items, onNavigate }: { items: typeof PIPELINE_NAV; onNavigate: () => void }) {
  return (
    <ul>
      {items.map((item) => (
        <li key={item.to}>
          <NavLink
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-start gap-3 px-4 py-2.5 border-l-2 transition-colors
               ${
                 isActive
                   ? 'border-accent bg-accent-bg text-ink'
                   : 'border-transparent text-ink-2 hover:bg-surface hover:text-ink'
               }`
            }
          >
            <item.icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="min-w-0">
              <span className="block truncate font-medium">{item.label}</span>
              <span className="block truncate text-micro text-muted">{item.stage}</span>
            </span>
          </NavLink>
        </li>
      ))}
    </ul>
  );
}

export function AppShell() {
  const { session, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  // Escape closes the drawer, like every other overlay in this interface.
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  const onLogout = () => {
    logout();
    navigate('/', { replace: true });
  };

  return (
    <div className="min-h-screen bg-surface">
      <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-paper px-4">
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label="Open navigation"
          aria-expanded={open}
          className="-ml-1 inline-flex h-9 w-9 items-center justify-center rounded text-ink-2
                     hover:bg-surface hover:text-ink"
        >
          <Menu className="h-5 w-5" />
        </button>

        {/*
          The wordmark alone. The section name used to sit beside it, and every
          screen already prints its own title immediately below — saying it twice
          in the same eyeline is duplication, not reinforcement.
        */}
        <span className="wordmark text-ink">Nirikshak</span>

        <div className="ml-auto flex items-center gap-5">
          {/*
            One identity, said once. The username is the identity; the role is a
            qualifier under it, not a second name beside it. The avatar carries no
            information of its own and is hidden from assistive technology — the
            text below it already says who this is.
          */}
          <div className="hidden items-center gap-2 sm:flex">
            <span
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full
                         border border-border bg-surface text-ink-2"
              aria-hidden="true"
            >
              <UserRound className="h-4 w-4" />
            </span>
            <span className="min-w-0 leading-tight">
              <span className="block truncate text-sm font-medium text-ink">
                {session?.username}
              </span>
              <span className="block text-micro uppercase tracking-wider text-muted">
                {isAdmin ? 'admin' : 'user'}
              </span>
            </span>
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="inline-flex items-center gap-1.5 text-base text-ink-2 hover:text-ink"
          >
            <LogOut className="h-4 w-4" aria-hidden="true" />
            <span className="hidden sm:inline">Sign out</span>
          </button>
        </div>
      </header>

      {open && (
        <div
          className="fixed inset-0 z-40 bg-ink/25 animate-fade-in"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      <nav
        aria-label="Main"
        aria-hidden={!open}
        className={`fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-border bg-paper
                    transition-transform duration-200
                    ${open ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className="flex h-14 items-center gap-2 border-b border-border px-4">
          <span className="wordmark text-ink">Nirikshak</span>
          <button
            type="button"
            className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded text-muted
                       hover:bg-surface hover:text-ink"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-3">
          <p className="px-4 pb-2 label">Pipeline</p>
          <NavList items={PIPELINE_NAV} onNavigate={() => setOpen(false)} />

          {/* Not "Records": these are capabilities built on top of the base
              idea, and only one of them is a record of anything. */}
          <p className="px-4 pb-2 pt-5 label">Beyond the pipeline</p>
          <NavList items={SUPPORT_NAV} onNavigate={() => setOpen(false)} />
        </div>

        {/*
          Identity, and the way out beside it. Sign out lives in the header too;
          it is repeated here because the drawer is where someone goes when they
          are finished, and having to close it again to leave is a small
          indignity at the end of every session.
        */}
        <div className="flex items-center gap-3 border-t border-border px-4 py-3">
          <div className="min-w-0 flex-1">
            <p className="truncate font-medium text-ink">{session?.username}</p>
            <p className="text-micro uppercase tracking-wider text-muted">
              {isAdmin ? 'Administrator' : 'User'}
            </p>
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded border border-border
                       bg-paper px-2.5 text-ink-2 transition-colors hover:bg-surface hover:text-ink"
          >
            <LogOut className="h-4 w-4" aria-hidden="true" />
            Sign out
          </button>
        </div>
      </nav>

      <main className="mx-auto w-full max-w-[1600px] p-4 lg:p-6">
        <Outlet />
      </main>

      <Toaster />
    </div>
  );
}
