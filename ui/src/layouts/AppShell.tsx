/**
 * The persistent application shell: sidebar, header, content.
 *
 * The header carries the product's own claim — "AI suggests. Rules decide." —
 * because it is the sentence that explains every other screen. A verdict on this
 * interface was produced by a deterministic engine reading a typed model, and
 * the one advisory branch in the system proposes mappings that a human confirms.
 */
import { LogOut, Menu, ShieldCheck, X } from 'lucide-react';
import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { Toaster } from '@/components/ui/Toaster';
import { useAuth } from '@/hooks/useAuth';
import { navFor } from './navigation';

export function AppShell() {
  const { session, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const items = navFor(isAdmin);

  const onLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="min-h-screen flex bg-surface">
      {/* Sidebar */}
      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 w-60 shrink-0 bg-paper border-r
                    border-border flex flex-col transition-transform
                    ${open ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        <div className="h-14 px-4 flex items-center gap-2 border-b border-border">
          <ShieldCheck className="h-5 w-5 text-accent" aria-hidden="true" />
          <div className="min-w-0">
            <p className="text-[14px] font-semibold tracking-tight text-ink leading-none">
              NIRIKSHAK
            </p>
            <p className="text-2xs text-muted mt-1 leading-none">Compliance auditor</p>
          </div>
          <button
            type="button"
            className="ml-auto lg:hidden text-muted"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-2" aria-label="Main">
          <p className="px-4 py-2 label">{isAdmin ? 'Fleet-wide' : 'My resources'}</p>
          <ul>
            {items.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-4 py-1.5 text-[13px] border-l-2 transition-colors
                     ${
                       isActive
                         ? 'border-accent bg-accent-bg text-ink font-medium'
                         : 'border-transparent text-ink-2 hover:bg-surface hover:text-ink'
                     }`
                  }
                >
                  <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span className="truncate">{item.label}</span>
                  {item.availability !== 'available' && (
                    <span
                      className="ml-auto text-2xs text-muted"
                      title={
                        item.availability === 'unavailable'
                          ? 'No backend capability'
                          : 'Partially available'
                      }
                    >
                      {item.availability === 'unavailable' ? 'n/a' : '·'}
                    </span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="border-t border-border p-3">
          <p className="text-[13px] text-ink font-medium truncate">{session?.username}</p>
          <p className="text-2xs text-muted uppercase tracking-wider mb-2">
            {isAdmin ? 'Administrator' : 'User'}
          </p>
          <button
            type="button"
            onClick={onLogout}
            className="inline-flex items-center gap-1.5 text-[13px] text-ink-2 hover:text-ink"
          >
            <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
            Sign out
          </button>
        </div>
      </aside>

      {open && (
        <div
          className="fixed inset-0 z-30 bg-ink/20 lg:hidden"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Main */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 shrink-0 bg-paper border-b border-border flex items-center gap-3 px-4">
          <button
            type="button"
            className="lg:hidden text-muted"
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="min-w-0">
            <p className="text-[13px] text-ink font-medium leading-none">
              Self-learning, vendor-agnostic network compliance auditor
            </p>
            <p className="text-2xs text-muted mt-1 leading-none">
              AI suggests. Rules decide. · Evidence-backed network security compliance.
            </p>
          </div>
        </header>

        <main className="flex-1 min-w-0 p-4 lg:p-6 max-w-[1600px] w-full">
          <Outlet />
        </main>
      </div>

      <Toaster />
    </div>
  );
}
