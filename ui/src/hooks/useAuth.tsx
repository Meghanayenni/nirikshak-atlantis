/**
 * Session state for the shell.
 *
 * **This is a UX control, not a security boundary.** Hiding an admin route here
 * stops a user stumbling into a page that would 403; it does not stop anybody
 * calling the endpoint. The backend enforces every rule — admin-only routes
 * answer 403, and a resource belonging to somebody else answers 404 rather than
 * 403 so an unauthorised caller learns nothing about which ids exist.
 *
 * The role is whatever `/users/me` said. Nothing in this file lets a caller
 * choose one.
 */
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

import { loadSession, type Session } from '@/services/api';
import { login as doLogin, logout as doLogout } from '@/services/auth';

interface AuthValue {
  session: Session | null;
  isAdmin: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  /** Called when any request returns 401, to drop back to the login screen. */
  expire: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSessionState] = useState<Session | null>(() => loadSession());

  const login = useCallback(async (username: string, password: string) => {
    setSessionState(await doLogin(username, password));
  }, []);

  const logout = useCallback(() => {
    doLogout();
    setSessionState(null);
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      session,
      isAdmin: session?.role === 'admin',
      isAuthenticated: session !== null,
      login,
      logout,
      expire: logout,
    }),
    [session, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside an AuthProvider');
  return value;
}
