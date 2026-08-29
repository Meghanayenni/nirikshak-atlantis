/**
 * Authentication against the backend's HTTP Basic surface (decision D25).
 *
 * The backend deliberately ships no sessions, refresh tokens, registration or
 * password reset — "each is a real feature with its own failure modes, and none
 * is needed to make the API safe to expose". So logging in means proving the
 * credentials work, and the only honest way to do that is to call an
 * authenticated endpoint and see whether it answers.
 *
 * **The role comes from `/users/me`, never from the login form.** A frontend
 * that let a caller assert their own role would be theatre: the backend decides,
 * and every admin route is enforced there with a 403 regardless of what this
 * client believes.
 */
import type { User } from '@/types/api';

import { basicToken, request, setSession, type Session } from './api';

export async function login(username: string, password: string): Promise<Session> {
  const token = basicToken(username, password);

  // Proves the credentials AND returns the authoritative role, in one call.
  const me = await request<User>('/users/me', { token });

  const session: Session = {
    username: me.username,
    token,
    role: me.role,
    userId: me.user_id,
  };
  setSession(session);
  return session;
}

export function logout(): void {
  setSession(null);
}

export function whoami(): Promise<User> {
  return request<User>('/users/me');
}
