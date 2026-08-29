/**
 * Account management. Every call here is admin-only at the backend.
 *
 * `disable` is the one destructive operation the API actually exposes, so it is
 * the one the confirmation dialog guards. There is deliberately no delete: the
 * backend disables accounts rather than removing them, which keeps the ownership
 * of earlier audits resolvable.
 *
 * `POST /users` is account *creation by an administrator*, not public sign-up.
 * The login screen says so rather than offering a register form that would
 * always 403.
 */
import type { Role, User, UserList } from '@/types/api';

import { request } from './api';

export async function listUsers(): Promise<User[]> {
  return (await request<UserList>('/users')).users;
}

export function createUser(username: string, password: string, role: Role): Promise<User> {
  return request<User>('/users', { method: 'POST', body: { username, password, role } });
}

export function disableUser(userId: string): Promise<{ user_id: string; disabled: boolean }> {
  return request<{ user_id: string; disabled: boolean }>(`/users/${userId}/disable`, {
    method: 'POST',
  });
}
