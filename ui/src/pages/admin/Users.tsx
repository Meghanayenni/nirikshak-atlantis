/**
 * User management. Admin-only, enforced by the backend.
 *
 * `disable` is the only destructive operation the API exposes, so it is the one
 * the confirmation dialog guards. There is no delete: the backend disables
 * accounts rather than removing them, which keeps the ownership of earlier
 * audits resolvable.
 *
 * A device-assignment column is deliberately absent. Ownership is established by
 * who uploaded a configuration, and there is no endpoint to reassign it —
 * showing an "assigned devices" control that could not work would be worse than
 * not showing one.
 */
import { UserPlus } from 'lucide-react';
import { useState } from 'react';

import { ConfirmDialog, Dialog } from '@/components/ui/Dialog';
import { PageHeader } from '@/components/ui/Page';
import { Button, Card, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/useToast';
import { createUser, disableUser, listUsers } from '@/services/users';
import type { Role, User } from '@/types/api';
import { formatTimestamp } from '@/utils/format';

export function UsersPage() {
  const { session } = useAuth();
  const { push } = useToast();
  const users = useApi(() => listUsers(), []);

  const [target, setTarget] = useState<User | null>(null);
  const [creating, setCreating] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('user');

  const disable = useMutation(disableUser);
  const create = useMutation(createUser);

  async function onDisable() {
    if (!target) return;
    const result = await disable.run(target.user_id);
    if (result) {
      push('success', `${target.username} disabled`, 'The account can no longer authenticate.');
      users.reload();
      setTarget(null);
    } else {
      // The dialog stays open so the operator sees the failure in context.
      push('error', 'Could not disable the account', disable.error ?? undefined);
    }
  }

  async function onCreate() {
    const result = await create.run(username, password, role);
    if (result) {
      push('success', `${result.username} created`, `Role: ${result.role}.`);
      users.reload();
      setCreating(false);
      setUsername('');
      setPassword('');
      setRole('user');
    } else {
      push('error', 'Could not create the account', create.error ?? undefined);
    }
  }

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Accounts and roles. A user sees only what they uploaded; an admin sees the fleet."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <UserPlus className="h-3.5 w-3.5" aria-hidden="true" />
            New account
          </Button>
        }
      />

      <Card>
        {users.loading && <SkeletonRows rows={4} cols={5} />}
        {users.error && !users.loading && <ErrorState message={users.error} onRetry={users.reload} />}
        {users.data && users.data.length === 0 && <EmptyState title="No accounts" />}
        {users.data && users.data.length > 0 && (
          <Table caption="User accounts">
            <thead>
              <tr>
                <Th>Username</Th>
                <Th style={{ width: 120 }}>Role</Th>
                <Th style={{ width: 120 }}>Status</Th>
                <Th style={{ width: 190 }}>Created</Th>
                <Th style={{ width: 110 }}>Action</Th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((user) => (
                <tr key={user.user_id}>
                  <Td className="font-medium">
                    {user.username}
                    {user.user_id === session?.userId && (
                      <span className="ml-2 text-2xs text-muted">you</span>
                    )}
                  </Td>
                  <Td>
                    <span className="text-2xs uppercase tracking-wider text-ink-2">
                      {user.role}
                    </span>
                  </Td>
                  <Td>
                    <span
                      className={`inline-flex items-center h-[22px] px-2 rounded border text-2xs
                        ${
                          user.disabled
                            ? 'bg-unknown-bg text-unknown border-unknown-br border-dashed'
                            : 'bg-pass-bg text-pass border-pass-br'
                        }`}
                    >
                      {user.disabled ? 'DISABLED' : 'ACTIVE'}
                    </span>
                  </Td>
                  <Td className="text-muted">{formatTimestamp(user.created_at)}</Td>
                  <Td>
                    <Button
                      variant="danger"
                      onClick={() => setTarget(user)}
                      disabled={user.disabled || user.user_id === session?.userId}
                      title={
                        user.user_id === session?.userId
                          ? 'You cannot disable your own account'
                          : undefined
                      }
                    >
                      Disable
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <ConfirmDialog
        open={target !== null}
        onClose={() => setTarget(null)}
        onConfirm={onDisable}
        pending={disable.pending}
        title="Disable account"
        subject={target?.username ?? ''}
        consequence={
          'This account will no longer be able to authenticate. Configurations and audits it ' +
          'already owns are kept, so earlier results remain attributable. The account is not ' +
          'deleted and this action is not reversible from this interface.'
        }
        confirmLabel="Disable account"
      />

      <Dialog
        open={creating}
        onClose={() => setCreating(false)}
        title="Create account"
        footer={
          <>
            <Button onClick={() => setCreating(false)} disabled={create.pending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={onCreate}
              disabled={create.pending || !username || !password}
            >
              {create.pending ? 'Creating…' : 'Create'}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <label htmlFor="new-username" className="label block mb-1">
              Username
            </label>
            <input
              id="new-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full h-9 px-3 rounded border border-border-strong bg-paper text-[13px]"
            />
          </div>
          <div>
            <label htmlFor="new-password" className="label block mb-1">
              Password
            </label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-9 px-3 rounded border border-border-strong bg-paper text-[13px]"
            />
            <p className="mt-1 text-2xs text-muted">
              Stored only as a scrypt hash. The contract has no field a plaintext password could
              be written to.
            </p>
          </div>
          <div>
            <label htmlFor="new-role" className="label block mb-1">
              Role
            </label>
            <select
              id="new-role"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="w-full h-9 px-2 rounded border border-border-strong bg-paper text-[13px]"
            >
              <option value="user">user — sees only their own uploads</option>
              <option value="admin">admin — sees the fleet and may train packs</option>
            </select>
          </div>
        </div>
      </Dialog>
    </>
  );
}
