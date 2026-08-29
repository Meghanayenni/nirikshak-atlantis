/**
 * Routing, authentication and role separation.
 *
 * The assertions that matter are the negative ones. A user must not be shown an
 * administrator's navigation, and an unauthenticated visitor must not reach a
 * page at all — though neither of those is the security control. The backend
 * refuses the request regardless, and these tests check that the interface does
 * not mislead somebody into thinking it will work.
 */
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ADMIN_SESSION,
  FIXTURES,
  USER_SESSION,
  mockApi,
  renderApp,
  signIn,
} from './helpers';

const BASE_ROUTES = [
  { match: '/ingest/devices', body: FIXTURES.devices },
  { match: '/ingest/files', body: { count: 0, files: [] } },
  { match: '/compliance/audits', body: FIXTURES.audits },
  { match: '/fleet/baseline', body: FIXTURES.fleet },
  { match: '/health', body: FIXTURES.health },
  { match: '/users/me', body: FIXTURES.users.users[0] },
];

beforeEach(() => {
  signIn(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
});

describe('authentication', () => {
  it('sends an unauthenticated visitor to the login screen', async () => {
    mockApi(BASE_ROUTES);
    renderApp('/dashboard');

    expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument();
    expect(screen.queryByText(/security command centre/i)).not.toBeInTheDocument();
  });

  it('offers no role selector and no self-registration', async () => {
    mockApi(BASE_ROUTES);
    renderApp('/login');

    await screen.findByRole('button', { name: /sign in/i });
    expect(screen.queryByLabelText(/role/i)).not.toBeInTheDocument();
    expect(screen.getByText(/created by an administrator/i)).toBeInTheDocument();
    expect(screen.getByText(/your role is decided by the server/i)).toBeInTheDocument();
  });

  it('surfaces the backend message when credentials are refused', async () => {
    mockApi([
      { match: '/users/me', status: 401, body: { detail: 'invalid username or password' } },
    ]);
    renderApp('/login');

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'root' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid username or password/i);
  });
});

describe('role-aware navigation', () => {
  it('shows administrator entries to an admin', async () => {
    mockApi(BASE_ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/dashboard');

    const nav = await screen.findByRole('navigation', { name: /main/i });
    expect(nav).toHaveTextContent('Prioritisation');
    expect(nav).toHaveTextContent('Training Center');
    expect(nav).toHaveTextContent('Users');
    expect(nav).toHaveTextContent('Fleet-wide');
  });

  it('does not show administrator entries to a user', async () => {
    mockApi(BASE_ROUTES);
    signIn(USER_SESSION);
    renderApp('/dashboard');

    const nav = await screen.findByRole('navigation', { name: /main/i });
    expect(nav).not.toHaveTextContent('Training Center');
    expect(nav).not.toHaveTextContent('Users');
    expect(nav).toHaveTextContent('My Devices');
    expect(nav).toHaveTextContent('My resources');
  });

  it('refuses an admin route to a user and says the server enforces it', async () => {
    mockApi(BASE_ROUTES);
    signIn(USER_SESSION);
    renderApp('/training');

    expect(await screen.findByText(/administrator access required/i)).toBeInTheDocument();
    expect(screen.getByText(/enforced by the server/i)).toBeInTheDocument();
  });

  it('shows the fleet heading to an admin and the personal one to a user', async () => {
    mockApi(BASE_ROUTES);
    signIn(ADMIN_SESSION);
    const admin = renderApp('/dashboard');
    expect(await screen.findByText(/security command centre/i)).toBeInTheDocument();
    admin.unmount();

    signIn(USER_SESSION);
    renderApp('/dashboard');
    await waitFor(() =>
      expect(screen.getByText(/my security dashboard/i)).toBeInTheDocument(),
    );
  });
});

describe('unknown routes', () => {
  it('renders a not-found page rather than a blank screen', async () => {
    mockApi(BASE_ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/no-such-page');

    expect(await screen.findByText(/page not found/i)).toBeInTheDocument();
  });
});
