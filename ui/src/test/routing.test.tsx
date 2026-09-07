/**
 * Routing, the landing page and the drawer.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PIPELINE_NAV } from '@/layouts/navigation';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

describe('the landing page', () => {
  it('carries no navigation bar and one way in', () => {
    mockApi([]);
    renderApp('/');

    expect(screen.getByRole('heading', { name: 'Nirikshak' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /sign in/i })).toBeInTheDocument();
    expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByRole('button', { name: /open navigation/i })).toBeNull();
  });
});

describe('authentication', () => {
  it('sends an unauthenticated visitor to the sign-in screen', async () => {
    mockApi([]);
    renderApp('/devices');

    expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('offers no role selector and no self-registration', async () => {
    mockApi([]);
    renderApp('/login');

    expect(await screen.findByText(/no self-registration/i)).toBeInTheDocument();
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(screen.queryByRole('link', { name: /sign up|register|create account/i })).toBeNull();
  });
});

describe('the navigation drawer', () => {
  function stub() {
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: {}, status: 403 },
      { match: '/training/examples', body: {}, status: 403 },
      { match: '/health', body: FIXTURES.health },
    ]);
  }

  it('stays closed until it is asked for', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp('/devices');

    await screen.findByRole('button', { name: /open navigation/i });
    const drawer = document.querySelector('nav[aria-label="Main"]') as HTMLElement;
    expect(drawer).toHaveAttribute('aria-hidden', 'true');
    expect(drawer.className).toContain('-translate-x-full');
  });

  it('opens on click and lists the pipeline in order', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: /open navigation/i }));

    const drawer = screen.getByRole('navigation', { name: /main/i });
    expect(drawer).toHaveAttribute('aria-hidden', 'false');

    const labels = Array.from(drawer.querySelectorAll('a')).map((link) =>
      link.textContent?.replace(/\s+/g, ' ').trim(),
    );
    // Ingest → Parse → Evaluate → Resolve → Report, in that order.
    for (const [index, item] of PIPELINE_NAV.entries()) {
      expect(labels[index]).toContain(item.label);
    }
  });

  it('closes again once a destination is chosen', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: /open navigation/i }));
    await user.click(screen.getByRole('link', { name: /compliance/i }));

    expect(document.querySelector('nav[aria-label="Main"]')).toHaveAttribute(
      'aria-hidden',
      'true',
    );
  });
});

describe('the device workspace', () => {
  it('opens a device in place rather than navigating to a page', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: {}, status: 403 },
      { match: '/training/examples', body: {}, status: 403 },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');

    // The list and the workspace are on screen together.
    expect(await screen.findByRole('searchbox', { name: /search devices/i })).toBeInTheDocument();
    expect(await screen.findByRole('tab', { name: /findings/i })).toBeInTheDocument();
  });
});
