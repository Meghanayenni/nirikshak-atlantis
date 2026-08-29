/**
 * Error handling, evidence, and the confirmation a destructive action requires.
 *
 * The API-failure tests matter most. A screen that swallowed a 403 and rendered
 * an empty table would tell an operator their fleet is clean when the truth is
 * that they were refused — which is the same class of mistake as showing an
 * empty outliers list for an uncomparable cohort.
 */
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { EvidenceViewer } from '@/components/domain/EvidenceViewer';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, renderWithProviders, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
});

const BASE = [
  { match: '/users/me', body: FIXTURES.users.users[0] },
  { match: '/health', body: FIXTURES.health },
  { match: '/ingest/files', body: { count: 0, files: [] } },
];

describe('API failures reach the screen', () => {
  it('shows the backend detail and a retry when a request fails', async () => {
    mockApi([
      ...BASE,
      { match: '/ingest/devices', status: 500, body: { detail: 'operational store is unreachable' } },
      { match: '/compliance/audits', body: FIXTURES.audits },
    ]);
    signIn(ADMIN_SESSION);
    renderApp('/devices');

    expect(await screen.findByText(/operational store is unreachable/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });

  it('does not render an empty table when the caller was refused', async () => {
    mockApi([
      ...BASE,
      { match: '/fleet/baseline', status: 403, body: { detail: 'admin role required' } },
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits', body: FIXTURES.audits },
    ]);
    signIn(ADMIN_SESSION);
    renderApp('/prioritisation');

    expect(await screen.findByText(/admin role required/i)).toBeInTheDocument();
    // A refusal must never be presented as "no deviations found".
    expect(screen.queryByText(/no deviations reported/i)).not.toBeInTheDocument();
  });

  it('reports a network failure as a network failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    signIn(ADMIN_SESSION);
    renderApp('/devices');

    expect(await screen.findByText(/could not reach the nirikshak api/i)).toBeInTheDocument();
  });

  it('treats an unparsable body as a failure, not as an empty result', async () => {
    mockApi([...BASE, { match: '/ingest/devices', text: 'not json at all' }]);
    signIn(ADMIN_SESSION);
    renderApp('/devices');

    expect(await screen.findByText(/could not be parsed as json/i)).toBeInTheDocument();
  });
});

describe('evidence viewer', () => {
  const evidence = {
    file_id: 'file-1',
    file_path: 'c0/config.cfg',
    line_start: 42,
    line_end: 42,
    raw_line: 'transport input telnet ssh',
    cite: 'c0/config.cfg:42',
  };

  it('shows the operator’s own lines and marks the cited one', async () => {
    mockApi([
      {
        match: '/ingest/files/file-1/lines',
        body: {
          file_id: 'file-1',
          total_lines: 60,
          lines: [
            { line_number: 41, text: ' exec-timeout 10 0', sha256: 'a' },
            { line_number: 42, text: ' transport input telnet ssh', sha256: 'b' },
            { line_number: 43, text: ' login authentication default', sha256: 'c' },
          ],
        },
      },
    ]);
    signIn(ADMIN_SESSION);
    renderWithProviders(<EvidenceViewer evidence={evidence} />);

    expect(await screen.findByText(/transport input telnet ssh/)).toBeInTheDocument();
    // Surrounding context, so the line can be read in place.
    expect(screen.getByText(/exec-timeout 10 0/)).toBeInTheDocument();

    // The cited row is marked for assistive technology, not by colour alone.
    const cited = screen.getByText(/transport input telnet ssh/).closest('tr');
    expect(cited).toHaveAttribute('aria-current', 'true');
  });

  it('reports a failure to read the source rather than showing nothing', async () => {
    mockApi([
      { match: '/ingest/files/file-1/lines', status: 404, body: { detail: 'file not found' } },
    ]);
    signIn(ADMIN_SESSION);
    renderWithProviders(<EvidenceViewer evidence={evidence} />);

    expect(await screen.findByText(/file not found/i)).toBeInTheDocument();
  });
});

describe('destructive actions', () => {
  it('names the subject and the consequence, and does nothing until confirmed', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open
        onClose={() => {}}
        onConfirm={onConfirm}
        title="Disable account"
        subject="alice"
        consequence="This account will no longer be able to authenticate."
        confirmLabel="Disable account"
      />,
    );

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.getByText(/no longer be able to authenticate/i)).toBeInTheDocument();

    // Nothing has happened yet.
    expect(onConfirm).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /disable account/i }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('closes on Escape without performing the action', () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        open
        onClose={onClose}
        onConfirm={onConfirm}
        title="Disable account"
        subject="alice"
        consequence="…"
      />,
    );

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('requires confirmation before disabling a user', async () => {
    const { calls } = mockApi([
      ...BASE,
      { match: '/users', body: FIXTURES.users },
    ]);
    signIn(ADMIN_SESSION);
    renderApp('/users');

    // The signed-in admin's own Disable button is correctly disabled, so target
    // alice's row specifically rather than whichever button comes first.
    const aliceRow = (await screen.findByText('alice')).closest('tr')!;
    fireEvent.click(within(aliceRow).getByRole('button', { name: /^disable$/i }));

    // The dialog is open and the request has NOT been sent.
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(calls.some((c) => c.includes('/disable'))).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: /disable account/i }));
    await waitFor(() => expect(calls.some((c) => c.includes('/disable'))).toBe(true));
  });
});
