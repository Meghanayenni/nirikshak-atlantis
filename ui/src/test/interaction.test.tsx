/**
 * Behaviour that must survive a redesign.
 *
 * A failed request has to reach the screen, a refusal has to read as a refusal
 * rather than as an empty result, and the report gate has to hold.
 */
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

/** Every endpoint the devices screen touches, with the queue refused. */
function stubDevices(overrides: { queueStatus?: number; queue?: unknown } = {}) {
  return mockApi([
    { match: '/ingest/devices', body: FIXTURES.devices },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
    { match: '/compliance/audits', body: FIXTURES.audits },
    {
      match: '/training/queue',
      status: overrides.queueStatus ?? 403,
      body: overrides.queue ?? { detail: 'admin role required' },
    },
    { match: '/training/examples', body: { count: 0, examples: [] } },
    { match: '/health', body: FIXTURES.health },
  ]);
}

describe('API failures reach the screen', () => {
  it('shows the backend detail and a retry when a request fails', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      {
        match: '/ingest/devices',
        status: 500,
        body: { detail: 'the operational database is not initialised' },
      },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');

    expect(
      await screen.findByText(/the operational database is not initialised/i),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });

  it('reads a refused capability as a refusal, not as an empty queue', async () => {
    signIn(ADMIN_SESSION);
    stubDevices({ queueStatus: 403 });

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /needs review/i }));

    expect(await screen.findByText(/administrator step/i)).toBeInTheDocument();
    // "Every line was recognised" would be the lie. It must not appear.
    expect(screen.queryByText(/every line was recognised/i)).toBeNull();
  });
});

describe('the report gate', () => {
  it('blocks the report and names what is outstanding', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      {
        match: '/training/queue',
        body: {
          size: 1,
          confirmable: 1,
          index: 'index',
          model: { available: false, summary: 'unavailable' },
          scrubbed: true,
          entries: [
            {
              cluster_id: 'c1',
              signature: 'set ssh <n>',
              line: 'set ssh proto-version 2',
              occurrences: 1,
              file_count: 1,
              confirmable: true,
              block_path: [],
              file_id: 'file-1',
              line_number: 10,
              state: 'model_unavailable',
              reason: 'no model',
              is_probability: false,
              confidence_note: 'ranking, not a probability',
              suggestions: [],
            },
          ],
        },
      },
      { match: '/training/examples', body: { count: 0, examples: [] } },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /report/i }));

    expect(await screen.findByText(/report is not available yet/i)).toBeInTheDocument();
    expect(screen.getByText(/await a decision/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /generate report/i })).toBeNull();
  });

  it('opens the report once nothing is outstanding', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      {
        match: '/training/queue',
        body: {
          size: 0,
          confirmable: 0,
          index: 'index',
          model: { available: false, summary: 'unavailable' },
          scrubbed: true,
          entries: [],
        },
      },
      { match: '/training/examples', body: { count: 0, examples: [] } },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /report/i }));

    expect(await screen.findByRole('button', { name: /generate report/i })).toBeInTheDocument();
  });
});

describe('local review marks', () => {
  it('says review marks are local and not part of the recorded log', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/audit/verify', body: { ok: true, checked: 3, algo: 'sha256' } },
      { match: '/audit/records', body: { verifiable: false, reason: 'filtered', count: 0, records: [] } },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/activity');

    await waitFor(() =>
      expect(screen.getByText(/notes in your browser, not recorded actions/i)).toBeInTheDocument(),
    );
  });
});
