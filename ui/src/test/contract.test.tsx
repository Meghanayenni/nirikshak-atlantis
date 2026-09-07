/**
 * The response shapes this interface reads.
 *
 * These exist because a wrong TypeScript declaration is invisible at runtime.
 * `RemediationStep` once claimed `commands: string[]` at the top level while the
 * API nested them under `snippet`; the first code to dereference it threw during
 * render, React unmounted the entire root, and the application became a white
 * page. Every fixture in the suite had stubbed that endpoint as `404` or
 * `{steps: []}`, so nothing caught it.
 *
 * A test that renders a real step is the cheapest guard against that class of
 * bug returning.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

/** The full device workspace, with a remediation plan in the live shape. */
function stubWorkspace() {
  return mockApi([
    { match: '/ingest/devices', body: FIXTURES.devices },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    { match: '/compliance/audits/aud-1/remediation', body: FIXTURES.remediation },
    { match: '/compliance/audits', body: FIXTURES.audits },
    {
      match: '/training/queue',
      body: {
        size: 0,
        confirmable: 0,
        index: 'index',
        model: { available: false, summary: 'unavailable', package_installed: false, weights_present: false, airgap: false },
        scrubbed: true,
        entries: [],
      },
    },
    { match: '/training/examples', body: { count: 0, examples: [] } },
    { match: '/audit/verify', body: { ok: true, records_checked: 7, algo: 'sha256', tamper_evident_not_tamper_proof: true, first_failure_seq: null, failures: [] } },
    { match: '/audit/records', body: { verifiable: false, reason: 'filtered', count: 0, records: [] } },
    { match: '/health', body: FIXTURES.health },
  ]);
}

describe('the remediation plan contract', () => {
  it('renders a plan whose commands are nested under snippet', async () => {
    signIn(ADMIN_SESSION);
    stubWorkspace();

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /remediation/i }));

    // The workspace survived the plan: it did not blank the application.
    expect(await screen.findByRole('tab', { name: /overview/i })).toBeInTheDocument();

    // The resolved step is offered for review; the unresolved one is not.
    expect(await screen.findByRole('button', { name: /mark reviewed/i })).toBeInTheDocument();
    expect(screen.getByText(/no vetted remediation is available/i)).toBeInTheDocument();
    // Split across elements, so match on the composed text.
    expect(
      screen.getByText((_, node) => node?.textContent?.replace(/\s+/g, ' ').trim() === '0/1 reviewed'),
    ).toBeTruthy();
  });

  it('shows the vetted command without being asked, and never invents one', async () => {
    signIn(ADMIN_SESSION);
    stubWorkspace();

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /remediation/i }));

    // No second click. This screen answers "what do I type", and the answer used
    // to sit behind a disclosure that said only "Vetted command available" —
    // telling an operator the thing they came for exists, then making them ask
    // for it. A step that HAS a command now starts open.
    expect(await screen.findByText('no ip http server')).toBeInTheDocument();

    // §10 — "never the command alone". The rollback and the attribution are on
    // screen beside it, not one interaction further away.
    expect(screen.getByText('ip http server')).toBeInTheDocument();
    expect(screen.getByText(/a\.operator/)).toBeInTheDocument();
    expect(screen.getByText(/lockout risk/i)).toBeInTheDocument();

    // Still collapsible: an operator working a long plan can put a finished step
    // away.
    await user.click(await screen.findByRole('button', { name: /http/i }));
    expect(screen.queryByText('no ip http server')).not.toBeInTheDocument();
  });

  it('reports the chain length using the API’s own field name', async () => {
    signIn(ADMIN_SESSION);
    stubWorkspace();

    renderApp('/activity');

    expect(await screen.findByText(/chain verified/i)).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
  });
});

describe('a render fault is contained, never a blank page', () => {
  it('keeps the rest of the screen when one panel throws', async () => {
    signIn(ADMIN_SESSION);
    // A malformed plan: `steps` is not an array of steps at all.
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: { ...FIXTURES.remediation, steps: [{ rule_id: 'X' }] } },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: {}, status: 403 },
      { match: '/training/examples', body: {}, status: 403 },
      { match: '/health', body: FIXTURES.health },
    ]);

    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /remediation/i }));

    // Whatever happened, the shell and the device list are still there.
    expect(screen.getByRole('searchbox', { name: /search devices/i })).toBeInTheDocument();
    expect(document.body.textContent?.length ?? 0).toBeGreaterThan(100);
    spy.mockRestore();
  });
});
