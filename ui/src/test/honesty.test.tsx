/**
 * The invariants this interface exists to hold.
 *
 * Every assertion here is a rule from DEVELOPER_GUIDE.md §10 or a decision that would be
 * silently reversible by an ordinary-looking edit. A screen can be redesigned
 * freely; it may not start claiming something the backend did not say.
 */
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { RemediationPanel } from '@/components/domain/RemediationPanel';
import { VerdictCounts } from '@/components/domain/VerdictCounts';
import { InferredMarker, VerdictChip } from '@/components/domain/Verdict';
import type { RemediationRef } from '@/types/api';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

const NO_SNIPPET: RemediationRef = {
  outcome: 'no_snippet',
  statement: 'No vetted remediation is available for this platform and rule.',
  snippet_id: null,
  commands: [],
  rollback: [],
  vetted_by: null,
  reference: null,
};

describe('verdict semantics (DEVELOPER_GUIDE.md §10)', () => {
  it('never relies on colour alone — every verdict carries a text label', () => {
    const { container } = render(
      <>
        <VerdictChip verdict="pass" />
        <VerdictChip verdict="fail" />
        <VerdictChip verdict="unknown" />
        <VerdictChip verdict="not_applicable" />
      </>,
    );
    for (const label of ['PASS', 'FAIL', 'UNKNOWN', 'N/A']) {
      expect(container.textContent).toContain(label);
    }
  });

  it('draws UNKNOWN dashed and neutral, never amber', () => {
    const { container } = render(<VerdictChip verdict="unknown" />);
    const chip = container.firstElementChild as HTMLElement;
    expect(chip.className).toContain('border-dashed');
    expect(chip.className).toContain('unknown');
    // The inferred palette is the amber one. Abstention must never borrow it.
    expect(chip.className).not.toContain('inferred');
  });

  it('gives FAIL the heaviest treatment and PASS the lightest', () => {
    const fail = render(<VerdictChip verdict="fail" />).container
      .firstElementChild as HTMLElement;
    expect(fail.className).toContain('bg-fail');
    expect(fail.className).toContain('text-white');
    expect(fail.className).toContain('font-semibold');

    const pass = render(<VerdictChip verdict="pass" />).container
      .firstElementChild as HTMLElement;
    expect(pass.className).toContain('bg-pass-bg');
    expect(pass.className).not.toContain('font-semibold');
  });

  it('marks an inferred value distinctly and offers no way to suppress it', () => {
    const { container } = render(<InferredMarker />);
    expect(container.textContent).toContain('INFERRED');
    // No prop exists to hide it. If one is ever added, this fails.
    expect(InferredMarker.length).toBe(0);
  });

  it('reports verdicts as counts, never as a compliance percentage', () => {
    const { container } = render(
      <VerdictCounts counts={{ pass: 3, fail: 1, unknown: 2, not_applicable: 0 }} />,
    );
    expect(container.textContent).not.toMatch(/%/);
    expect(container.textContent).toContain('Unknown');
  });
});

describe('no invented data', () => {
  it('shows the resolver statement and no command while the library is empty', () => {
    const { container } = render(<RemediationPanel remediation={NO_SNIPPET} />);
    expect(container.textContent).toContain('No vetted remediation is available');
    expect(container.querySelector('pre')).toBeNull();
  });

  it('renders a command only when the vetted library supplied one', () => {
    const { container } = render(
      <RemediationPanel
        remediation={{
          ...NO_SNIPPET,
          outcome: 'resolved',
          statement: 'A vetted snippet exists.',
          snippet_id: 'snip-1',
          commands: ['no ip http server'],
          rollback: ['ip http server'],
          vetted_by: 'a.operator',
          reference: 'vendor guide 4.2',
        }}
      />,
    );
    expect(container.querySelector('pre')?.textContent).toBe('no ip http server');
    expect(container.textContent).toContain('a.operator');
  });

  it('renders no framework identifier while every rule ships an empty list', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: { steps: [] }, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: { size: 0, confirmable: 0, entries: [] }, status: 403 },
      { match: '/training/examples', body: { count: 0, examples: [] }, status: 403 },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();

    await screen.findByRole('tab', { name: /findings/i });
    await user.click(screen.getByRole('tab', { name: /findings/i }));
    await user.click((await screen.findAllByRole('button', { name: /expand finding/i }))[0]);

    expect(await screen.findByText(/no framework control is mapped/i)).toBeInTheDocument();
    // No CIS / NIST / STIG / ISO identifier may appear anywhere on the screen.
    expect(document.body.textContent).not.toMatch(/\b(CIS|NIST|STIG|ISO)[- ]?\d/);
  });

  it('states that exposure was undetermined rather than showing a rank', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
      { match: '/compliance/audits/aud-1/remediation', body: { steps: [] }, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: {}, status: 403 },
      { match: '/training/examples', body: {}, status: 403 },
      { match: '/health', body: FIXTURES.health },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('tab', { name: /findings/i }));
    await user.click((await screen.findAllByRole('button', { name: /expand finding/i }))[0]);

    expect(await screen.findByText(/exposure was not determined/i)).toBeInTheDocument();
    expect(screen.queryByText(/^#\d+$/)).toBeNull();
  });
});

describe('DEF-3 — a content hash is not a device identity', () => {
  it('labels devices by hostname, not by the configuration hash', async () => {
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

    expect(await screen.findByRole('heading', { name: 'rtr-core-01' })).toBeInTheDocument();
    // The full hash is never printed as a name.
    expect(document.body.textContent).not.toContain(FIXTURES.devices.devices[0].device_id);
  });

  it('calls the hash a configuration file, never a device id', async () => {
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
    await waitFor(() => expect(screen.getByText(/configuration file/i)).toBeInTheDocument());
  });
});
