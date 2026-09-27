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
  it('shows the resolver statement and no command when no vetted snippet exists', () => {
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

  // Replaces "renders no framework identifier while every rule ships an empty
  // list" (ADR 0057). Its premise stopped being true at P17, when every rule was
  // mapped to NIST; it went on passing only because the fixtures still shipped
  // empty lists, so the suite defended a string the product should not say.
  async function openFirstFinding(findings: unknown) {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits/aud-1/findings', body: findings },
      { match: '/compliance/audits/aud-1/remediation', body: { steps: [] }, status: 404 },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: { size: 0, confirmable: 0, entries: [] }, status: 403 },
      { match: '/training/examples', body: { count: 0, examples: [] }, status: 403 },
    ]);
    renderApp('/devices');
    const user = userEvent.setup();
    await screen.findByRole('tab', { name: /findings/i });
    await user.click(screen.getByRole('tab', { name: /findings/i }));
    return { user, expanders: await screen.findAllByRole('button', { name: /expand finding/i }) };
  }

  it('shows each mapped control with its edition and project-asserted provenance', async () => {
    const { user, expanders } = await openFirstFinding(FIXTURES.findings);
    await user.click(expanders[0]);

    const mapped = await screen.findByRole('list', { name: /mapped controls/i });
    expect(mapped).toHaveTextContent('CISC-ND-000140');
    expect(mapped).toHaveTextContent('edition V3R7 (2026-04-01)');
    expect(mapped).toHaveTextContent('CM-07');
    expect(mapped).toHaveTextContent(/project asserted/i);
    expect(document.body.textContent).not.toMatch(/no framework control is mapped/i);
  });

  it('shows a declined mapping with the reason the rule records', async () => {
    const { user, expanders } = await openFirstFinding(FIXTURES.findings);
    await user.click(expanders[1]);

    const declined = await screen.findByRole('list', { name: /declined mappings/i });
    expect(declined).toHaveTextContent('CISC-ND-000720');
    expect(declined).toHaveTextContent(/not mapped/i);
  });

  it('says why mappings are withheld rather than that none exist', async () => {
    const withheld = {
      ...FIXTURES.findings,
      framework_view: {
        ...FIXTURES.findings.framework_view,
        attached: false,
        withheld_reason:
          'This run was evaluated under rulepack 1.0.0 before rulepack contents were recorded; re-run the audit to see them.',
      },
      findings: FIXTURES.findings.findings.map((f) => ({ ...f, frameworks: [], declined: [] })),
    };
    const { user, expanders } = await openFirstFinding(withheld);
    await user.click(expanders[0]);

    expect(await screen.findByText(/control mappings are not shown for this run/i)).toBeInTheDocument();
    expect(document.body.textContent).toMatch(/re-run the audit/i);
    expect(document.body.textContent).not.toMatch(/no framework control is mapped/i);
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
    ]);

    renderApp('/devices');
    await waitFor(() => expect(screen.getByText(/configuration file/i)).toBeInTheDocument());
  });
});
