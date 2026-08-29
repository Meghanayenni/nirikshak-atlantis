/**
 * The tests that carry the weight of this phase.
 *
 * The backend has four architecture guards over its own report template: it may
 * not claim an exposure ranking, may not print a framework identifier, may not
 * hard-code a remediation sentence, and may not call `device_id` a device
 * identity. Those guards encode *principles*, not template rules, so they are
 * mirrored here for the interface.
 *
 * Each of these would be trivially easy to violate by accident — a severity
 * sort, a placeholder "CIS 1.2.3", a hard-coded example command — and each would
 * make NIRIKSHAK claim something it deliberately refuses to claim.
 */
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PrioritisationPanel, VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { RemediationPanel } from '@/components/domain/RemediationPanel';
import { InferredMarker, VerdictChip } from '@/components/domain/Verdict';
import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
});

const ROUTES = [
  { match: '/ingest/devices', body: FIXTURES.devices },
  { match: '/ingest/files', body: { count: 0, files: [] } },
  { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
  { match: '/compliance/audits/aud-1/remediation', body: { steps: [] } },
  { match: '/compliance/audits/aud-1', body: FIXTURES.audits.audits[0] },
  { match: '/compliance/audits', body: FIXTURES.audits },
  { match: '/fleet/baseline', body: FIXTURES.fleet },
  { match: '/health', body: FIXTURES.health },
  { match: '/users/me', body: FIXTURES.users.users[0] },
];

describe('verdict semantics (DEVELOPER_GUIDE.md §10)', () => {
  it('never relies on colour alone — every verdict carries a text label', () => {
    render(
      <>
        <VerdictChip verdict="fail" />
        <VerdictChip verdict="pass" />
        <VerdictChip verdict="unknown" />
      </>,
    );
    expect(screen.getByText('FAIL')).toBeInTheDocument();
    expect(screen.getByText('PASS')).toBeInTheDocument();
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
  });

  it('draws UNKNOWN dashed and neutral, never amber', () => {
    const { container } = render(<VerdictChip verdict="unknown" />);
    const chip = container.firstElementChild as HTMLElement;

    // Dashed border and the neutral-slate token. Amber belongs to INFERRED and
    // must never mark an abstention: abstention sits off the severity axis, and
    // making it look like a weaker failure defeats Rule 3 at the presentation
    // layer.
    expect(chip.className).toContain('border-dashed');
    expect(chip.className).toContain('unknown');
    expect(chip.className).not.toContain('inferred');
    expect(chip.className).not.toContain('amber');
  });

  it('gives FAIL the heaviest treatment and PASS the lightest', () => {
    const { container: fail } = render(<VerdictChip verdict="fail" />);
    const { container: pass } = render(<VerdictChip verdict="pass" />);

    // FAIL: solid fill, reversed text, bold.
    expect((fail.firstElementChild as HTMLElement).className).toContain('bg-fail');
    expect((fail.firstElementChild as HTMLElement).className).toContain('text-white');
    expect((fail.firstElementChild as HTMLElement).className).toContain('font-semibold');
    // PASS: a light tint only.
    expect((pass.firstElementChild as HTMLElement).className).toContain('bg-pass-bg');
    expect((pass.firstElementChild as HTMLElement).className).not.toContain('text-white');
  });

  it('marks an inferred value distinctly and offers no way to suppress it', () => {
    render(<InferredMarker />);
    expect(screen.getByText('INFERRED')).toBeInTheDocument();
    // The component takes no props: there is nothing to pass that would hide it.
    expect(InferredMarker.length).toBe(0);
  });
});

describe('P12 — the ranking that is not produced', () => {
  it('states the refusal and its blockers rather than showing an order', () => {
    render(
      <PrioritisationPanel
        prioritisation={{
          ranked: false,
          reason:
            'Exposure could not be determined for any finding. Ranking by severity alone is ' +
            'deliberately not offered: severity alone must not determine remediation order.',
          determined: 0,
          undetermined: 7,
          blockers: { no_interface_data: 4, not_exposure_relevant: 3 },
        }}
      />,
    );

    expect(screen.getByText(/no exposure ranking was produced/i)).toBeInTheDocument();
    expect(screen.getByText(/severity alone must not determine remediation order/i)).toBeInTheDocument();
    expect(screen.getByText(/where the control lives is unknown/i)).toBeInTheDocument();
  });

  it('renders no rank column when the backend did not rank', async () => {
    mockApi(ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/audits/aud-1');

    await screen.findByText('NRK-TELNET-001');

    // The findings fixture carries no priority_rank, so the header must be absent.
    expect(screen.queryByRole('columnheader', { name: '#' })).not.toBeInTheDocument();
    expect(screen.getByText(/this is not an exposure ranking/i)).toBeInTheDocument();
  });

  it('reports peer baselines that established nothing, with the reason', async () => {
    mockApi(ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/prioritisation');

    expect(await screen.findByText(/no exposure ranking is produced/i)).toBeInTheDocument();
    // An empty outlier list must not read as a uniform fleet.
    expect(screen.getByText(/no cohort reached the minimum size/i)).toBeInTheDocument();
    expect(screen.getByText(/5 are required/i)).toBeInTheDocument();
  });
});

describe('no invented data', () => {
  it('renders no framework identifier while every rule ships an empty list', async () => {
    mockApi(ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/audits/aud-1/findings/aud-1%3Adev%3ANRK-TELNET-001');

    await screen.findByText(/this check maps to no framework control/i);

    const body = document.body.textContent ?? '';
    // The visual reference draws "CIS 1.2.3 · NIST AC-17 · STIG V-215807" as an
    // illustration. Shipping any of it would be inventing coverage.
    expect(body).not.toMatch(/CIS\s*\d+\.\d+/);
    expect(body).not.toMatch(/AC-17/);
    expect(body).not.toMatch(/V-2158\d\d/);
    expect(body).not.toMatch(/ISO\s*A\.\d/);
  });

  it('shows the resolver statement and no command while the library is empty', () => {
    render(
      <RemediationPanel
        remediation={{
          outcome: 'no_snippet',
          statement: 'No vetted remediation is available for this platform and rule.',
          snippet_id: null,
          commands: [],
          rollback: [],
          vetted_by: null,
          reference: null,
        }}
      />,
    );

    expect(
      screen.getByText(/no vetted remediation is available for this platform and rule/i),
    ).toBeInTheDocument();

    // No <pre> block exists unless the response carried commands, so there is
    // nowhere for an invented command to appear.
    expect(document.querySelector('pre')).toBeNull();
    expect(document.body.textContent).not.toMatch(/transport input ssh/);
    expect(document.body.textContent).not.toMatch(/configure terminal/);
  });

  it('renders a command only when the vetted library supplied one', () => {
    render(
      <RemediationPanel
        remediation={{
          outcome: 'resolved',
          statement: 'A vetted snippet applies.',
          snippet_id: 'snip-1',
          commands: ['line vty 0 4', 'transport input ssh'],
          rollback: ['transport input telnet ssh'],
          vetted_by: 'A. Engineer',
          reference: 'vendor-guide-12.3 §4.1',
        }}
      />,
    );

    expect(screen.getByText(/transport input ssh/)).toBeInTheDocument();
    // Rule 4 — never the command alone: rollback and attribution travel with it.
    expect(screen.getByText('Rollback')).toBeInTheDocument();
    expect(screen.getByText('A. Engineer')).toBeInTheDocument();
    expect(screen.getByText(/NIRIKSHAK does not apply these commands/i)).toBeInTheDocument();
  });

  it('reports verdicts as counts, never as a compliance percentage', () => {
    render(<VerdictCounts counts={{ pass: 7, fail: 1, unknown: 2, not_applicable: 0 }} />);

    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    // A single ratio would have to hide one of the three states.
    expect(document.body.textContent).not.toMatch(/\d+%/);
  });
});

describe('DEF-3 — a content hash is not a device identity', () => {
  it('labels devices by hostname, not by the configuration hash', async () => {
    mockApi(ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/devices');

    expect(await screen.findByText('rtr-core-01')).toBeInTheDocument();
    // The full hash must not be presented as the device's name.
    expect(
      screen.queryByText('c0f08477bb6ad93bf0da05c4269b87c38c815ecf1d492fadd28ce38af2601fb1'),
    ).not.toBeInTheDocument();
  });

  it('calls the identifier a configuration file id on the device page', async () => {
    mockApi(ROUTES);
    signIn(ADMIN_SESSION);
    renderApp('/devices/c0f08477bb6ad93bf0da05c4269b87c38c815ecf1d492fadd28ce38af2601fb1');

    // The phrase appears as the field label and again in the explanation below it.
    expect((await screen.findAllByText(/configuration file id/i)).length).toBeGreaterThan(0);
    // The sentence is split by an <em>, so match a contiguous fragment of it.
    expect(screen.getByText(/changes whenever the file is edited/i)).toBeInTheDocument();
  });
});
