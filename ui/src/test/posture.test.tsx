/**
 * The compliance posture panel (ADR 0068).
 *
 * The gate is the backend's; these tests hold the two presentation rules that
 * make it mean something: a gated device shows no number, and the headline
 * percentage never renders without the undetermined count and the coverage line.
 */
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { CompliancePosture, PostureView } from '@/components/domain/CompliancePosture';
import type { DevicePosture } from '@/types/api';

import {
  ADMIN_SESSION,
  FIXTURES,
  USER_SESSION,
  mockApi,
  renderApp,
  renderWithProviders,
  signIn,
} from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

const DEVICE = 'dev-1';

function gated(
  state: DevicePosture['gate']['state'],
  extra: Partial<DevicePosture['gate']> = {},
  vendor: string | null = 'cisco',
): DevicePosture {
  return {
    device_id: DEVICE,
    platform: { vendor, os_family: vendor ? 'ios' : null, os_version: '15.2' },
    gate: {
      state,
      message: {
        not_audited: 'This configuration has not been audited, so there is nothing to score.',
        review_pending: 'Review all unrecognised lines before a compliance score is shown.',
        rerun_required: 'Re-run the audit to include your review decisions.',
        evaluation_file:
          'Reserved for measurement — scored by the evaluation harness, not reviewed.',
        ready: '',
      }[state],
      next_step: null,
      review: null,
      audit_id: 'aud-1',
      evaluated_at: '2026-09-28T10:00:00+00:00',
      last_decision_at: null,
      ...extra,
    },
    posture: null,
  };
}

/** Shaped from a live response for dist-sw-03 after review and a re-run. */
const READY: DevicePosture = {
  device_id: DEVICE,
  platform: { vendor: 'cisco', os_family: 'ios', os_version: '15.2' },
  gate: {
    state: 'ready',
    message: 'Every unrecognised line has a decision, and the latest run includes them all.',
    next_step: null,
    review: { reviewed: 40, total: 40 },
    audit_id: 'aud-1',
    evaluated_at: '2026-09-28T10:22:21+00:00',
    last_decision_at: '2026-09-12T06:48:48+00:00',
  },
  posture: {
    mappings_attached: true,
    withheld_reason: null,
    note: "Control mappings are this project's judgement, not from a published crosswalk. This is evidence about one configuration, not a certification.",
    unsourced: { iso: 'no ISO catalog has been sourced, so this report says nothing about it either way' },
    frameworks: [
      {
        framework: 'cis',
        document: 'CIS Cisco IOS XE 17.x Benchmark',
        edition: 'v2.2.1 (2025-07-17)',
        status: 'not_applicable',
        reason:
          'CIS Cisco IOS XE 17.x Benchmark v2.2.1 (2025-07-17) is written for cisco/ios with a release matching ^17\\.; this device is cisco/ios release 15.2, which the edition does not describe.',
        coverage: { assessed: 0, catalog_total: 84, basis: '84 live controls in the pinned index.' },
      },
      {
        framework: 'nist',
        document: 'NIST SP 800-53 Rev 5 — OSCAL catalog',
        edition: '5.2.0',
        status: 'assessed',
        reason: null,
        coverage: { assessed: 10, catalog_total: 1014, basis: '1014 live controls in the pinned index.' },
        // Every NIST mapping is partial: nothing is fully satisfied, and the
        // controls whose checks all passed are "no violation found".
        counts: { satisfied: 0, no_violation_found: 4, violated: 3, undetermined: 3, assessed: 10 },
        satisfied: [],
        no_violation_found: [
          {
            control_id: 'AC-08',
            edition: '5.2.0',
            state: 'no_violation_found',
            reason: 'Every mapped check passed (NRK-BANNER-001), but each tests only part of this control.',
            rules: [
              {
                rule_id: 'NRK-BANNER-001',
                verdict: 'pass',
                finding_id: 'fnd-banner',
                unknown_reason: null,
                absence_reason: null,
                evidence: [],
                coverage: 'partial',
                coverage_reason:
                  'The control specifies the notice\'s content and that it stay until acknowledged. This rule tests only that a message-of-the-day banner is configured.',
              },
            ],
          },
        ],
        violated: [
          {
            control_id: 'CM-07',
            edition: '5.2.0',
            state: 'violated',
            reason: 'NRK-TELNET-001 failed; one failing mapped check is enough.',
            rules: [
              {
                rule_id: 'NRK-TELNET-001',
                verdict: 'fail',
                finding_id: 'fnd-telnet',
                unknown_reason: null,
                absence_reason: null,
                coverage: 'partial',
                coverage_reason: 'Tests one part of the control.',
                evidence: [
                  {
                    file_id: 'f',
                    file_path: 'dist-sw-03.cfg',
                    line_start: 113,
                    line_end: 113,
                    raw_line: 'transport input telnet ssh',
                    cite: 'dist-sw-03.cfg:113',
                  },
                ],
                remediation: {
                  outcome: 'resolved',
                  statement: 'A vetted snippet exists for this platform and rule.',
                  snippet_id: 'snip-telnet',
                  commands: ['line vty 0 15', 'transport input ssh'],
                  rollback: ['line vty 0 15', 'transport input telnet ssh'],
                  vetted_by: 'a.reviewer',
                  reference: 'vendor guide',
                },
              },
            ],
          },
          {
            control_id: 'SC-08(01)',
            edition: '5.2.0',
            state: 'violated',
            reason: 'NRK-CIPHER-001 failed; one failing mapped check is enough.',
            rules: [
              {
                rule_id: 'NRK-CIPHER-001',
                verdict: 'fail',
                finding_id: 'fnd-cipher',
                unknown_reason: null,
                absence_reason: null,
                coverage: 'partial',
                coverage_reason: 'Tests one part of the control.',
                evidence: [
                  {
                    file_id: 'f',
                    file_path: 'dist-sw-03.cfg',
                    line_start: 55,
                    line_end: 55,
                    raw_line: 'ip ssh server algorithm encryption 3des-cbc',
                    cite: 'dist-sw-03.cfg:55',
                  },
                ],
                remediation: {
                  outcome: 'no_snippet',
                  statement: 'No vetted remediation is available for this platform and rule.',
                  snippet_id: null,
                  commands: [],
                  rollback: [],
                  vetted_by: null,
                  reference: null,
                },
              },
            ],
          },
        ],
        undetermined: [
          {
            control_id: 'AC-12',
            edition: '5.2.0',
            state: 'undetermined',
            reason: 'NRK-TIMEOUT-001 is UNKNOWN (conflicting_evidence).',
            rules: [
              {
                rule_id: 'NRK-TIMEOUT-001',
                verdict: 'unknown',
                finding_id: 'fnd-timeout',
                unknown_reason: 'conflicting_evidence',
                absence_reason: null,
                evidence: [],
                coverage: 'partial',
                coverage_reason: 'Tests the vty lines only.',
              },
            ],
          },
        ],
      },
    ],
  },
};

function renderView(data: DevicePosture) {
  return renderWithProviders(<PostureView data={data} deviceId={DEVICE} />);
}

describe('a gated device shows no number', () => {
  it.each(['not_audited', 'review_pending', 'rerun_required', 'evaluation_file'] as const)(
    '%s renders its message and no score, bar or percentage',
    (state) => {
      signIn(ADMIN_SESSION);
      const { container } = renderView(
        gated(state, state === 'review_pending' ? { review: { reviewed: 31, total: 48 } } : {}),
      );
      expect(container.textContent).not.toMatch(/%/);
      expect(container.textContent).not.toMatch(/assessed controls|catalog controls|satisfied/);
      expect(screen.queryByTestId('posture-bar')).toBeNull();
      expect(screen.queryByTestId('posture-headline')).toBeNull();
      expect(screen.getByRole('region', { name: /score withheld/i })).toBeInTheDocument();
    },
  );

  it('shows review progress and links an administrator to Needs review', () => {
    signIn(ADMIN_SESSION);
    renderView(gated('review_pending', { review: { reviewed: 31, total: 48 } }));
    expect(
      screen.getByText('Review all unrecognised lines before a compliance score is shown.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/lines reviewed/).textContent).toBe('31 of 48 lines reviewed');
    expect(screen.getByRole('link', { name: /needs review/i })).toHaveAttribute(
      'href',
      `/devices/${DEVICE}?tab=review`,
    );
  });

  it('tells a non-administrator who must finish the review, with no link to a step they cannot take', () => {
    signIn(USER_SESSION);
    renderView(
      gated('review_pending', {
        review: { reviewed: 0, total: 29 },
        next_step: 'An administrator must complete the review.',
      }),
    );
    expect(screen.getByText('An administrator must complete the review.')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /needs review/i })).toBeNull();
  });

  it('points a re-run at the device workspace', () => {
    signIn(ADMIN_SESSION);
    renderView(gated('rerun_required'));
    expect(screen.getByText('Re-run the audit to include your review decisions.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /re-run the audit/i })).toHaveAttribute(
      'href',
      `/devices/${DEVICE}`,
    );
  });

  it('sends an unidentified platform to the bootstrap page', () => {
    signIn(ADMIN_SESSION);
    renderView(gated('not_audited', {}, null));
    expect(screen.getByRole('link', { name: /bootstrap/i })).toHaveAttribute(
      'href',
      `/bootstrap/${DEVICE}`,
    );
  });

  it('withholds the score when the run was decided by other rules', () => {
    signIn(ADMIN_SESSION);
    const { container } = renderView({
      ...READY,
      posture: {
        ...READY.posture!,
        mappings_attached: false,
        withheld_reason: 'This run was evaluated under rulepack 1.0.0 before rulepack contents were recorded.',
        frameworks: [],
      },
    });
    expect(container.textContent).toContain('before rulepack contents were recorded');
    expect(container.textContent).not.toMatch(/%/);
    expect(screen.queryByTestId('posture-bar')).toBeNull();
  });
});

describe('the ready state', () => {
  it('never renders the bar or the fraction without the other counts, the legend and the coverage line', () => {
    signIn(ADMIN_SESSION);
    renderView(READY);
    const bars = screen.getAllByTestId('posture-bar');
    expect(bars).toHaveLength(1);
    for (const bar of bars) {
      const headline = bar.closest('[data-testid="posture-headline"]') as HTMLElement;
      expect(headline).not.toBeNull();
      expect(headline.textContent).not.toMatch(/%/);
      expect(headline.textContent).toContain('0 of 10 assessed controls fully satisfied');
      expect(headline.textContent).toContain('4 no violation found (partial check)');
      expect(headline.textContent).toContain('3 violated');
      expect(within(headline).getByRole('list', { name: 'Legend' }).children).toHaveLength(4);
      expect(headline.textContent).toContain('3 undetermined');
      expect(headline.textContent).toContain('10 of 1014 catalog controls assessed by NIRIKSHAK');
    }
  });

  it('draws undetermined dashed slate and never amber, with no severity on the panel', () => {
    signIn(ADMIN_SESSION);
    const { container } = renderView(READY);
    const segments = Array.from(screen.getByTestId('posture-bar').children) as HTMLElement[];
    expect(segments.map((s) => s.dataset.segment)).toEqual([
      'no_violation_found',
      'violated',
      'undetermined',
    ]);
    // No violation found is the pass colour at lower weight — outlined, not a new hue.
    expect(segments[0].className).toContain('border-pass');
    expect(segments[0].className).toContain('bg-pass-bg');
    expect(segments[2].className).toContain('border-dashed');
    expect(container.innerHTML).not.toMatch(/inferred/);
    expect(container.textContent).not.toMatch(/\b(critical|high|medium|low)\b/i);
  });

  it('draws a fully satisfied control solid, apart from a partial pass', () => {
    signIn(ADMIN_SESSION);
    const nist = READY.posture!.frameworks[1];
    renderView({
      ...READY,
      posture: {
        ...READY.posture!,
        frameworks: [
          {
            ...nist,
            counts: { satisfied: 1, no_violation_found: 1, violated: 1, undetermined: 1, assessed: 4 },
          },
        ],
      },
    });
    const segments = Array.from(screen.getByTestId('posture-bar').children) as HTMLElement[];
    expect(segments.map((s) => s.dataset.segment)).toEqual([
      'satisfied',
      'no_violation_found',
      'violated',
      'undetermined',
    ]);
    expect(segments[0].className).toContain('bg-pass');
    expect(segments[0].className).not.toContain('bg-pass-bg');
    expect(screen.getByTestId('posture-headline').textContent).toContain(
      '1 of 4 assessed controls fully satisfied',
    );
  });

  it('lists partial passes, collapsed, each saying it is a partial check with the reason', () => {
    signIn(ADMIN_SESSION);
    renderView(READY);
    const nist = screen.getByRole('region', { name: /NIST SP 800-53 Rev 5/ });
    const nvf = Array.from(nist.querySelectorAll('details')).find((d) =>
      d.textContent?.includes('No violation found'),
    )!;
    expect(nvf.open).toBe(false);
    expect(nvf.textContent).toContain('partial check: NIRIKSHAK tests only part of this control');
    expect(nvf.textContent).toContain('This rule tests only that a message-of-the-day banner');
  });

  it('states a framework that does not describe the device, never as a zero', () => {
    signIn(ADMIN_SESSION);
    renderView(READY);
    const cis = screen.getByRole('region', { name: /CIS Cisco IOS XE 17.x Benchmark posture/ });
    expect(cis.textContent).toContain('Not applicable');
    expect(cis.textContent).toContain('which the edition does not describe');
    expect(cis.textContent).not.toMatch(/%|0 of|satisfied/);
  });

  it('opens "Did not comply" by default with control, rule, cited line and fix', () => {
    signIn(ADMIN_SESSION);
    renderView(READY);
    const nist = screen.getByRole('region', { name: /NIST SP 800-53 Rev 5/ });
    const details = nist.querySelectorAll('details');
    expect(details[0].open).toBe(true);
    expect(details[0].textContent).toContain('Did not comply');
    const undetermined = Array.from(details).find((d) =>
      d.textContent?.includes('Could not be determined'),
    )!;
    expect(undetermined.open).toBe(false);
    // "Did not comply" first, then the partial passes, then the abstentions.
    expect(Array.from(details).map((d) => d.querySelector('summary')?.textContent)).toEqual([
      'Did not comply 2',
      'No violation found 1',
      'Could not be determined 1',
    ]);

    const violated = within(details[0] as HTMLElement);
    expect(violated.getByText('CM-07')).toBeInTheDocument();
    expect(violated.getByText('NRK-TELNET-001')).toBeInTheDocument();
    expect(violated.getByRole('link', { name: 'dist-sw-03.cfg:113' })).toHaveAttribute(
      'href',
      `/devices/${DEVICE}?tab=findings&finding=fnd-telnet`,
    );
    expect(details[0].textContent).toContain('transport input ssh');
    expect(details[0].textContent).toContain('Rollback');
    // No snippet: said plainly, and no command drawn for it.
    expect(details[0].textContent).toContain(
      'No vetted remediation is available for this platform and rule.',
    );
  });

  it('keeps the undetermined share visible, each with its UNKNOWN reason', async () => {
    signIn(ADMIN_SESSION);
    renderView(READY);
    const user = userEvent.setup();
    await user.click(screen.getByText(/Could not be determined/));
    expect(screen.getByText('AC-12')).toBeInTheDocument();
    expect(screen.getByText(/UNKNOWN — Conflicting evidence/i)).toBeInTheDocument();
  });
});

describe('browser review marks', () => {
  it('have no effect on the gate: the panel renders only what the API sent', async () => {
    signIn(ADMIN_SESSION);
    // Every remediation step of the run marked reviewed, in this browser.
    localStorage.setItem(
      'nirikshak.review.local',
      JSON.stringify({ 'aud-1': ['NRK-TELNET-001', 'NRK-CIPHER-001', 'NRK-HTTP-001'] }),
    );
    const { calls } = mockApi([
      {
        match: '/compliance/devices/',
        body: gated('review_pending', { review: { reviewed: 31, total: 48 } }),
      },
    ]);
    const { container } = renderWithProviders(<CompliancePosture deviceId={DEVICE} />);

    expect(
      await screen.findByText('Review all unrecognised lines before a compliance score is shown.'),
    ).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/%/);
    // The marks are never sent: the request carries the device and nothing else.
    expect(calls).toEqual([`/compliance/devices/${DEVICE}/posture`]);
  });
});

describe('the Compliance page', () => {
  it('lists a device with no run as not audited and opens its gate', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/devices/', body: gated('not_audited') },
      { match: '/compliance/audits', body: { count: 0, audits: [] } },
      { match: '/fleet/baseline', body: {}, status: 404 },
    ]);
    renderApp('/compliance');
    const user = userEvent.setup();

    expect(await screen.findByText('Not audited')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Expand' }));
    await waitFor(() =>
      expect(
        screen.getByText('This configuration has not been audited, so there is nothing to score.'),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByTestId('posture-bar')).toBeNull();
  });
});
