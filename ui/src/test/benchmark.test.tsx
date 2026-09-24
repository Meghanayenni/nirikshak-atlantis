/**
 * The benchmark selector (ADR 0058) — the interface shows what the API decided.
 *
 * Options come from `/compliance/audits/frameworks/device/{id}`. The interface
 * adds none, removes none, and decides no scope: an unsourced framework is
 * absent because the API omits it, a benchmark that does not describe the
 * device says so in the API's words, and a refused audit shows the API's 409
 * sentence where the operator is looking.
 */
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

const DEVICE = FIXTURES.devices.devices[0].device_id;

const OPTIONS = {
  file_id: DEVICE,
  platform: { vendor: 'juniper', os_family: 'junos', os_version: null },
  frameworks: [
    {
      framework: 'cis',
      document: 'CIS Cisco IOS XE 17.x Benchmark',
      edition: 'v2.2.1 (2025-07-17)',
      describes_device: false,
      reason:
        "CIS Cisco IOS XE 17.x Benchmark v2.2.1 (2025-07-17) is written for cisco/ios with a release matching '^17\\\\.'; this device is juniper/junos, which the edition does not describe.",
    },
    {
      framework: 'nist',
      document: 'NIST SP 800-53 Rev 5 — OSCAL catalog',
      edition: '5.2.0',
      describes_device: true,
      reason: null,
    },
    {
      framework: 'stig',
      document: 'DISA Cisco IOS XE Router NDM STIG — XCCDF manual benchmark',
      edition: 'V3R7 (2026-04-01)',
      describes_device: false,
      reason: 'DISA … is written for cisco/ios; this device is juniper/junos, which the edition does not describe.',
    },
  ],
  note: 'Mappings from NIRIKSHAK checks to these controls are asserted by this project.',
};

const REFUSAL =
  'none of the selected frameworks describes this device, so auditing against them would report zero findings — which reads as compliance. STIG: this device is juniper/junos, which the edition does not describe.';

function stub(extra: Parameters<typeof mockApi>[0] = []) {
  signIn(ADMIN_SESSION);
  return mockApi([
    ...extra,
    { match: '/compliance/audits/frameworks/device/', body: OPTIONS },
    { match: '/ingest/devices', body: FIXTURES.devices },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    { match: '/compliance/audits/aud-1/remediation', body: { steps: [] }, status: 404 },
    { match: '/compliance/audits', body: FIXTURES.audits },
    { match: '/training/queue', body: { size: 0, confirmable: 0, entries: [] }, status: 403 },
    { match: '/training/examples', body: { count: 0, examples: [] }, status: 403 },
    { match: '/health', body: FIXTURES.health },
  ]);
}

describe('the benchmark selector', () => {
  it('offers exactly the frameworks the API lists, and no other', async () => {
    stub();
    renderApp('/devices');
    const scope = await screen.findByRole('region', { name: /benchmark scope/i });

    expect(await within(scope).findAllByRole('checkbox')).toHaveLength(3);
    // ISO is not sourced; the API omits it, so it is not here — not even unchecked.
    expect(scope.textContent).not.toMatch(/\bISO\b/);
  });

  it('says plainly when a benchmark does not describe the device, in the API’s words', async () => {
    stub();
    renderApp('/devices');
    const scope = await screen.findByRole('region', { name: /benchmark scope/i });

    expect(await within(scope).findByText(/Does not describe this device — CIS Cisco IOS XE/)).toBeInTheDocument();
    expect(within(scope).getByText('Describes this device.')).toBeInTheDocument();
  });

  it('sends the selection and shows a 409 refusal as a reason, not as an empty result', async () => {
    const { calls } = stub([
      { match: /\/compliance\/audits\?file_id=.*framework=stig/, body: { detail: REFUSAL }, status: 409 },
    ]);
    renderApp('/devices');
    const user = userEvent.setup();
    const scope = await screen.findByRole('region', { name: /benchmark scope/i });

    await user.click(await within(scope).findByRole('checkbox', { name: /stig/i }));
    await user.click(screen.getByRole('button', { name: /run audit|re-run audit/i }));

    const alert = await within(scope).findByRole('alert');
    expect(alert).toHaveTextContent(/audit refused — nothing was run/i);
    expect(alert).toHaveTextContent('none of the selected frameworks describes this device');
    expect(calls.some((url) => url.includes('framework=stig'))).toBe(true);
  });

  it('shows what a scoped run left out, with each reason', async () => {
    stub([
      {
        match: '/compliance/audits/aud-1/findings',
        body: {
          ...FIXTURES.findings,
          framework_view: {
            ...FIXTURES.findings.framework_view,
            selection: ['cis'],
            not_assessed: [
              {
                rule_id: 'NRK-HTTP-001',
                reason:
                  "CIS: CIS Cisco IOS XE 17.x v2.2.1 has no recommendation requiring the plaintext HTTP server be disabled. DISA's CISC-ND-000470 says the opposite.",
              },
            ],
          },
        },
      },
    ]);
    renderApp('/devices');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('tab', { name: /findings/i }));

    const runScope = await screen.findByRole('region', { name: /run scope/i });
    expect(runScope).toHaveTextContent(/Scoped to CIS/);
    const left = within(runScope).getByRole('list', { name: /not assessed/i });
    expect(left).toHaveTextContent('NRK-HTTP-001');
    expect(left).toHaveTextContent('CISC-ND-000470 says the opposite');
  });
});

describe('an audit that fails is never silent', () => {
  it('shows the refusal for an unscoped audit — silent from P13 until ADR 0058', async () => {
    const detail =
      'the platform for this file was not identified, so no vendor pack applies and nothing can be audited. This is UNKNOWN, not a failure.';
    stub([{ match: /\/compliance\/audits\?file_id=/, body: { detail }, status: 409 }]);
    renderApp('/devices');
    const user = userEvent.setup();

    await user.click(await screen.findByRole('button', { name: /run audit|re-run audit/i }));

    expect(await screen.findByText(/nothing to audit/i)).toBeInTheDocument();
    expect(screen.getByText(/This is UNKNOWN, not a failure/)).toBeInTheDocument();
  });
});
