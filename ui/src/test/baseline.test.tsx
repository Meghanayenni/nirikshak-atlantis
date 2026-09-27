/**
 * The peer-baseline card — one device against its cohort.
 *
 * Every state comes from `/fleet/baseline/device/{id}`; these tests stub that
 * response and check that the card says what the API said and nothing more.
 * Colour is asserted by what must be ABSENT: a deviation is not a verdict, so no
 * pass, fail or inferred colour may appear anywhere in the card.
 */
import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PeerBaseline } from '@/components/device/PeerBaseline';
import type { DeviceBaseline, DeviceBaselineField } from '@/types/api';

import { ADMIN_SESSION, FIXTURES, USER_SESSION, mockApi, renderWithProviders, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
});

const VERDICT_COLOUR = /\b(?:bg|text|border)-(?:pass|fail|inferred)\b/;

function row(field: string, extra: Partial<DeviceBaselineField> = {}): DeviceBaselineField {
  return {
    field,
    outcome: 'compared',
    device_state: 'present',
    majority_state: 'present',
    agreeing: 9,
    of_readable: 9,
    deviation: false,
    explanation: `9 of 9 readable device(s) in 'cisco/ios' are present for '${field}'`,
    ...extra,
  };
}

function baseline(extra: Partial<DeviceBaseline>): DeviceBaseline {
  return {
    device_id: 'file-1',
    cohort: 'cisco/ios',
    cohort_size: 9,
    floor: 5,
    status: 'compared',
    per_field: [],
    overall_deviation: false,
    is_verdict: false,
    note: 'A deviation from a peer group is an observation about the fleet, not a compliance verdict.',
    ...extra,
  };
}

function show(body: DeviceBaseline, session = ADMIN_SESSION) {
  signIn(session);
  const api = mockApi([
    { match: '/fleet/baseline/device/', body },
    { match: '/health', body: FIXTURES.health },
  ]);
  const view = renderWithProviders(<PeerBaseline deviceId="file-1" />);
  return { api, view };
}

const pills = (state?: string) =>
  screen
    .queryAllByRole('listitem')
    .filter((li) => state === undefined || li.getAttribute('data-state') === state);

describe('the peer-baseline card', () => {
  it('below the floor: one muted line, and no pills', async () => {
    const { view } = show(
      baseline({
        cohort: 'cisco/nxos',
        cohort_size: 1,
        status: 'cohort_too_small',
        per_field: [row('telnet_enabled', { outcome: 'cohort_too_small', majority_state: null })],
      }),
    );

    const line = await screen.findByText(/No peer baseline — cohort has/);
    expect(line.textContent).toBe('No peer baseline — cohort has 1 device(s), 5 needed for comparison');
    expect(line.className).toContain('text-muted');
    expect(pills()).toHaveLength(0);
    expect(view.container.innerHTML).not.toMatch(VERDICT_COLOUR);
  });

  it('above the floor with nothing compared: says so, and never "no deviation"', async () => {
    show(baseline({ cohort: 'juniper/junos', cohort_size: 5, status: 'nothing_compared' }));

    const line = await screen.findByText(/No peer baseline — cohort has/);
    expect(line.textContent).toBe('No peer baseline — cohort has 5 devices but no fields are compared');
    expect(pills()).toHaveLength(0);
    expect(screen.queryByText(/differs/i)).toBeNull();
  });

  it('compared, no deviation: neutral pills and dashed slate UNKNOWN, no verdict colour', async () => {
    const { view } = show(
      baseline({
        per_field: [
          row('telnet_enabled'),
          row('ssh_version', { device_state: 'unknown', agreeing: 8, of_readable: 8 }),
        ],
      }),
    );

    await screen.findByText(/No compared field differs from the cohort majority/);
    expect(screen.getByText(/Peer baseline —/).textContent).toBe('Peer baseline — 9 cisco/ios devices');
    expect(pills('compared')).toHaveLength(1);
    expect(pills('unknown')).toHaveLength(1);
    expect(pills('deviates')).toHaveLength(0);
    expect(pills('compared')[0].textContent).toContain('Present · Present 9 of 9');
    expect(view.container.innerHTML).not.toMatch(VERDICT_COLOUR);
    expect(screen.getByText(/field\(s\) unknown on this device, so not compared/)).toBeTruthy();
  });

  it('with a deviation: heavier ink, device state against the cohort and its count', async () => {
    const { view } = show(
      baseline({
        overall_deviation: true,
        per_field: [
          row('banner_present'),
          row('logging_hosts', { device_state: 'absent_default', agreeing: 8, deviation: true }),
        ],
      }),
    );

    await screen.findByText(/Differs from its cohort on/);
    const [deviating] = pills('deviates');
    expect(deviating.textContent).toContain('logging_hosts');
    expect(deviating.textContent).toContain('Absent — platform default vs cohort Present 8 of 9');
    expect(deviating.className).toContain('font-semibold');
    expect(deviating.className).toContain('border-2');
    // Listed first, so a collapsed strip can never hide it.
    expect(pills()[0]).toBe(deviating);
    // An anomaly, not a failure: no fail red, no inferred amber, no pass green.
    expect(view.container.innerHTML).not.toMatch(VERDICT_COLOUR);
  });

  it('an UNKNOWN field on the device is a slate pill whatever the cohort holds', async () => {
    show(
      baseline({
        per_field: [
          row('ssh_version', { device_state: 'unknown', majority_state: 'present' }),
          row('http_server_enabled', { device_state: 'unknown', majority_state: 'absent_default' }),
        ],
      }),
    );

    await screen.findByText(/No compared field differs/);
    const unknown = pills('unknown');
    expect(unknown).toHaveLength(2);
    for (const pill of unknown) {
      expect(within(pill).getByText('UNKNOWN')).toBeTruthy();
      expect(pill.className).toContain('border-dashed');
      expect(pill.className).toContain('text-unknown');
      expect(pill.textContent).not.toMatch(/Present|match/i);
    }
  });

  it('collapses after six pills and reveals the rest on request', async () => {
    const fields = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].map((f) => row(`field_${f}`));
    show(baseline({ per_field: fields }));

    await screen.findByText(/No compared field differs/);
    expect(pills()).toHaveLength(6);
    await userEvent.click(screen.getByRole('button', { name: 'Show all (2 more)' }));
    expect(pills()).toHaveLength(8);
    await userEvent.click(screen.getByRole('button', { name: 'Show fewer' }));
    expect(pills()).toHaveLength(6);
  });

  it('a refusal shows the API sentence; any other failure never prints the request URL', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/fleet/baseline/device/', body: { detail: 'this file is outside the first 200 files read' }, status: 409 },
      { match: '/health', body: FIXTURES.health },
    ]);
    const refused = renderWithProviders(<PeerBaseline deviceId="file-1" />);
    expect(
      (await screen.findByText(/No peer baseline —/)).textContent,
    ).toBe('No peer baseline — this file is outside the first 200 files read');
    refused.unmount();

    const hash = 'a'.repeat(64);
    mockApi([{ match: '/health', body: FIXTURES.health }]); // the baseline is unstubbed: a 404 naming the URL
    const failed = renderWithProviders(<PeerBaseline deviceId={hash} />);
    expect((await screen.findByText(/No peer baseline —/)).textContent).toBe(
      'No peer baseline — the request failed (404)',
    );
    expect(failed.container.textContent).not.toContain(hash);
  });

  it('is not shown, and not requested, for a non-admin', async () => {
    const { api } = show(baseline({}), USER_SESSION);
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByRole('region', { name: 'Peer baseline' })).toBeNull();
    expect(api.calls.some((url) => url.includes('/fleet/baseline'))).toBe(false);
  });
});
