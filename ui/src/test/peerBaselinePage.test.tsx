/**
 * The peer-baseline page — a device chosen from a list, and the same card.
 *
 * The card's own states are tested in `baseline.test.tsx`. These tests cover
 * where it now lives: its own admin-only page and drawer entry, and no longer
 * the device Overview tab.
 */
import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_SESSION, FIXTURES, USER_SESSION, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

const AUDITED = FIXTURES.devices.devices[0];
const NEVER_AUDITED = {
  device_id: 'f'.repeat(64),
  hostname: 'sw-unaudited-01',
  vendor: 'arista',
  os_family: 'eos',
  os_version: null,
  model: null,
};

const BASELINE = {
  device_id: AUDITED.device_id,
  cohort: 'cisco/ios',
  cohort_size: 9,
  floor: 5,
  status: 'compared',
  per_field: [
    {
      field: 'telnet_enabled',
      outcome: 'compared',
      device_state: 'present',
      majority_state: 'present',
      agreeing: 9,
      of_readable: 9,
      deviation: false,
      explanation: "9 of 9 readable device(s) in 'cisco/ios' are present for 'telnet_enabled'",
    },
  ],
  overall_deviation: false,
  is_verdict: false,
  note: 'A deviation from a peer group is an observation about the fleet, not a compliance verdict.',
};

function stub() {
  return mockApi([
    { match: '/fleet/baseline/device/', body: BASELINE },
    { match: '/ingest/devices', body: { count: 2, devices: [AUDITED, NEVER_AUDITED] } },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    { match: '/compliance/audits/aud-1/remediation', body: {}, status: 404 },
    { match: '/compliance/audits', body: FIXTURES.audits },
    { match: '/training/queue', body: {}, status: 403 },
    { match: '/training/examples', body: {}, status: 403 },
  ]);
}

async function openDrawer() {
  await userEvent.click(await screen.findByRole('button', { name: /open navigation/i }));
  return screen.getByRole('navigation', { name: /main/i });
}

describe('the peer-baseline drawer entry', () => {
  it('is listed for an administrator, between Vendor packs and Activity log', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp('/devices');

    const drawer = await openDrawer();
    const labels = Array.from(drawer.querySelectorAll('a')).map((a) => a.textContent ?? '');
    const at = labels.findIndex((label) => label.includes('Peer baseline'));
    expect(at).toBeGreaterThan(-1);
    expect(labels[at]).toContain('Compare devices in cohort');
    expect(labels[at - 1]).toContain('Vendor packs');
    expect(labels[at + 1]).toContain('Activity log');
  });

  it('is not listed for a non-admin, and the page sends them back to Devices', async () => {
    signIn(USER_SESSION);
    const { calls } = stub();
    renderApp('/peer-baseline');

    expect(await screen.findByRole('button', { name: /open navigation/i })).toBeInTheDocument();
    const drawer = await openDrawer();
    expect(within(drawer).queryByText('Peer baseline')).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Peer baseline' })).toBeNull();
    expect(calls.some((url) => url.includes('/fleet/baseline'))).toBe(false);
  });
});

describe('the peer-baseline page', () => {
  it('shows the selector and a placeholder until a device is chosen', async () => {
    signIn(ADMIN_SESSION);
    const { calls } = stub();
    renderApp('/peer-baseline');

    expect(await screen.findByRole('heading', { name: 'Peer baseline' })).toBeInTheDocument();
    expect(screen.getByText('Compare a device against others in its vendor cohort')).toBeInTheDocument();
    expect(await screen.findByText('Select a device to view its peer baseline')).toBeInTheDocument();
    expect(screen.getByLabelText('Device')).toHaveValue('');
    expect(screen.queryByRole('region', { name: 'Peer baseline' })).toBeNull();
    expect(calls.some((url) => url.includes('/fleet/baseline'))).toBe(false);
  });

  it('renders the baseline card for the chosen device, and keeps the selector', async () => {
    signIn(ADMIN_SESSION);
    const { calls } = stub();
    renderApp('/peer-baseline');

    const select = await screen.findByLabelText('Device');
    await userEvent.selectOptions(select, AUDITED.device_id);

    expect(
      await screen.findByText(/No compared field differs from the cohort majority/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Showing peer baseline for:/).textContent).toBe(
      'Showing peer baseline for: rtr-core-01 (cisco/ios)',
    );
    expect(calls.some((url) => url.includes(`/fleet/baseline/device/${AUDITED.device_id}`))).toBe(true);
    expect(screen.getByLabelText('Device')).toBeInTheDocument();
    expect(screen.queryByText('Select a device to view its peer baseline')).toBeNull();
  });

  it('lists only devices with at least one audit run', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp('/peer-baseline');

    const select = await screen.findByLabelText('Device');
    const options = within(select).getAllByRole('option').map((o) => o.textContent);
    expect(options).toContain('rtr-core-01 — cisco/ios');
    expect(options.some((o) => o?.includes('sw-unaudited-01'))).toBe(false);
  });
});

describe('which devices the selector lists', () => {
  it('lists every audited device, a finished one included — there is no "completed" filter', async () => {
    // A second audited device made to look finished in every way the interface
    // could see: its remediation commands marked reviewed in localStorage, and
    // a report_generated record in the chain. It must still be listed — the
    // baseline is as true for a finished device as for an open one.
    const FINISHED = {
      device_id: 'e'.repeat(64),
      hostname: 'sw-finished-01',
      vendor: 'cisco',
      os_family: 'ios',
      os_version: '17.9',
      model: null,
    };
    localStorage.setItem(
      'nirikshak.review.local',
      JSON.stringify({ 'aud-2': ['NRK-TELNET-001', 'NRK-HTTP-001'] }),
    );
    signIn(ADMIN_SESSION);
    mockApi([
      {
        match: '/ingest/devices',
        body: { count: 3, devices: [AUDITED, FINISHED, NEVER_AUDITED] },
      },
      {
        match: '/audit/records',
        body: {
          verifiable: false,
          reason: 'a filtered view has no links between its rows; use /audit/verify',
          count: 1,
          records: [
            {
              seq: 7,
              timestamp: '2026-09-27T10:00:00.000000Z',
              actor: { type: 'system', id: 'nirikshak', role: null },
              action: 'report_generated',
              subject: { kind: 'report', id: 'rep-2' },
              payload: JSON.stringify({ audit_id: 'aud-2', config_file_id: FINISHED.device_id }),
              entry_hash: 'a'.repeat(64),
            },
          ],
        },
      },
      {
        match: '/compliance/audits',
        body: {
          count: 2,
          audits: [
            ...FIXTURES.audits.audits,
            { ...FIXTURES.audits.audits[0], audit_id: 'aud-2', device_id: FINISHED.device_id },
          ],
        },
      },
    ]);
    renderApp('/peer-baseline');

    const select = await screen.findByLabelText('Device');
    const options = within(select)
      .getAllByRole('option')
      .map((o) => o.textContent)
      .filter((text) => text !== 'Choose a device…');

    expect(options).toEqual(['rtr-core-01 — cisco/ios', 'sw-finished-01 — cisco/ios']);
  });
});

describe('the device Overview tab', () => {
  it('no longer carries the peer-baseline card, and does not request it', async () => {
    signIn(ADMIN_SESSION);
    const { calls } = stub();
    renderApp('/devices');

    expect(await screen.findByRole('heading', { name: 'rtr-core-01' })).toBeInTheDocument();
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByRole('region', { name: 'Peer baseline' })).toBeNull();
    expect(calls.some((url) => url.includes('/fleet/baseline'))).toBe(false);
  });
});
