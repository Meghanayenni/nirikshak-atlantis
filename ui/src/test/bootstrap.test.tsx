/**
 * Unrecognised vendor (ADR 0067): the page proposes structure, never a name,
 * and every derived value has its own correction path.
 */
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { BootstrapAssessment, BootstrapResult } from '@/types/api';

import { ADMIN_SESSION, FIXTURES, USER_SESSION, mockApi, renderApp, signIn } from './helpers';

const FILE = 'f'.repeat(64);

const ASSESSMENT: BootstrapAssessment = {
  file_id: FILE,
  filename: 'unknown-01.txt',
  eligible: true,
  reason: 'no pack claims this file',
  principle:
    'NIRIKSHAK proposes only what it can derive from this file: its structure, its comment style, and lines no known platform uses. It never proposes a vendor or platform name — nothing in the file states that in a form it can verify. You supply the name; the file supplies the structure.',
  detection: {
    outcome: 'no_signature_matched',
    explanation: 'no known platform signature matched',
    min_score: 0.6,
    min_margin: 0.25,
  },
  split_check: 'not an evaluation or held-out corpus file',
  bootstrapped_platform: null,
  syntax: {
    derived: 'indent',
    evidence: ['no line is indented: every statement is read at the top level'],
    parseable: true,
    implemented_modes: ['brace', 'indent', 'set_path'],
  },
  comments: { prefix: '#', counts: { '#': 4 } },
  structure: {
    total_lines: 20,
    blank_lines: 0,
    comment_lines: 4,
    content_lines: 16,
    indented_lines: 0,
    max_depth: 0,
    block_headers: [],
    section_path_lines: 3,
  },
  fingerprints: {
    candidates: [
      { stem: '/alpha beta', pattern: '^/alpha beta$', example: '/alpha beta', line_number: 5, occurrences: 1, pasted: false },
      { stem: '/gamma delta', pattern: '^/gamma delta$', example: '/gamma delta', line_number: 9, occurrences: 1, pasted: false },
      { stem: '/epsilon', pattern: '^/epsilon$', example: '/epsilon', line_number: 12, occurrences: 1, pasted: false },
    ],
    excluded_as_used_elsewhere: 2,
    choose: [2, 5],
  },
};

const CREATED: BootstrapResult = {
  pack_id: 'acme/widget-os',
  pack_version: '1.0.0',
  checksum: `sha256:${'0'.repeat(64)}`,
  syntax_mode: 'indent',
  syntax_mode_derived: 'indent',
  comment_prefixes: ['#'],
  detect: [
    { pattern: '^/alpha beta$', weight: 0.5 },
    { pattern: '^/gamma delta$', weight: 0.5 },
  ],
  fingerprints: [],
  detection: { outcome: 'detected', score: 1, margin: 1, explanation: 'acme/widget-os (score 1.00, margin 1.00)' },
  also_matches: [],
  next: 'Run an audit of this file.',
};

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
});

function stub(extra: Parameters<typeof mockApi>[0] = []) {
  return mockApi([
    { match: new RegExp(`/training/bootstrap/${FILE}$`), body: ASSESSMENT },
    ...extra,
  ]);
}

function sent(fetchMock: ReturnType<typeof vi.fn>, method: string) {
  const call = fetchMock.mock.calls.find(([, init]) => (init as RequestInit)?.method === method);
  return call ? { url: String(call[0]), body: JSON.parse(String((call[1] as RequestInit).body ?? 'null')) } : null;
}

describe('the unrecognised-vendor page', () => {
  it('states the principle and proposes no name', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp(`/bootstrap/${FILE}`);

    const principle = await screen.findByRole('region', { name: /what nirikshak proposes/i });
    expect(principle.textContent).toMatch(/never proposes a vendor or platform name/);
    expect((screen.getByLabelText('Vendor') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Platform') as HTMLInputElement).value).toBe('');
  });

  it('shows the derived mode with its evidence, pre-selected and overridable', async () => {
    signIn(ADMIN_SESSION);
    stub();
    renderApp(`/bootstrap/${FILE}`);
    const user = userEvent.setup();

    const select = (await screen.findByLabelText('Syntax mode')) as HTMLSelectElement;
    expect(select.value).toBe('indent');
    expect(screen.getByRole('list', { name: 'Syntax evidence' }).textContent).toMatch(/no line is indented/);
    // Declared-but-unimplemented modes are visible and cannot be chosen.
    expect((within(select).getByRole('option', { name: /XML/ }) as HTMLOptionElement).disabled).toBe(true);

    await user.selectOptions(select, 'brace');
    expect(screen.getByText(/the file reads as/).textContent).toMatch(/You chose brace; the file reads as indent/);
    // The evidence stays visible after an override.
    expect(screen.getByRole('list', { name: 'Syntax evidence' })).toBeInTheDocument();
  });

  it('creates only with 2-5 fingerprints and valid names, and sends every choice', async () => {
    signIn(ADMIN_SESSION);
    const { fetchMock } = stub([{ match: /\/training\/bootstrap$/, body: CREATED, status: 201 }]);
    renderApp(`/bootstrap/${FILE}`);
    const user = userEvent.setup();

    const create = await screen.findByRole('button', { name: /create platform/i });
    expect(create).toBeDisabled();

    await user.click(screen.getByLabelText('Use /alpha beta'));
    await user.type(screen.getByLabelText('Vendor'), 'acme');
    await user.type(screen.getByLabelText('Platform'), 'widget-os');
    expect(create).toBeDisabled(); // one fingerprint is too few

    // "None of these": a line of the administrator's own.
    await user.type(screen.getByLabelText('Your own fingerprint line'), 'widget mode on');
    await user.click(screen.getByRole('button', { name: /add this line/i }));
    expect(create).toBeEnabled();

    await user.click(create);
    const post = sent(fetchMock, 'POST');
    expect(post?.body).toEqual({
      file_id: FILE,
      vendor: 'acme',
      os_family: 'widget-os',
      syntax_mode: 'indent',
      fingerprints: ['/alpha beta'],
      pasted_lines: ['widget mode on'],
      comment_prefixes: ['#'],
    });
    expect(await screen.findByText('acme/widget-os 1.0.0')).toBeInTheDocument();
    expect(screen.getByText(/score 1\.00/)).toBeInTheDocument();
  });

  it('shows a refusal as a reason, having written nothing', async () => {
    signIn(ADMIN_SESSION);
    stub([
      {
        match: /\/training\/bootstrap$/,
        body: { detail: 'cisco/ios already has a pack.' },
        status: 409,
      },
    ]);
    renderApp(`/bootstrap/${FILE}`);
    const user = userEvent.setup();

    await user.click(await screen.findByLabelText('Use /alpha beta'));
    await user.click(screen.getByLabelText('Use /gamma delta'));
    await user.type(screen.getByLabelText('Vendor'), 'cisco');
    await user.type(screen.getByLabelText('Platform'), 'ios');
    await user.click(screen.getByRole('button', { name: /create platform/i }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(/nothing was written/i);
    expect(alert.textContent).toMatch(/already has a pack/);
  });

  it('discards only after a second, explicit confirmation', async () => {
    signIn(ADMIN_SESSION);
    const { fetchMock } = stub([
      { match: /\/training\/bootstrap$/, body: CREATED, status: 201 },
      {
        match: /\/training\/bootstrap\/acme\/widget-os$/,
        body: { pack_id: 'acme/widget-os', versions_removed: ['1.0.0'], files_reset: [FILE] },
      },
    ]);
    renderApp(`/bootstrap/${FILE}`);
    const user = userEvent.setup();

    await user.click(await screen.findByLabelText('Use /alpha beta'));
    await user.click(screen.getByLabelText('Use /gamma delta'));
    await user.type(screen.getByLabelText('Vendor'), 'acme');
    await user.type(screen.getByLabelText('Platform'), 'widget-os');
    await user.click(screen.getByRole('button', { name: /create platform/i }));

    await user.click(await screen.findByRole('button', { name: /discard and start over/i }));
    expect(sent(fetchMock, 'DELETE')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Discard acme/widget-os' }));

    expect(sent(fetchMock, 'DELETE')?.url).toMatch(/\/training\/bootstrap\/acme\/widget-os$/);
  });

  it('is not shown to a non-administrator', async () => {
    signIn(USER_SESSION);
    mockApi([
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits', body: FIXTURES.audits },
    ]);
    renderApp(`/bootstrap/${FILE}`);

    expect(await screen.findByRole('searchbox', { name: /search devices/i })).toBeInTheDocument();
    expect(screen.queryByText('Unrecognised vendor')).toBeNull();
  });
});

describe('an unidentified device in the workspace', () => {
  const unidentified = {
    count: 1,
    devices: [{ device_id: FILE, hostname: null, vendor: null, os_family: null, os_version: null, model: null }],
  };

  function stubDevice() {
    mockApi([
      { match: '/ingest/devices', body: unidentified },
      { match: '/compliance/audits', body: { count: 0, audits: [] } },
      { match: '/training/queue', body: {}, status: 403 },
      { match: '/training/examples', body: {}, status: 403 },
    ]);
  }

  it('points an administrator at the bootstrap page instead of a dead end', async () => {
    signIn(ADMIN_SESSION);
    stubDevice();
    renderApp(`/devices/${FILE}`);

    const banner = await screen.findByRole('region', { name: 'Platform not identified' });
    expect(within(banner).getByRole('link', { name: /describe this platform/i })).toHaveAttribute(
      'href',
      `/bootstrap/${FILE}`,
    );
  });

  it('tells anyone else that an administrator can', async () => {
    signIn(USER_SESSION);
    stubDevice();
    renderApp(`/devices/${FILE}`);

    const banner = await screen.findByRole('region', { name: 'Platform not identified' });
    expect(within(banner).queryByRole('link')).toBeNull();
    expect(banner.textContent).toMatch(/an administrator can describe its platform/i);
  });
});
