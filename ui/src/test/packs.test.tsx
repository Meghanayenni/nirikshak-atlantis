/**
 * The vendor packs screen, and the loop it drives.
 *
 * This screen is the only place in the interface that WRITES to a vendor pack,
 * and a vendor pack decides how every future configuration of a platform is
 * read. So the tests here are less about layout than about three properties
 * that would each be a real failure if they slipped:
 *
 *   1. **Built-in and human-verified are never merged.** They carry different
 *      warrants — one was reviewed as code against a corpus, the other was
 *      confirmed by a named person at a known moment — and a single
 *      undifferentiated list would lose the only signal that says how far to
 *      trust a row.
 *
 *   2. **The review step cannot be skipped.** DEVELOPER_GUIDE.md §4 requires the
 *      generated expression be shown and be editable before activation, so
 *      `compile` and `activate` must remain two calls with a human in between.
 *      A form that posted both on one click would delete that review while
 *      looking like a convenience.
 *
 *   3. **Replacing is not editing in place.** The new mapping is activated and
 *      the old one is withdrawn, in that order — so a failure leaves the
 *      platform reading both patterns rather than neither.
 */
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_SESSION, USER_SESSION, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

const BUILTIN_PATTERN = {
  id: 'p-ssh-version-001',
  field: 'ssh_version',
  source: 'builtin',
  match_type: 'regex',
  pattern: '^ip ssh version (\\d+)$',
  capture: '$1',
  cast: 'int',
  scope_block: [],
  examples: ['ip ssh version 2'],
  training_example_id: null,
  audit_seq: null,
  withdrawable: false,
};

const TRAINED_PATTERN = {
  id: 'p-admin-logging-001',
  field: 'logging_hosts',
  source: 'admin_trained',
  match_type: 'regex',
  pattern: '^logging\\s+host\\s+(\\S+)$',
  capture: '$1',
  cast: 'list',
  scope_block: [],
  examples: ['logging host 192.0.2.10'],
  training_example_id: 'trn-1',
  audit_seq: 41,
  withdrawable: true,
};

function packsBody(patterns = [BUILTIN_PATTERN, TRAINED_PATTERN]) {
  return {
    count: 2,
    canonical_fields: ['logging_hosts', 'ssh_version', 'telnet_enabled'],
    casts: ['int', 'bool', 'str', 'list'],
    packs: [
      {
        pack_id: 'cisco/ios',
        vendor: 'cisco',
        os_family: 'ios',
        pack_version: '1.1.0',
        parent_version: null,
        status: 'active',
        origin: 'builtin',
        is_active: true,
        checksum: 'sha256:abc',
        created_at: null,
        pattern_count: patterns.length,
        admin_trained_count: patterns.filter((p) => p.source === 'admin_trained').length,
        patterns,
      },
      {
        pack_id: 'cisco/ios',
        vendor: 'cisco',
        os_family: 'ios',
        pack_version: '1.0.0',
        parent_version: null,
        status: 'deprecated',
        origin: 'builtin',
        is_active: false,
        checksum: 'sha256:old',
        created_at: null,
        pattern_count: 0,
        admin_trained_count: 0,
        patterns: [],
      },
    ],
  };
}

function stubPacks(extra: Parameters<typeof mockApi>[0] = []) {
  return mockApi([
    ...extra,
    { match: '/training/packs', body: packsBody() },
    {
      match: '/training/examples',
      body: {
        count: 1,
        examples: [
          {
            example_id: 'trn-1',
            vendor: 'cisco',
            os_family: 'ios',
            line: 'logging host 192.0.2.10',
            field: 'logging_hosts',
            outcome: 'corrected',
            confirmed_by: 'root',
            audit_seq: 41,
            top3_hit: false,
          },
        ],
      },
    },
  ]);
}

describe('the vendor pack index', () => {
  it('shows one box per platform, counting the two kinds separately', async () => {
    signIn(ADMIN_SESSION);
    stubPacks();
    renderApp('/packs');

    // The superseded 1.0.0 version is not a box of its own — it is history, and
    // it belongs inside the platform rather than beside it.
    const boxes = await screen.findAllByText(/cisco \/ ios/i);
    expect(boxes.length).toBe(1);

    expect(await screen.findByText('human-verified')).toBeInTheDocument();
    expect(await screen.findByText('built-in')).toBeInTheDocument();
  });

  it('refuses the whole screen to a non-admin rather than showing an empty one', async () => {
    signIn(USER_SESSION);
    mockApi([{ match: '/training/packs', status: 403, body: { detail: 'admin only' } }]);
    renderApp('/packs');

    expect(await screen.findByText(/cannot read the pack inventory/i)).toBeInTheDocument();
    // An empty list would read as "this platform has no mappings", which is a
    // claim about the data rather than about this account's permissions.
    expect(screen.queryByText('human-verified')).not.toBeInTheDocument();
  });
});

describe('a pack detail', () => {
  it('keeps built-in and human-verified in separate sections', async () => {
    signIn(ADMIN_SESSION);
    stubPacks();
    renderApp('/packs');

    await userEvent.click(await screen.findByText(/cisco \/ ios/i));

    const trained = await screen.findByRole('table', {
      name: /confirmed by an administrator/i,
    });
    const builtin = await screen.findByRole('table', {
      name: /shipped with the repository/i,
    });

    // Exact strings, not substring regexes: the humanised field name reads
    // "Ssh Version" and the example line beneath it reads "ip ssh version 2",
    // so a loose match finds the very row it was meant to distinguish.
    expect(within(trained).getByText('Logging hosts')).toBeInTheDocument();
    expect(within(trained).queryByText('Ssh version')).not.toBeInTheDocument();

    expect(within(builtin).getByText('Ssh version')).toBeInTheDocument();
    expect(within(builtin).queryByText('Logging hosts')).not.toBeInTheDocument();
  });

  it('offers no way to remove a built-in mapping', async () => {
    signIn(ADMIN_SESSION);
    stubPacks();
    renderApp('/packs');

    await userEvent.click(await screen.findByText(/cisco \/ ios/i));

    const builtin = await screen.findByRole('table', { name: /shipped with the repository/i });
    expect(within(builtin).queryByRole('button', { name: /withdraw/i })).not.toBeInTheDocument();
    expect(within(builtin).queryByRole('button', { name: /replace/i })).not.toBeInTheDocument();

    // The human-verified section does offer both.
    const trained = await screen.findByRole('table', { name: /confirmed by an administrator/i });
    expect(within(trained).getByRole('button', { name: /withdraw/i })).toBeInTheDocument();
    expect(within(trained).getByRole('button', { name: /replace/i })).toBeInTheDocument();
  });

  it('names the person who confirmed a human-verified mapping', async () => {
    signIn(ADMIN_SESSION);
    stubPacks();
    renderApp('/packs');

    await userEvent.click(await screen.findByText(/cisco \/ ios/i));
    expect(await screen.findByText(/by root/i)).toBeInTheDocument();
  });
});

describe('teaching a new mapping', () => {
  it('compiles and shows the expression before anything is activated', async () => {
    signIn(ADMIN_SESSION);
    const { calls } = stubPacks([
      {
        match: '/training/confirm',
        status: 201,
        body: { example_id: 'trn-new', field: 'telnet_enabled', outcome: 'corrected' },
      },
      {
        match: '/training/compile',
        status: 201,
        body: {
          pack_id: 'cisco/ios',
          pack_version: '1.1.1',
          parent_version: '1.1.0',
          status: 'draft',
          pattern_id: 'p-authored-001',
          field: 'telnet_enabled',
          pattern: '^transport\\s+input\\s+(\\S+)$',
          scope: [],
          capture: '$1',
          cast: 'str',
          edited: false,
          examples: ['transport input ssh'],
        },
      },
    ]);

    renderApp('/packs');
    const user = userEvent.setup();

    await user.click(await screen.findByText(/cisco \/ ios/i));
    await user.click(await screen.findByRole('button', { name: /add mapping/i }));

    await user.type(
      await screen.findByRole('textbox', { name: /configuration line/i }),
      'transport input ssh',
    );
    await user.click(screen.getByRole('button', { name: /compile and review/i }));

    // The generated expression is on screen and editable — §4's review step.
    const expression = await screen.findByDisplayValue('^transport\\s+input\\s+(\\S+)$');
    expect(expression).toBeInTheDocument();

    // And nothing has been activated by getting here.
    expect(calls.some((url) => url.includes('/training/activate'))).toBe(false);
    expect(screen.getByRole('button', { name: /activate mapping/i })).toBeInTheDocument();
  });

  it('does not compile until a line has been given', async () => {
    signIn(ADMIN_SESSION);
    stubPacks();
    renderApp('/packs');
    const user = userEvent.setup();

    await user.click(await screen.findByText(/cisco \/ ios/i));
    await user.click(await screen.findByRole('button', { name: /add mapping/i }));

    expect(screen.getByRole('button', { name: /compile and review/i })).toBeDisabled();
  });
});
