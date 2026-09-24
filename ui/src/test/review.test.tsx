/**
 * Confirming a boolean mapping.
 *
 * A boolean control is asserted by a line EXISTING, not by a token inside it.
 * `aaa new-model` carries nothing to capture, and neither does
 * `snmp-server community public RO` — what matters is that the line is there.
 *
 * The compiler has always accepted that (`literal_value`) and the backend
 * refuses a decision that captures nothing and declares nothing:
 *
 *   "a pattern must either capture a token or declare the literal value its
 *    presence asserts; this one does neither, so it would produce no fact"
 *
 * This form sent only `value_token`, so every boolean field failed to compile
 * with that message and no boolean mapping could be confirmed at all. These
 * tests pin the two halves of the fix: the control appears for a boolean field
 * *instead of* the token picker, and the request carries the literal value.
 *
 * `false` matters as much as `true`. A v1/v2c community line asserts that SNMP
 * is NOT v3-only; recording that is how the check fails honestly instead of
 * abstaining.
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

const LINE = 'snmp-server community public RO';

const QUEUE = {
  size: 1,
  confirmable: 1,
  index: '11 examples, 8 fields, one vendor',
  model: {
    available: false,
    summary: 'unavailable',
    package_installed: false,
    weights_present: false,
    airgap: false,
  },
  scrubbed: true,
  entries: [
    {
      cluster_id: 'cl-snmp-1',
      signature: 'snmp-server community <str> RO',
      line: LINE,
      occurrences: 1,
      file_count: 1,
      confirmable: true,
      block_path: [],
      file_id: FIXTURES.devices.devices[0].device_id,
      line_number: 73,
      state: 'unavailable',
      reason: 'the embedding model is not installed',
      is_probability: false,
      confidence_note: 'Similarity scores are rankings, not probabilities.',
      suggestions: [],
    },
  ],
};

function stubReview(extra: Parameters<typeof mockApi>[0] = []) {
  return mockApi([
    ...extra,
    { match: '/training/queue', body: QUEUE },
    { match: '/training/examples', body: { count: 0, examples: [] } },
    { match: '/ingest/devices', body: FIXTURES.devices },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    { match: '/compliance/audits/aud-1/remediation', body: FIXTURES.remediation },
    { match: '/compliance/audits', body: FIXTURES.audits },
    { match: '/health', body: FIXTURES.health },
  ]);
}

/** Open the device workspace at Needs review and select the queued line. */
async function openReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('tab', { name: /needs review/i }));
  await user.click(await screen.findByText(LINE));
}

describe('confirming a boolean mapping', () => {
  it('offers the literal value instead of a token picker', async () => {
    signIn(ADMIN_SESSION);
    stubReview();
    renderApp('/devices');
    const user = userEvent.setup();
    await openReview(user);

    // A capturing field asks which token carries the value.
    expect(await screen.findByText(/which token carries the value/i)).toBeInTheDocument();

    await user.selectOptions(await screen.findByLabelText(/data type/i), 'bool');

    // For a boolean it asks what the line asserts, and the token picker is gone —
    // offering both would invite a decision that names two value sources.
    expect(await screen.findByText(/what does this line assert/i)).toBeInTheDocument();
    expect(screen.queryByText(/which token carries the value/i)).not.toBeInTheDocument();
  });

  it('sends the literal value, and no token, when the field is boolean', async () => {
    signIn(ADMIN_SESSION);
    const { calls, fetchMock } = stubReview([
      {
        match: '/training/confirm',
        status: 201,
        body: { example_id: 'trn-1', field: 'snmp_v3_only', outcome: 'corrected', audit_seq: 7 },
      },
      {
        match: '/training/compile',
        status: 201,
        body: {
          pack_id: 'cisco/ios',
          pack_version: '1.1.1',
          parent_version: '1.1.0',
          status: 'draft',
          pattern_id: 'p-snmp-v3-only-admin-001',
          field: 'snmp_v3_only',
          pattern: '^snmp\\-server\\s+community\\s+public\\s+RO$',
          scope: [],
          capture: 'false',
          cast: 'bool',
          edited: false,
          examples: [LINE],
        },
      },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();
    await openReview(user);

    await user.selectOptions(await screen.findByLabelText(/security field/i), 'snmp_v3_only');
    await user.selectOptions(await screen.findByLabelText(/data type/i), 'bool');

    // A v2c community asserts that SNMP is NOT v3-only. Targeted by role: the
    // explanatory note beneath the control mentions `false` in prose too.
    await user.click(await screen.findByRole('button', { name: 'false' }));

    await user.click(await screen.findByRole('button', { name: /confirm mapping/i }));

    await screen.findByText(/generated pattern|activate|review/i).catch(() => undefined);

    const compile = fetchMock.mock.calls.find(([url]) => String(url).includes('/training/compile'));
    expect(compile, `compile was never called; calls: ${calls.join(', ')}`).toBeDefined();

    // The mock declares one parameter; the app calls fetch(url, init).
    const init = (compile as unknown as [unknown, RequestInit])[1];
    const body = JSON.parse(String(init.body));
    expect(body.literal_value).toBe('false');
    // The two are exclusive: a decision naming both would declare two sources
    // for one value, and the compiler would have to choose between them.
    expect(body.value_token).toBeNull();
    expect(body.cast).toBe('bool');
  });
});
