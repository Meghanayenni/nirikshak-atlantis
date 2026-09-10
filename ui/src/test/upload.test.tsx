/**
 * An upload says what happened to each file.
 *
 * The ingestion endpoint returns a reason for every refusal and an explanation
 * for every platform it could not identify. The toast used to discard both: an
 * empty file, a binary file and a renamed image all read "1 rejected", and a
 * file stored without an identified platform — one that will refuse every audit
 * — was announced with a green "accepted".
 *
 * The response shapes below are the backend's real ones (`api/routers/ingest.py`),
 * including `detection` nested under each accepted file. The type used to declare
 * `vendor` at the top level, which type-checked and was always undefined.
 */
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { UploadAccepted, UploadRejected, UploadResult } from '@/types/api';
import { describeUpload } from '@/utils/upload';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  signIn(null);
  localStorage.clear();
});

/** The exact refusal a 0-byte file produces (`api/ingest/validate.py`). */
const EMPTY_FILE: UploadRejected = {
  filename: 'cisco_ios_xe.cfg',
  reason: 'empty',
  detail: 'the file is empty (0 bytes)',
  size_bytes: 0,
};

function acceptedFile(overrides: Partial<UploadAccepted['detection']> = {}): UploadAccepted {
  return {
    file_id: 'f'.repeat(64),
    filename: 'rtr-core-01.cfg',
    size_bytes: 1657,
    line_count: 42,
    encoding: 'utf-8',
    format: 'text',
    duplicate: false,
    identity: {},
    detection: {
      outcome: 'detected',
      vendor: 'cisco',
      os_family: 'ios',
      score: 0.95,
      margin: 0.7,
      explanation: 'cisco/ios scored 0.95',
      ...overrides,
    },
  };
}

/** A Cisco NX-OS file with no NX-OS pack: stored, and not auditable. */
const NXOS_UNIDENTIFIED = (() => {
  const file = acceptedFile({
    outcome: 'below_threshold',
    vendor: null,
    os_family: null,
    score: 0.25,
    margin: 0.05,
    explanation: 'best candidate cisco/ios scored 0.25, below the 0.60 threshold',
  });
  return { ...file, filename: 'dc1-leaf-01.cfg' };
})();

function result(accepted: UploadAccepted[], rejected: UploadRejected[]): UploadResult {
  return { batch_id: 'batch-1', accepted, rejected };
}

describe('describeUpload', () => {
  it('names the file and the reason when an empty file is refused', () => {
    const message = describeUpload(result([], [EMPTY_FILE]));

    expect(message.kind).toBe('error');
    expect(message.title).toBe('File refused');
    expect(message.detail).toContain('cisco_ios_xe.cfg');
    expect(message.detail).toContain('the file is empty (0 bytes)');
  });

  it('does not call an unidentified platform a plain success', () => {
    const message = describeUpload(result([NXOS_UNIDENTIFIED], []));

    // Accepted, but it will refuse every audit. Green would be a false promise.
    expect(message.kind).not.toBe('success');
    expect(message.title).toContain('not identified');
    expect(message.detail).toContain('dc1-leaf-01.cfg');
    expect(message.detail).toContain('below the 0.60 threshold');
    expect(message.detail).toContain('cannot be audited');
  });

  it('reports each file in a mixed batch on its own line', () => {
    const message = describeUpload(result([acceptedFile(), NXOS_UNIDENTIFIED], [EMPTY_FILE]));

    expect(message.kind).toBe('info');
    expect(message.title).toBe('2 accepted · 1 refused · 1 not identified');
    expect(message.detail?.split('\n')).toHaveLength(2);
  });

  it('keeps a clean upload short', () => {
    const message = describeUpload(result([acceptedFile()], []));

    expect(message).toEqual({ kind: 'success', title: '1 configuration accepted' });
  });

  it('treats a duplicate of stored bytes as an acceptance, not a refusal', () => {
    const message = describeUpload(result([{ ...acceptedFile(), duplicate: true }], []));

    expect(message.kind).toBe('success');
  });
});

describe('the upload control', () => {
  it('shows the refusal reason on screen, not just a count', async () => {
    signIn(ADMIN_SESSION);
    mockApi([
      { match: '/ingest/upload', body: result([], [EMPTY_FILE]) },
      { match: '/ingest/devices', body: FIXTURES.devices },
      { match: '/compliance/audits', body: FIXTURES.audits },
      { match: '/training/queue', body: { size: 0, confirmable: 0, index: 'i', model: { available: false, summary: 'x', package_installed: false, weights_present: false, airgap: false }, scrubbed: true, entries: [] } },
      { match: '/training/examples', body: { count: 0, examples: [] } },
    ]);

    renderApp('/devices');
    const user = userEvent.setup();

    const input = await screen.findByLabelText('Configuration files');
    await user.upload(input, new File([], 'cisco_ios_xe.cfg', { type: 'text/plain' }));

    expect(await screen.findByText('File refused')).toBeInTheDocument();
    expect(await screen.findByText(/the file is empty \(0 bytes\)/)).toBeInTheDocument();
    // The old wording, which told the operator nothing about what to fix.
    expect(screen.queryByText(/1 rejected/)).not.toBeInTheDocument();
  });
});
