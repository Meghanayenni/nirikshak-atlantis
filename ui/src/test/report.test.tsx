/**
 * The report screen, and two failures that produced no error anywhere.
 *
 * Both shipped, both reached an operator, and neither raised anything a test or
 * a console would have shown:
 *
 *   **Generate report rendered a blank box.** The document is fetched and put in
 *   a sandboxed iframe. The fetch asked for `Accept: text/html`, and the
 *   development proxy used that header to decide a request was a browser
 *   navigating and answered it with the application's own `index.html`. The
 *   request succeeded, the iframe received real HTML, scripts were blocked by
 *   the sandbox, and the operator got white space.
 *
 *   **Download PDF delivered the sign-in screen.** It was an `<a href>` with
 *   `target="_blank"`. Credentials are HTTP Basic held in `sessionStorage`; a
 *   navigation sends no `Authorization` header, and a new tab has no
 *   `sessionStorage` to read, so the request arrived unauthenticated and the
 *   application bounced it to `/login`.
 *
 * What both have in common is that the interface asserted success while showing
 * the operator nothing of what they asked for. So these tests check the
 * property that was actually missing — that the thing requested arrives — rather
 * than that a button exists.
 */
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_SESSION, FIXTURES, mockApi, renderApp, signIn } from './helpers';

/** The document the backend actually returns: self-contained, styled, no script. */
const REPORT_HTML =
  '<!DOCTYPE html><html><head><title>NIRIKSHAK compliance report</title>' +
  '<style>body{font-family:sans-serif}</style></head>' +
  '<body><h1>Compliance report</h1><p class="cited">ip ssh version 2</p></body></html>';

beforeEach(() => {
  // jsdom implements neither, and the download path uses both.
  URL.createObjectURL = vi.fn(() => 'blob:nirikshak/report');
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  signIn(null);
  localStorage.clear();
});

/** A device whose gate is fully open: audited, nothing undecided, nothing to review. */
function stubOpenGate(extra: Parameters<typeof mockApi>[0] = []) {
  return mockApi([
    ...extra,
    { match: '/ingest/devices', body: FIXTURES.devices },
    { match: '/compliance/audits/aud-1/findings', body: FIXTURES.findings },
    // No resolved snippet, so nothing needs a review mark and the gate opens.
    {
      match: '/compliance/audits/aud-1/remediation',
      body: {
        audit_id: 'aud-1',
        failing_findings: 0,
        resolved: 0,
        snippet_library_version: '865562dbef8c',
        steps: [],
        note: 'NIRIKSHAK does not apply these commands.',
      },
    },
    { match: '/compliance/audits', body: FIXTURES.audits },
    {
      match: '/training/queue',
      body: {
        size: 0,
        confirmable: 0,
        index: 'index',
        model: {
          available: false,
          summary: 'unavailable',
          package_installed: false,
          weights_present: false,
          airgap: false,
        },
        scrubbed: true,
        entries: [],
      },
    },
    { match: '/training/examples', body: { count: 0, examples: [] } },
    { match: '/health', body: FIXTURES.health },
  ]);
}

async function openReportTab() {
  renderApp('/devices');
  const user = userEvent.setup();
  await user.click(await screen.findByRole('tab', { name: /report/i }));
  return user;
}

describe('generating the report', () => {
  it('puts the returned document into the frame, rather than an empty one', async () => {
    signIn(ADMIN_SESSION);
    stubOpenGate([
      { match: '/compliance/audits/aud-1/report.html', text: REPORT_HTML },
    ]);

    const user = await openReportTab();
    await user.click(await screen.findByRole('button', { name: /generate report/i }));

    const frame = (await screen.findByTitle('Compliance report')) as HTMLIFrameElement;

    // The assertion the blank-screen bug needed. A frame that exists proves
    // nothing; a frame carrying the document proves the fetch reached the API.
    expect(frame.getAttribute('srcdoc')).toContain('Compliance report');
    expect(frame.getAttribute('srcdoc')).toContain('ip ssh version 2');

    // And it is still sandboxed — the report is operator data, not code to run.
    expect(frame.getAttribute('sandbox')).toBe('');
  });

  it('does not ask for text/html, which a dev proxy reads as a navigation', async () => {
    signIn(ADMIN_SESSION);
    const { fetchMock } = stubOpenGate([
      { match: '/compliance/audits/aud-1/report.html', text: REPORT_HTML },
    ]);

    const user = await openReportTab();
    await user.click(await screen.findByRole('button', { name: /generate report/i }));
    await screen.findByTitle('Compliance report');

    const call = fetchMock.mock.calls.find(([url]) => String(url).includes('report.html'));
    expect(call, 'the report was never requested').toBeDefined();

    // The mock declares one parameter; the app calls fetch(url, init).
    const init = (call as unknown as [unknown, RequestInit])[1];
    const headers = init.headers as Record<string, string>;
    // `text/html` is true of the response and is exactly what made the proxy
    // answer this request with the application shell. These endpoints do not
    // content-negotiate, so claiming it buys nothing and costs a blank screen.
    expect(headers.Accept).not.toContain('text/html');
    expect(headers.Authorization).toMatch(/^Basic /);
  });

  it('shows the backend’s reason when the report cannot be rendered', async () => {
    signIn(ADMIN_SESSION);
    stubOpenGate([
      {
        match: '/compliance/audits/aud-1/report.html',
        status: 500,
        body: { detail: 'the template could not be rendered' },
      },
    ]);

    const user = await openReportTab();
    await user.click(await screen.findByRole('button', { name: /generate report/i }));

    expect(await screen.findByText(/the template could not be rendered/i)).toBeInTheDocument();
    // A failure must not leave an empty frame standing, which is the shape the
    // original bug took.
    expect(screen.queryByTitle('Compliance report')).not.toBeInTheDocument();
  });
});

describe('downloading the PDF', () => {
  it('fetches it with credentials instead of navigating to the endpoint', async () => {
    signIn(ADMIN_SESSION);
    const { fetchMock } = stubOpenGate([
      { match: '/compliance/audits/aud-1/report.pdf', text: '%PDF-1.7 fake' },
    ]);

    const user = await openReportTab();

    // There must be no link pointing at the endpoint. A navigation carries no
    // Authorization header, and in a new tab there is no session to read.
    const link = screen.queryByRole('link', { name: /download pdf/i });
    expect(link, 'the PDF must not be a plain link').toBeNull();

    await user.click(await screen.findByRole('button', { name: /download pdf/i }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) => String(url).includes('report.pdf'));
      expect(call, 'the PDF was never requested').toBeDefined();
      // The mock declares one parameter; the app calls fetch(url, init).
      const init = (call as unknown as [unknown, RequestInit])[1];
      const headers = init.headers as Record<string, string>;
      expect(headers.Authorization).toMatch(/^Basic /);
    });

    // Handed to the browser as a blob, and the handle released afterwards.
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it('names the missing runtime when the PDF stack is unavailable', async () => {
    signIn(ADMIN_SESSION);
    stubOpenGate([
      {
        match: '/compliance/audits/aud-1/report.pdf',
        status: 503,
        body: {
          detail:
            'PDF rendering is unavailable: libpango-1.0-0 is missing. ' +
            'See docs/adr/0006-weasyprint-gtk-probe.md',
        },
      },
    ]);

    const user = await openReportTab();
    await user.click(await screen.findByRole('button', { name: /download pdf/i }));

    // The library name is the useful part. "Download failed" would send somebody
    // looking in the wrong place entirely.
    expect(await screen.findByText(/libpango-1\.0-0/)).toBeInTheDocument();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
