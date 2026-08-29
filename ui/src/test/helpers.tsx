/**
 * Test helpers.
 *
 * `renderApp` mounts the real router, the real providers and the real guards, so
 * a routing test exercises what ships rather than a simplified stand-in.
 *
 * `mockApi` replaces `fetch` with a table of path patterns. Anything not in the
 * table is a 404 — a test that forgets to stub an endpoint fails loudly instead
 * of silently rendering an empty screen, which is exactly the failure mode this
 * interface exists to avoid.
 */
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

import { App } from '@/App';
import { AuthProvider } from '@/hooks/useAuth';
import { ToastProvider } from '@/hooks/useToast';
import { setSession, type Session } from '@/services/api';

export const ADMIN_SESSION: Session = {
  username: 'root',
  token: 'dG9rZW4=',
  role: 'admin',
  userId: 'admin-1',
};

export const USER_SESSION: Session = {
  username: 'alice',
  token: 'dG9rZW4=',
  role: 'user',
  userId: 'user-1',
};

export interface Route {
  /** Substring or RegExp matched against the request URL. */
  match: string | RegExp;
  status?: number;
  body?: unknown;
  /** Returned verbatim for `raw` requests such as the HTML report. */
  text?: string;
}

export function mockApi(routes: Route[]) {
  const calls: string[] = [];

  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);

    const route = routes.find((r) =>
      typeof r.match === 'string' ? url.includes(r.match) : r.match.test(url),
    );

    if (!route) {
      return new Response(JSON.stringify({ detail: `unstubbed endpoint: ${url}` }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const status = route.status ?? 200;
    const body = route.text ?? JSON.stringify(route.body ?? {});
    return new Response(body, {
      status,
      headers: { 'Content-Type': route.text ? 'text/html' : 'application/json' },
    });
  });

  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}

export function signIn(session: Session | null) {
  setSession(session);
}

export function renderApp(initialPath = '/dashboard') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <AuthProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

export function renderWithProviders(element: ReactElement) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ToastProvider>{element}</ToastProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

/** Response fixtures shaped exactly like the live API returns them. */
export const FIXTURES = {
  devices: {
    count: 1,
    devices: [
      {
        device_id: 'c0f08477bb6ad93bf0da05c4269b87c38c815ecf1d492fadd28ce38af2601fb1',
        hostname: 'rtr-core-01',
        vendor: 'cisco',
        os_family: 'ios',
        os_version: '17.9',
        model: 'ISR4331',
      },
    ],
  },
  audits: {
    count: 1,
    audits: [
      {
        audit_id: 'aud-1',
        device_id: 'c0f08477bb6ad93bf0da05c4269b87c38c815ecf1d492fadd28ce38af2601fb1',
        owner_id: 'user-1',
        engine_version: '0.1.0',
        rulepack_id: 'canonical',
        rulepack_version: '1.0.0',
        pack_versions: { cisco: '1.1.0' },
        rules_evaluated: 2,
        verdicts: { pass: 1, fail: 1, unknown: 0, not_applicable: 0 },
        evaluated_at: '2026-08-28T18:28:16.025946+00:00',
      },
    ],
  },
  findings: {
    audit_id: 'aud-1',
    count: 2,
    snippet_library_version: 'empty',
    findings: [
      {
        finding_id: 'aud-1:dev:NRK-TELNET-001',
        rule_id: 'NRK-TELNET-001',
        status: 'fail',
        severity: 'high',
        expected: 'disabled',
        observed: {
          value: true,
          state: 'present',
          confidence: 1.0,
          confidence_method: 'deterministic',
          is_probability: false,
        },
        unknown_reason: null,
        absence_reason: null,
        evidence: [
          {
            file_id: 'file-1',
            file_path: 'c0/config.cfg',
            line_start: 42,
            line_end: 42,
            raw_line: 'transport input telnet ssh',
            cite: 'c0/config.cfg:42',
          },
        ],
        frameworks: [],
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
      {
        finding_id: 'aud-1:dev:NRK-PASSWORD-001',
        rule_id: 'NRK-PASSWORD-001',
        status: 'unknown',
        severity: 'medium',
        expected: 'at least 12',
        observed: {
          value: null,
          state: 'unknown',
          confidence: 0.0,
          confidence_method: 'deterministic',
          is_probability: false,
        },
        unknown_reason: 'no_match',
        absence_reason: null,
        evidence: [],
        frameworks: [],
        remediation: {
          outcome: 'not_actionable',
          statement: 'No remediation is proposed: this finding is not a failure.',
          snippet_id: null,
          commands: [],
          rollback: [],
          vetted_by: null,
          reference: null,
        },
      },
    ],
  },
  fleet: {
    devices: 4,
    skipped_files: 0,
    cohorts: [{ cohort: 'cisco/ios', size: 4, devices: ['rtr-core-01'] }],
    minimum_cohort_size: 5,
    summary: '4 device(s) across 1 cohort(s); no baseline could be established.',
    baselines: [
      {
        cohort: 'cisco/ios',
        field: 'logging_hosts',
        outcome: 'cohort_too_small',
        cohort_size: 4,
        determinable: 4,
        indeterminate: 0,
        majority_state: null,
        majority_count: 0,
        counts: null,
        explanation: "cohort 'cisco/ios' holds 4 device(s); 5 are required",
      },
    ],
    comparable_baselines: 0,
    outliers: [],
    is_verdict: false,
    note: 'A deviation from a peer group is an observation about the fleet, not a compliance verdict.',
  },
  health: {
    status: 'ok',
    version: '0.1.0',
    phase: 'P12',
    schema_version: 1,
    schema_versions: { operational: 3, audit: 1 },
    airgap: false,
    confidence_threshold: 0.85,
    platform_default_min_confidence: 0.9,
    platform_default_confidence: 0.95,
    similarity_model: {
      available: false,
      model: 'sentence-transformers/all-MiniLM-L6-v2',
      package_installed: false,
      weights_present: false,
      summary: 'The embedding model is unavailable: sentence-transformers is not installed.',
      calibrated: false,
      note: 'No calibrator is fitted (D42). Every suggestion is UNCALIBRATED_SIMILARITY.',
    },
    pdf_reporting: {
      available: false,
      weasyprint_installed: false,
      missing_libraries: ['libcairo-2'],
      detail: 'PDF rendering is unavailable: the weasyprint package is not installed.',
    },
    remediation_library: {},
  },
  users: {
    count: 2,
    users: [
      {
        user_id: 'admin-1',
        username: 'root',
        role: 'admin',
        disabled: false,
        created_at: '2026-08-01T00:00:00+00:00',
      },
      {
        user_id: 'user-1',
        username: 'alice',
        role: 'user',
        disabled: false,
        created_at: '2026-08-02T00:00:00+00:00',
      },
    ],
  },
};
