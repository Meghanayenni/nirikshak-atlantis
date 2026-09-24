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

/**
 * The benchmark options every device workspace requests (ADR 0058).
 *
 * Supplied by default, ahead of the suites' catch-all `/compliance/audits`
 * routes — which would otherwise answer this URL with an audit list, a shape
 * the selector cannot read. A suite that stubs the endpoint itself wins.
 */
const DEFAULT_FRAMEWORK_OPTIONS: Route = {
  match: '/compliance/audits/frameworks/device/',
  body: {
    file_id: 'file-1',
    platform: { vendor: 'cisco', os_family: 'ios', os_version: '17.9' },
    frameworks: [
      {
        framework: 'nist',
        document: 'NIST SP 800-53 Rev 5 — OSCAL catalog',
        edition: '5.2.0',
        describes_device: true,
        reason: null,
      },
    ],
    note: 'Mappings from NIRIKSHAK checks to these controls are asserted by this project.',
  },
};

export function mockApi(routes: Route[]) {
  const calls: string[] = [];
  const stubsOptions = routes.some(
    (r) => typeof r.match === 'string' && r.match.includes('/frameworks/device/'),
  );
  if (!stubsOptions) routes = [DEFAULT_FRAMEWORK_OPTIONS, ...routes];

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

export function renderApp(initialPath = '/devices') {
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
    // The shape `/findings` returns since ADR 0057: the API has already decided
    // which identifiers apply, which are declined, and why any are absent.
    framework_view: {
      attached: true,
      withheld_reason: null,
      absent: { iso: 'no ISO catalog has been sourced, so this report says nothing about it either way' },
      selection: null,
      not_applied: {},
      not_assessed: [],
    },
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
        frameworks: [
          {
            framework: 'nist',
            control_id: 'CM-07',
            edition: '5.2.0',
            citation: 'NIST SP 800-53 Rev 5 — OSCAL catalog, edition 5.2.0, control CM-07',
            mapping_provenance: 'project_asserted',
          },
          {
            framework: 'stig',
            control_id: 'CISC-ND-000140',
            edition: 'V3R7 (2026-04-01)',
            citation:
              'DISA Cisco IOS XE Router NDM STIG — XCCDF manual benchmark, edition V3R7 (2026-04-01), control CISC-ND-000140',
            mapping_provenance: 'project_asserted',
          },
        ],
        declined: [],
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
        declined: [
          {
            framework: 'stig',
            reason:
              'CISC-ND-000720 requires five minutes or less; this rule passes up to ten.',
          },
        ],
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
  /**
   * A remediation plan in the shape the API actually returns.
   *
   * Copied from a live `/compliance/audits/{id}/remediation` response. Commands
   * are nested under `snippet`, and `snippet` is null when the vetted library
   * resolved nothing for that rule and platform. The
   * earlier fixtures stubbed this endpoint as 404 or `{steps: []}`, so nothing
   * ever exercised a real step and a wrong assumption about its shape reached
   * the browser.
   */
  remediation: {
    audit_id: 'aud-1',
    config_file_id: 'file-1',
    platform: 'cisco/ios',
    failing_findings: 2,
    resolved: 1,
    snippet_library_version: 'empty',
    note: 'Steps that resolved to nothing carry no apply_order.',
    steps: [
      {
        apply_order: 1,
        rule_id: 'NRK-HTTP-001',
        severity: 'high',
        expected: 'disabled',
        outcome: 'resolved',
        statement: 'A vetted snippet is available.',
        snippet: {
          snippet_id: 'snip-1',
          vendor: 'cisco',
          os_family: 'ios',
          commands: ['no ip http server'],
          rollback: ['ip http server'],
          preconditions: [],
          verification: ['show running-config | include http'],
          lockout_risk: 'none',
          service_affecting: false,
          requires_reload: false,
          depends_on: [],
          vetted_by: 'a.operator',
          reference: 'vendor guide 4.2',
        },
      },
      {
        apply_order: null,
        rule_id: 'NRK-TELNET-001',
        severity: 'high',
        expected: 'disabled',
        outcome: 'no_snippet',
        statement: 'No vetted remediation is available for this platform and rule.',
        snippet: null,
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
