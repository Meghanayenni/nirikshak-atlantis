/**
 * The remaining screens.
 *
 * Grouped in one module because each is small and they share one shape: state
 * what the backend can do, and say plainly where it cannot. None of them
 * fabricates a capability to look complete.
 */
import { Link } from 'react-router-dom';

import { VerdictChip, SeverityLabel } from '@/components/domain/Verdict';
import { CapabilityNotice, PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Field, Table, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, Loading, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { getFindings, listAudits } from '@/services/audits';
import { whoami } from '@/services/auth';
import { ADMIN_NAV } from '@/layouts/navigation';
import { formatTimestamp, ruleLabel, shortId } from '@/utils/format';

function noteFor(path: string): string {
  return ADMIN_NAV.find((item) => item.to === path)?.note ?? '';
}

// ---------------------------------------------------------------------------
// Findings — aggregated across the runs the caller can see
// ---------------------------------------------------------------------------

/**
 * There is no fleet-wide findings endpoint: findings are scoped to an audit run.
 * This page therefore fans out over the runs the caller can already see, which
 * is a composition of existing responses rather than a new claim.
 */
export function FindingsPage() {
  const { isAdmin } = useAuth();
  const audits = useApi(() => listAudits(50), []);

  const latest = (audits.data ?? [])
    .slice()
    .sort((a, b) => (b.evaluated_at ?? '').localeCompare(a.evaluated_at ?? ''))
    .slice(0, 1)[0];

  const findings = useApi(
    () => (latest ? getFindings(latest.audit_id) : Promise.resolve(null)),
    [latest?.audit_id],
  );

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Findings' : 'My findings'}
        subtitle="Every finding is a deterministic rule-engine result, never a model output"
      />

      {audits.loading && <SkeletonRows rows={6} cols={4} />}
      {audits.error && <ErrorState message={audits.error} onRetry={audits.reload} />}

      {!audits.loading && !latest && (
        <Card>
          <EmptyState
            title="No audits yet"
            detail="Findings appear once a configuration has been audited."
            action={
              <Link to="/audits" className="link text-[13px]">
                Go to audits →
              </Link>
            }
          />
        </Card>
      )}

      {latest && (
        <Card>
          <CardHeader
            title="Most recent run"
            subtitle={`${shortId(latest.audit_id, 16)} · ${formatTimestamp(latest.evaluated_at)}`}
            actions={
              <Link to={`/audits/${latest.audit_id}`} className="link text-[13px]">
                Open run
              </Link>
            }
          />
          {findings.loading && <SkeletonRows rows={6} cols={4} />}
          {findings.error && <ErrorState message={findings.error} onRetry={findings.reload} />}
          {findings.data && (
            <Table caption="Findings from the most recent audit run">
              <thead>
                <tr>
                  <Th style={{ width: 104 }}>Verdict</Th>
                  <Th>Control</Th>
                  <Th style={{ width: 120 }}>Severity</Th>
                  <Th style={{ width: 240 }}>Evidence</Th>
                </tr>
              </thead>
              <tbody>
                {findings.data.findings.map((f) => (
                  <tr key={f.finding_id}>
                    <Td>
                      <VerdictChip verdict={f.status} />
                    </Td>
                    <Td>
                      <Link
                        to={`/audits/${latest.audit_id}/findings/${encodeURIComponent(f.finding_id)}`}
                        className="link font-medium"
                      >
                        {ruleLabel(f.rule_id)}
                      </Link>
                      <div className="mono text-[12px] text-muted">{f.rule_id}</div>
                    </Td>
                    <Td>
                      <SeverityLabel severity={f.severity} />
                    </Td>
                    <Td className="mono text-[12px] text-muted">
                      {f.evidence[0]?.raw_line ?? '—'}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
          <p className="px-4 py-3 text-2xs text-muted border-t border-border leading-relaxed">
            Findings are scoped to an audit run by the API, so this shows the most recent run.
            Open a device to see its full history.
          </p>
        </Card>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export function ReportsPage() {
  const { isAdmin } = useAuth();
  const audits = useApi(() => listAudits(200), []);

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Reports' : 'My reports'}
        subtitle="One evidence-linked HTML document per audit run"
      />
      <Card>
        <CardHeader
          title="Available reports"
          subtitle="Regenerated from the persisted run each time, never stored as a second copy"
        />
        {audits.loading && <SkeletonRows rows={5} cols={3} />}
        {audits.error && <ErrorState message={audits.error} onRetry={audits.reload} />}
        {audits.data && audits.data.length === 0 && (
          <EmptyState title="No reports" detail="Run an audit to produce one." />
        )}
        {audits.data && audits.data.length > 0 && (
          <Table caption="Reports">
            <thead>
              <tr>
                <Th>Run</Th>
                <Th>Evaluated</Th>
                <Th style={{ width: 200 }}>Document</Th>
              </tr>
            </thead>
            <tbody>
              {audits.data.map((run) => (
                <tr key={run.audit_id}>
                  <Td className="mono">{shortId(run.audit_id, 16)}</Td>
                  <Td className="text-muted">{formatTimestamp(run.evaluated_at)}</Td>
                  <Td>
                    <a
                      href={`/compliance/audits/${run.audit_id}/report.html`}
                      target="_blank"
                      rel="noreferrer"
                      className="link"
                    >
                      Open HTML report
                    </a>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <p className="px-4 py-3 text-2xs text-muted border-t border-border leading-relaxed">
          The HTML report is self-contained — no external stylesheet, script or web font — so it
          can be saved, mailed or opened on a machine with no network. PDF rendering needs the
          WeasyPrint/GTK stack; where it is absent the endpoint answers 503 and names the missing
          libraries rather than substituting the HTML document under a .pdf name.
        </p>
      </Card>
    </>
  );
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

export function ProfilePage() {
  const me = useApi(() => whoami(), []);

  if (me.loading) return <Loading label="Loading profile" />;
  if (me.error) return <ErrorState message={me.error} onRetry={me.reload} />;
  if (!me.data) return null;

  return (
    <>
      <PageHeader title="My profile" subtitle="Your identity as the server records it" />
      <Card className="max-w-2xl">
        <CardHeader title="Account" />
        <div className="p-4 grid gap-4 sm:grid-cols-2">
          <Field label="Username">{me.data.username}</Field>
          <Field label="Role">
            <span className="uppercase text-2xs tracking-wider text-ink-2">{me.data.role}</span>
          </Field>
          <Field label="Status">{me.data.disabled ? 'Disabled' : 'Active'}</Field>
          <Field label="Created">{formatTimestamp(me.data.created_at)}</Field>
          <Field label="User id" mono>
            {me.data.user_id}
          </Field>
        </div>
        <p className="px-4 py-3 text-2xs text-muted border-t border-border leading-relaxed">
          Nothing here is editable. The backend exposes no profile-update or password-change
          endpoint, and a role is assigned by an administrator — a user cannot change their own.
          Presenting an editable field that could not save would be worse than presenting none.
        </p>
      </Card>
    </>
  );
}

// ---------------------------------------------------------------------------
// Capability-limited pages
// ---------------------------------------------------------------------------

export function CompliancePage() {
  const { isAdmin } = useAuth();
  return (
    <>
      <PageHeader
        title={isAdmin ? 'Compliance' : 'My compliance'}
        subtitle="Framework coverage"
      />
      <CapabilityNotice note={noteFor('/compliance')} />
      <Card>
        <BlockedState
          title="No framework mapping is available"
          reason={
            'Every rule ships with an empty framework list. NIRIKSHAK evaluates its own checks ' +
            'and maps them to nothing, because writing a CIS, NIST SP 800-53, DISA STIG or ' +
            'ISO/IEC 27001 identifier without having read the benchmark would be inventing it. ' +
            'No claim of coverage against any of those four frameworks is made or supported.'
          }
          unblockedBy="A benchmark edition obtained and read, so a mapping can name a control and its source document."
        />
      </Card>
    </>
  );
}

export function RemediationPage() {
  const { isAdmin } = useAuth();
  return (
    <>
      <PageHeader
        title={isAdmin ? 'Remediation' : 'My remediation'}
        subtitle="Vetted commands, keyed by vendor, OS family and rule"
      />
      <CapabilityNotice note={noteFor('/remediation')} />
      <Card>
        <BlockedState
          title="The vetted snippet library is empty"
          reason={
            'Commands come only from the vetted snippet library and are never generated. A ' +
            'snippet cannot exist without a person who read a vendor document and checked the ' +
            'commands, their rollback and their service impact against it — so every failing ' +
            'finding reads "No vetted remediation is available for this platform and rule."'
          }
          unblockedBy="A vendor configuration guide, obtained and read, with the commands checked against it."
        />
        <p className="px-5 pb-5 text-2xs text-muted leading-relaxed">
          Open any audit run to see the resolver&rsquo;s own statement per finding. NIRIKSHAK
          recommends; a human operator applies.
        </p>
      </Card>
    </>
  );
}

export function DriftPage() {
  return (
    <>
      <PageHeader title="Drift detection" subtitle="Configuration change over time" />
      <Card>
        <BlockedState
          title="Not implemented"
          reason={noteFor('/drift')}
          unblockedBy="A backend snapshot store and comparison endpoint."
        />
        <p className="px-5 pb-5 text-2xs text-muted leading-relaxed">
          Peer-baseline drift — how one device differs from its cohort right now — is a different
          question and is available under Prioritisation.
        </p>
      </Card>
    </>
  );
}

export function VendorPacksPage() {
  const audits = useApi(() => listAudits(200), []);

  const packs = new Map<string, string>();
  for (const run of audits.data ?? []) {
    for (const [vendor, version] of Object.entries(run.pack_versions)) {
      packs.set(vendor, version);
    }
  }

  return (
    <>
      <PageHeader title="Vendor packs" subtitle="How each platform's syntax maps to the schema" />
      <CapabilityNotice note={noteFor('/packs')} />
      <Card>
        {audits.loading && <SkeletonRows rows={3} cols={2} />}
        {audits.error && <ErrorState message={audits.error} onRetry={audits.reload} />}
        {!audits.loading && packs.size === 0 && (
          <EmptyState
            title="No pack versions recorded"
            detail="Pack versions are recorded on audit runs. Run an audit to populate this view."
          />
        )}
        {packs.size > 0 && (
          <Table caption="Vendor pack versions in use">
            <thead>
              <tr>
                <Th>Vendor</Th>
                <Th>Version in use</Th>
              </tr>
            </thead>
            <tbody>
              {[...packs.entries()].map(([vendor, version]) => (
                <tr key={vendor}>
                  <Td className="font-medium">{vendor}</Td>
                  <Td className="mono">{version}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <p className="px-4 py-3 text-2xs text-muted border-t border-border leading-relaxed">
          These are the versions recorded on audit runs — the pack that actually read the line,
          not whichever pack happens to be active now. Pack contents, patterns and activation
          history are not exposed by any endpoint. New pack versions are created through the
          training centre.
        </p>
      </Card>
    </>
  );
}

export function NotFoundPage() {
  return (
    <Card>
      <EmptyState
        title="Page not found"
        detail="That route does not exist in this interface."
        action={
          <Link to="/dashboard" className="link text-[13px]">
            Back to the dashboard →
          </Link>
        }
      />
    </Card>
  );
}
