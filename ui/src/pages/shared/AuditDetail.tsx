/**
 * One audit run: findings, prioritisation, remediation and the report.
 *
 * The findings table renders **no rank column** unless the backend ranked them.
 * The ordering is the engine's own — verdict, then severity, then rule id — and
 * the table says so, mirroring the sentence the HTML report prints for the same
 * reason. Sorting by severity and calling it prioritisation is the one thing
 * decision D53 exists to prevent.
 */
import { ExternalLink } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { RemediationPanel } from '@/components/domain/RemediationPanel';
import { SeverityLabel, VerdictChip } from '@/components/domain/Verdict';
import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Field, Table, Tabs, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, Loading, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { getAudit, getFindings, getRemediation, pdfReportUrl } from '@/services/audits';
import { getHealth } from '@/services/health';
import type { Severity, Verdict } from '@/types/api';
import { formatTimestamp, ruleLabel, shortId } from '@/utils/format';

export function AuditDetailPage() {
  const { auditId = '' } = useParams();
  const [tab, setTab] = useState('findings');
  const [status, setStatus] = useState<Verdict | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');

  const run = useApi(() => getAudit(auditId), [auditId]);
  const findings = useApi(
    () =>
      getFindings(auditId, {
        ...(status ? { status } : {}),
        ...(severity ? { severity } : {}),
      }),
    [auditId, status, severity],
  );
  const remediation = useApi(() => getRemediation(auditId), [auditId]);
  const health = useApi(() => getHealth(), []);

  const ranked = useMemo(
    () => (findings.data?.findings ?? []).some((f) => f.priority_rank != null),
    [findings.data],
  );

  if (run.loading) return <Loading label="Loading audit" />;
  if (run.error) return <ErrorState message={run.error} onRetry={run.reload} />;
  if (!run.data) return <EmptyState title="Audit not found" />;

  const pdfAvailable = health.data?.pdf_reporting.available ?? false;

  return (
    <>
      <PageHeader
        breadcrumb={[{ label: 'Audits', to: '/audits' }, { label: shortId(auditId, 16) }]}
        title="Audit run"
        subtitle={
          <span className="mono">
            {run.data.rulepack_id} {run.data.rulepack_version} · engine {run.data.engine_version}
          </span>
        }
        actions={
          <>
            <a
              href={`/compliance/audits/${auditId}/report.html`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded border
                         border-border-strong bg-paper text-[13px] font-medium text-ink
                         hover:bg-surface"
            >
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              HTML report
            </a>
            {pdfAvailable ? (
              <a
                href={pdfReportUrl(auditId)}
                className="inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded border
                           border-border-strong bg-paper text-[13px] font-medium text-ink
                           hover:bg-surface"
              >
                PDF
              </a>
            ) : (
              <span
                className="inline-flex items-center h-8 px-3 rounded border border-border
                           text-[13px] text-muted"
                title={health.data?.pdf_reporting.detail}
              >
                PDF unavailable
              </span>
            )}
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-4 mb-4">
        <Card className="lg:col-span-2">
          <CardHeader title="Verdicts" />
          <div className="p-4">
            <VerdictCounts counts={run.data.verdicts} />
            <p className="mt-3 text-2xs text-muted leading-relaxed">
              Counts, not a percentage. A single number cannot carry three-valued logic: an
              abstention is neither a pass nor a failure, and folding it into either would hide
              what the engine actually said.
            </p>
          </div>
        </Card>
        <Card>
          <CardHeader title="Scope" />
          <div className="p-4 space-y-3">
            <Field label="Rules evaluated">
              <span className="num">{run.data.rules_evaluated}</span>
            </Field>
            <Field label="Evaluated at">{formatTimestamp(run.data.evaluated_at)}</Field>
          </div>
        </Card>
        <Card>
          <CardHeader title="Provenance" />
          <div className="p-4 space-y-3">
            <Field label="Vendor packs" mono>
              {Object.entries(run.data.pack_versions)
                .map(([v, ver]) => `${v} ${ver}`)
                .join(', ') || '—'}
            </Field>
            <Field label="Configuration" mono>
              <Link to={`/devices/${run.data.device_id}`} className="link">
                {shortId(run.data.device_id, 14)}
              </Link>
            </Field>
          </div>
        </Card>
      </div>

      <Card>
        <Tabs
          tabs={[
            { id: 'findings', label: 'Findings', count: findings.data?.count },
            { id: 'prioritisation', label: 'Prioritisation' },
            { id: 'remediation', label: 'Remediation', count: remediation.data?.steps.length },
          ]}
          active={tab}
          onChange={setTab}
        />

        {tab === 'findings' && (
          <>
            <div className="p-3 border-b border-border flex flex-wrap gap-2">
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as Verdict | '')}
                aria-label="Filter by verdict"
                className="h-8 px-2 rounded border border-border bg-paper text-[13px]"
              >
                <option value="">All verdicts</option>
                <option value="fail">Fail</option>
                <option value="unknown">Unknown</option>
                <option value="pass">Pass</option>
                <option value="not_applicable">Not applicable</option>
              </select>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity | '')}
                aria-label="Filter by severity"
                className="h-8 px-2 rounded border border-border bg-paper text-[13px]"
              >
                <option value="">All severities</option>
                {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <p className="ml-auto self-center text-2xs text-muted">
                Ordered by verdict, then severity, then rule id. This is not an exposure ranking.
              </p>
            </div>

            {findings.loading && <SkeletonRows rows={6} cols={4} />}
            {findings.error && !findings.loading && (
              <ErrorState message={findings.error} onRetry={findings.reload} />
            )}
            {!findings.loading && !findings.error && (findings.data?.count ?? 0) === 0 && (
              <EmptyState title="No findings match" detail="Clear the filters to see them all." />
            )}
            {!findings.loading && !findings.error && (findings.data?.count ?? 0) > 0 && (
              <Table caption="Findings">
                <thead>
                  <tr>
                    {/* Rendered only when the backend actually ranked. */}
                    {ranked && <Th style={{ width: 48 }}>#</Th>}
                    <Th style={{ width: 104 }}>Verdict</Th>
                    <Th>Control</Th>
                    <Th style={{ width: 120 }}>Severity</Th>
                    <Th style={{ width: 240 }}>Evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data!.findings.map((f) => (
                    <tr key={f.finding_id}>
                      {ranked && <Td className="num text-muted">{f.priority_rank ?? '—'}</Td>}
                      <Td>
                        <VerdictChip verdict={f.status} />
                      </Td>
                      <Td>
                        <Link
                          to={`/audits/${auditId}/findings/${encodeURIComponent(f.finding_id)}`}
                          className="link font-medium"
                        >
                          {ruleLabel(f.rule_id)}
                        </Link>
                        <div className="mono text-muted text-[12px]">{f.rule_id}</div>
                      </Td>
                      <Td>
                        <SeverityLabel severity={f.severity} />
                      </Td>
                      <Td className="mono text-[12px] text-muted truncate max-w-[240px]">
                        {f.evidence[0]?.raw_line ?? '—'}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}

        {tab === 'prioritisation' && (
          <div className="p-4">
            <BlockedState
              title="Prioritisation runs on every audit"
              reason={
                'The stage executed when this audit ran. Its result is returned on the audit ' +
                'response itself and is not persisted, so it cannot be read back for a past run — ' +
                're-run the audit to see the live breakdown, or open Prioritisation for the ' +
                'fleet-wide view.'
              }
            />
            <div className="mt-2">
              <Link to="/prioritisation" className="link text-[13px]">
                Open the prioritisation view →
              </Link>
            </div>
          </div>
        )}

        {tab === 'remediation' && (
          <div className="p-4">
            {remediation.loading && <Loading label="Loading remediation" />}
            {remediation.error && (
              <ErrorState message={remediation.error} onRetry={remediation.reload} />
            )}
            {remediation.data && (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-3">
                  <Field label="Platform">{remediation.data.platform}</Field>
                  <Field label="Failing findings">
                    <span className="num">{remediation.data.failing_findings}</span>
                  </Field>
                  <Field label="Snippet library">
                    <span className="mono">{remediation.data.snippet_library_version}</span>
                  </Field>
                </div>

                {remediation.data.steps.length === 0 ? (
                  <BlockedState
                    title="No remediation steps"
                    reason={remediation.data.note}
                    unblockedBy="A vetted snippet, written by a person who read the vendor documentation."
                  />
                ) : (
                  <ul className="space-y-4">
                    {remediation.data.steps.map((step, index) => (
                      <li key={`${step.rule_id}-${index}`} className="border-t border-border pt-3">
                        <p className="mono text-[12px] text-muted mb-2">{step.rule_id}</p>
                        <RemediationPanel
                          remediation={{
                            outcome: step.outcome,
                            statement: step.statement,
                            snippet_id: null,
                            commands: step.commands,
                            rollback: step.rollback,
                            vetted_by: null,
                            reference: null,
                          }}
                        />
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
      </Card>

    </>
  );
}
