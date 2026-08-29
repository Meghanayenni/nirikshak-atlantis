/**
 * The finding detail view.
 *
 * DEVELOPER_GUIDE.md §10: "Build the finding detail view before any dashboard — it is the
 * atom of the product; everything else is composition." This screen answers the
 * third level of zoom: *why do you claim that, and what do I type?*
 *
 * Four things it must get right, all of them from §10 and the reference:
 *
 *   The verdict is the rule engine's, and is labelled as such. Nothing on this
 *   page implies a model produced it.
 *
 *   Evidence is one interaction away and is the operator's own text, shown with
 *   surrounding lines and the cited span marked.
 *
 *   Confidence names its population. An abstention shows its reason instead of a
 *   number pretending to be one.
 *
 *   Remediation shows the resolver's statement, and a command only if the vetted
 *   library returned one.
 */
import { useParams } from 'react-router-dom';

import { EvidenceViewer } from '@/components/domain/EvidenceViewer';
import { RemediationPanel } from '@/components/domain/RemediationPanel';
import {
  ConfidenceBadge,
  FieldStateLabel,
  SeverityLabel,
  VerdictChip,
} from '@/components/domain/Verdict';
import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Field, NotAvailable } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, Loading } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { getFindings } from '@/services/audits';
import { humanise, ruleLabel } from '@/utils/format';

export function FindingDetailPage() {
  const { auditId = '', findingId = '' } = useParams();
  const { data, error, loading, reload } = useApi(() => getFindings(auditId), [auditId]);

  if (loading) return <Loading label="Loading finding" />;
  if (error) return <ErrorState message={error} onRetry={reload} />;

  const finding = data?.findings.find((f) => f.finding_id === decodeURIComponent(findingId));
  if (!finding) {
    return (
      <EmptyState
        title="Finding not found"
        detail="This finding is not part of the audit run, or the run belongs to another user."
      />
    );
  }

  const abstained = finding.status === 'unknown';

  return (
    <>
      <PageHeader
        breadcrumb={[
          { label: 'Audits', to: '/audits' },
          { label: auditId.slice(0, 12), to: `/audits/${auditId}` },
          { label: finding.rule_id },
        ]}
        title={ruleLabel(finding.rule_id)}
        subtitle={
          <span className="inline-flex items-center gap-2">
            <span className="mono">{finding.rule_id}</span>
            <span aria-hidden="true">·</span>
            <SeverityLabel severity={finding.severity} />
          </span>
        }
        actions={<VerdictChip verdict={finding.status} />}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader
              title="What was observed"
              subtitle="Produced by the deterministic rule engine, reading the canonical model"
            />
            <div className="p-4 grid gap-4 sm:grid-cols-2">
              <Field label="Expected">{finding.expected}</Field>
              <Field label="Observed state">
                <FieldStateLabel state={finding.observed.state} />
              </Field>
              <Field label="Observed value" mono>
                {finding.observed.value === null || finding.observed.value === undefined ? (
                  <NotAvailable reason="the field did not resolve to a value" />
                ) : (
                  String(finding.observed.value)
                )}
              </Field>
              <Field label="Confidence">
                <ConfidenceBadge
                  confidence={finding.observed.confidence}
                  method={finding.observed.confidence_method}
                  isProbability={finding.observed.is_probability}
                />
              </Field>

              {abstained && finding.unknown_reason && (
                <div className="sm:col-span-2 rounded border border-unknown-br bg-unknown-bg px-3 py-2">
                  <p className="label">Why this abstained</p>
                  <p className="mt-0.5 text-[13px] text-ink-2">
                    {humanise(finding.unknown_reason)}
                  </p>
                </div>
              )}

              {finding.absence_reason && (
                <div className="sm:col-span-2 rounded border border-inferred-br bg-inferred-bg px-3 py-2">
                  <p className="label">Rests on a documented default</p>
                  <p className="mt-0.5 text-[13px] text-ink-2">{finding.absence_reason}</p>
                </div>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Evidence"
              subtitle={
                finding.evidence.length > 0
                  ? 'The configuration line this verdict rests on'
                  : undefined
              }
            />
            <div className="p-4 space-y-3">
              {finding.evidence.length === 0 ? (
                <p className="text-[13px] text-muted">
                  No line is cited. This verdict rests on the <em>absence</em> of a directive
                  rather than on something written in the configuration.
                </p>
              ) : (
                finding.evidence.map((evidence) => (
                  <EvidenceViewer key={evidence.cite} evidence={evidence} />
                ))
              )}
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Remediation" />
            <div className="p-4">
              <RemediationPanel remediation={finding.remediation} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Frameworks" />
            <div className="p-4">
              {finding.frameworks.length === 0 ? (
                <p className="text-[13px] text-muted leading-relaxed">
                  This check maps to no framework control. NIRIKSHAK evaluates its own checks and
                  claims no CIS, NIST SP 800-53, DISA STIG or ISO/IEC 27001 coverage: writing an
                  identifier without having read the benchmark would be inventing it.
                </p>
              ) : (
                <ul className="space-y-1">
                  {finding.frameworks.map((ref) => (
                    <li key={`${ref.framework}-${ref.control_id}`} className="text-[13px]">
                      <span className="label mr-2">{ref.framework}</span>
                      <span className="mono">{ref.control_id}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Priority" />
            <div className="p-4">
              {finding.priority_rank == null ? (
                <p className="text-[13px] text-muted leading-relaxed">
                  No exposure rank. Exposure needs interface and access-list data that this build
                  does not extract, and severity alone must not determine remediation order.
                </p>
              ) : (
                <Field label="Rank">
                  <span className="num">#{finding.priority_rank}</span>
                </Field>
              )}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
