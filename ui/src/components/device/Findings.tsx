/**
 * Findings for one device, each opening in place.
 *
 * The finding is the atom of the product (§10), so it is reachable without
 * leaving the device: a row expands, the evidence loads underneath it, and the
 * operator never loses the list they were working through.
 */
import { ChevronDown, ChevronRight } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';

import { EvidenceViewer } from '@/components/domain/EvidenceViewer';
import { RemediationPanel } from '@/components/domain/RemediationPanel';
import {
  ConfidenceBadge,
  FieldStateLabel,
  SeverityLabel,
  VerdictChip,
} from '@/components/domain/Verdict';
import { Field, NotAvailable, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import type { Finding, FrameworkView, Verdict } from '@/types/api';
import { humanise, ruleLabel } from '@/utils/format';

import type { DeviceWorkspace } from './useDeviceWorkspace';

const FILTERS: { id: '' | Verdict; label: string }[] = [
  { id: '', label: 'All' },
  { id: 'fail', label: 'Fail' },
  { id: 'unknown', label: 'Unknown' },
  { id: 'pass', label: 'Pass' },
  { id: 'not_applicable', label: 'N/A' },
];

/**
 * The controls this finding's rule maps to — every value from the API.
 *
 * Plain metadata, never a verdict-coloured chip: a mapping is a cross-reference,
 * and a second colour scale would compete with the verdict (§10, ADR 0036).
 * Each identifier carries its edition and its provenance, because a control ID
 * without "project asserted" beside it claims a crosswalk nobody published.
 *
 * Three states, and each says what it is (ADR 0057):
 *   - withheld: the run's rules are not the active rules; the API's reason;
 *   - mapped, with declined frameworks and their recorded reasons;
 *   - frameworks absent on this device, each with why.
 * "No framework control is mapped" appeared here on every finding from P17 to
 * P18 while every rule was mapped; it is not said by default any more.
 */
function FrameworkMappings({ finding, view }: { finding: Finding; view: FrameworkView | null }) {
  if (view && !view.attached) {
    return (
      <div>
        <p className="label mb-1">Frameworks</p>
        <p className="text-muted">
          Control mappings are not shown for this run. {view.withheld_reason}
        </p>
      </div>
    );
  }

  const absent = Object.entries(view?.absent ?? {});

  return (
    <div className="space-y-3">
      <div>
        <p className="label mb-1">Frameworks</p>
        {finding.frameworks.length === 0 ? (
          <p className="text-muted">
            No control in a sourced framework that describes this device is mapped to this check.
          </p>
        ) : (
          <ul className="space-y-1.5" aria-label="Mapped controls">
            {finding.frameworks.map((ref) => (
              <li key={`${ref.framework}-${ref.control_id}`}>
                <span className="label mr-2 uppercase">{ref.framework}</span>
                <span className="mono text-ink">{ref.control_id}</span>
                <span className="block text-xs text-muted">
                  {ref.edition ? `edition ${ref.edition} · ` : ''}
                  {ref.mapping_provenance === 'project_asserted'
                    ? 'project asserted — our judgement, not a published crosswalk'
                    : humanise(ref.mapping_provenance)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {finding.declined.length > 0 && (
        <div>
          <p className="label mb-1">Declined mappings</p>
          <ul className="space-y-1.5" aria-label="Declined mappings">
            {finding.declined.map((gap) => (
              <li key={gap.framework} className="text-ink-2">
                <span className="label mr-2 uppercase">{gap.framework}</span>
                not mapped — {gap.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {absent.length > 0 && (
        <div>
          <p className="label mb-1">Not applicable to this device</p>
          <ul className="space-y-1 text-xs text-muted" aria-label="Frameworks absent on this device">
            {absent.map(([framework, why]) => (
              <li key={framework}>
                <span className="uppercase">{framework}</span> — {why}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function FindingDetail({ finding, view }: { finding: Finding; view: FrameworkView | null }) {
  return (
    <div className="grid gap-5 bg-surface px-4 py-5 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <div className="grid gap-4 sm:grid-cols-2">
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
        </div>

        {finding.status === 'unknown' && finding.unknown_reason && (
          <div className="rounded border border-unknown-br bg-unknown-bg px-3 py-2">
            <p className="label">Why this abstained</p>
            <p className="mt-0.5 text-ink-2">{humanise(finding.unknown_reason)}</p>
          </div>
        )}

        {finding.absence_reason && (
          <div className="rounded border border-inferred-br bg-inferred-bg px-3 py-2">
            <p className="label">Rests on a documented default</p>
            <p className="mt-0.5 text-ink-2">{finding.absence_reason}</p>
          </div>
        )}

        <div className="space-y-3">
          <p className="label">Evidence</p>
          {finding.evidence.length === 0 ? (
            <p className="text-muted">
              No line is cited — this verdict rests on the absence of a directive.
            </p>
          ) : (
            finding.evidence.map((evidence) => (
              <EvidenceViewer key={evidence.cite} evidence={evidence} />
            ))
          )}
        </div>
      </div>

      <div className="space-y-5">
        <div>
          <p className="label mb-2">Remediation</p>
          <RemediationPanel remediation={finding.remediation} />
        </div>

        <FrameworkMappings finding={finding} view={view} />

        <div>
          <p className="label mb-1">Priority</p>
          {finding.priority_rank == null ? (
            <p className="text-muted">Exposure was not determined, so this is unranked.</p>
          ) : (
            <p className="num text-ink">#{finding.priority_rank}</p>
          )}
        </div>
      </div>
    </div>
  );
}

export function FindingsPanel({ workspace }: { workspace: DeviceWorkspace }) {
  const { findings, latest } = workspace;
  const [filter, setFilter] = useState<'' | Verdict>('');
  const [openId, setOpenId] = useState<string | null>(null);

  const all = useMemo(() => findings.data?.findings ?? [], [findings.data]);
  const rows = useMemo(
    () => (filter ? all.filter((f) => f.status === filter) : all),
    [all, filter],
  );

  const counts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const finding of all) map[finding.status] = (map[finding.status] ?? 0) + 1;
    return map;
  }, [all]);

  if (!latest) {
    return (
      <EmptyState title="No audit yet" detail="Run an audit to evaluate this configuration." />
    );
  }
  if (findings.loading) return <SkeletonRows rows={6} cols={4} />;
  if (findings.error) return <ErrorState message={findings.error} onRetry={findings.reload} />;
  if (all.length === 0) return <EmptyState title="No findings in this run" />;

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
        {FILTERS.map((option) => {
          const active = option.id === filter;
          const count = option.id ? (counts[option.id] ?? 0) : all.length;
          return (
            <button
              key={option.id || 'all'}
              type="button"
              onClick={() => setFilter(option.id)}
              aria-pressed={active}
              className={`h-8 rounded-full border px-3 transition-colors
                ${
                  active
                    ? 'border-ink bg-ink text-white'
                    : 'border-border bg-paper text-ink-2 hover:bg-surface'
                }`}
            >
              {option.label} <span className="num opacity-70">{count}</span>
            </button>
          );
        })}
      </div>

      <Table caption="Findings">
        <thead>
          <tr>
            <Th style={{ width: 36 }}>
              <span className="sr-only">Expand</span>
            </Th>
            <Th style={{ width: 116 }}>Verdict</Th>
            <Th>Control</Th>
            <Th style={{ width: 130 }}>Severity</Th>
            <Th>Cited line</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((finding) => {
            const open = openId === finding.finding_id;
            return (
              <Fragment key={finding.finding_id}>
                <tr
                  className="row-button"
                  onClick={() => setOpenId(open ? null : finding.finding_id)}
                >
                  <Td>
                    <button
                      type="button"
                      aria-expanded={open}
                      aria-label={open ? 'Collapse finding' : 'Expand finding'}
                      className="text-muted"
                      onClick={(event) => {
                        event.stopPropagation();
                        setOpenId(open ? null : finding.finding_id);
                      }}
                    >
                      {open ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </button>
                  </Td>
                  <Td>
                    <VerdictChip verdict={finding.status} />
                  </Td>
                  <Td>
                    <span className="font-medium text-ink">{ruleLabel(finding.rule_id)}</span>
                    <span className="mono ml-2 text-muted">{finding.rule_id}</span>
                  </Td>
                  <Td>
                    <SeverityLabel severity={finding.severity} />
                  </Td>
                  <Td className="mono text-muted">
                    {finding.evidence[0]?.raw_line ?? <NotAvailable reason="no line cited" />}
                  </Td>
                </tr>
                {open && (
                  <tr>
                    <td colSpan={5} className="border-b border-border p-0">
                      <FindingDetail
                        finding={finding}
                        view={findings.data?.framework_view ?? null}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </Table>
    </>
  );
}
