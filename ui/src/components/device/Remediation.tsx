/**
 * Remediation for one device, with the human review step.
 *
 * Rule 4: every command here came from the vetted snippet library. Nothing on
 * this screen can render a command string that was not in the response, and
 * there is no field an operator can type one into — a command NIRIKSHAK
 * displays is a command somebody vetted against a vendor document.
 *
 * Marking a step reviewed is a local note (see `useLocalReview`) and says so.
 */
import { Check, Square } from 'lucide-react';
import { useState } from 'react';

import { Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import type { RemediationStepSnippet } from '@/types/api';
import { ruleLabel } from '@/utils/format';

import type { DeviceWorkspace } from './useDeviceWorkspace';

function Commands({ title, lines }: { title: string; lines: string[] }) {
  return (
    <div>
      <p className="label mb-1">{title}</p>
      <pre className="mono overflow-x-auto whitespace-pre rounded border border-border bg-surface p-3 text-ink">
        {lines.join('\n')}
      </pre>
    </div>
  );
}

function Notes({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="label mb-1">{title}</p>
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item} className="flex gap-2 text-ink-2">
            <span aria-hidden="true" className="text-muted">
              &mdash;
            </span>
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * What applying this does to a running device.
 *
 * §10: "Remediation displays with its rollback and its impact note; never the
 * command alone." A high lockout risk is the one thing on this screen that can
 * end an operator's access to the device they are fixing, so it is stated in
 * words and carries the FAIL weight — the same treatment a failing verdict gets,
 * because it is the same order of consequence. The words do the work; the colour
 * only makes them findable.
 */
function Impact({ snippet }: { snippet: RemediationStepSnippet }) {
  const high = snippet.lockout_risk === 'high';
  return (
    <div>
      <p className="label mb-1">Impact</p>
      <div
        className={`rounded border p-3 ${
          high ? 'border-fail-br bg-fail-bg' : 'border-border bg-surface'
        }`}
      >
        <p className={high ? 'font-medium text-fail' : 'text-ink-2'}>
          Lockout risk: {snippet.lockout_risk}
          {snippet.service_affecting && ' · service affecting'}
          {snippet.requires_reload && ' · requires a reload'}
        </p>
        {high && (
          <p className="mt-1 text-ink-2">
            This change can end your own access to the device. It is sequenced last for that
            reason. Apply it from a session it does not close, with a console path open.
          </p>
        )}
        {snippet.depends_on.length > 0 && (
          <p className="mt-1 text-muted">
            Apply after <span className="mono">{snippet.depends_on.join(', ')}</span>.
          </p>
        )}
      </div>
    </div>
  );
}

export function RemediationTab({ workspace }: { workspace: DeviceWorkspace }) {
  const { remediation, latest, actionableSteps, review } = workspace;

  /**
   * Which steps are open. Every step that HAS a command starts open.
   *
   * The panel used to collapse everything and print "Vetted command available"
   * in the resolution column, which told an operator that the thing they came
   * for exists and then made them click to see it. This screen answers "what do
   * I type"; hiding the answer behind a disclosure is the wrong default.
   *
   * `null` means "not decided yet" and is resolved from the plan on first
   * render, so a step the operator collapses stays collapsed instead of being
   * reopened every time the plan refetches.
   */
  const [open, setOpen] = useState<Set<string> | null>(null);

  if (!latest) {
    return <EmptyState title="No audit yet" detail="Run an audit to resolve remediation." />;
  }
  if (remediation.loading) return <SkeletonRows rows={5} cols={3} />;
  if (remediation.error) {
    return <ErrorState message={remediation.error} onRetry={remediation.reload} />;
  }

  const plan = remediation.data;
  if (!plan || plan.steps.length === 0) {
    return <EmptyState title="Nothing to remediate" detail="This run produced no failures." />;
  }

  const reviewedCount = actionableSteps.filter((step) => review.isReviewed(step.rule_id)).length;

  const expanded = open ?? new Set(actionableSteps.map((step) => step.rule_id));
  const toggle = (ruleId: string) =>
    setOpen(() => {
      const next = new Set(expanded);
      if (next.has(ruleId)) next.delete(ruleId);
      else next.add(ruleId);
      return next;
    });

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
        <p className="text-ink-2">
          <span className="num font-medium text-ink">{plan.failing_findings}</span> failing ·{' '}
          <span className="num font-medium text-ink">{plan.resolved}</span> with a vetted command
        </p>
        {actionableSteps.length > 0 && (
          <p className="text-muted">
            <span className="num">{reviewedCount}</span>/
            <span className="num">{actionableSteps.length}</span> reviewed
          </p>
        )}
      </div>

      <Table caption="Remediation plan">
        <thead>
          <tr>
            <Th style={{ width: 48 }}>#</Th>
            <Th>Control</Th>
            <Th>Resolution</Th>
            <Th style={{ width: 130 }}>Review</Th>
          </tr>
        </thead>
        <tbody>
          {plan.steps.map((step) => {
            // `snippet` is null whenever the vetted library resolved nothing.
            const snippet = step.snippet;
            const actionable = (snippet?.commands.length ?? 0) > 0;
            const reviewed = review.isReviewed(step.rule_id);
            const isOpen = expanded.has(step.rule_id);
            return (
              <tr key={step.rule_id}>
                {/* The backend's own ordering. It is null for a step with
                    nothing to apply, and a number there would imply there was. */}
                <Td className="num text-muted">{step.apply_order ?? '—'}</Td>
                <Td>
                  <button
                    type="button"
                    onClick={() => toggle(step.rule_id)}
                    aria-expanded={isOpen}
                    className="text-left font-medium text-ink hover:underline"
                  >
                    {ruleLabel(step.rule_id)}
                  </button>
                  <span className="mono ml-2 text-muted">{step.rule_id}</span>
                  {isOpen && (
                    <div className="mt-3 space-y-3">
                      {actionable && snippet ? (
                        <>
                          <Notes title="Before you start" items={snippet.preconditions} />
                          <Commands title="Commands" lines={snippet.commands} />
                          {snippet.rollback.length > 0 && (
                            <Commands title="Rollback" lines={snippet.rollback} />
                          )}
                          <Impact snippet={snippet} />
                          <Notes title="Verify it took effect" items={snippet.verification} />
                          {snippet.vetted_by && (
                            <p className="text-micro text-muted">
                              <span className="label">Vetted by</span>{' '}
                              <span className="text-ink">{snippet.vetted_by}</span>
                              {snippet.reference && <> · {snippet.reference}</>}
                            </p>
                          )}
                          <p className="text-micro text-muted">
                            NIRIKSHAK does not apply these. A human operator applies them, after
                            checking the rollback and the service impact.
                          </p>
                        </>
                      ) : (
                        <p className="text-muted">{step.statement}</p>
                      )}
                    </div>
                  )}
                </Td>
                <Td className="text-ink-2">
                  {/*
                    A count and the consequence, not "a command exists". The
                    commands themselves are open below by default; this column
                    is what an operator scans to plan the order of work.
                  */}
                  {actionable && snippet ? (
                    <>
                      <span className="num font-medium text-ink">{snippet.commands.length}</span>{' '}
                      command{snippet.commands.length === 1 ? '' : 's'}
                      {snippet.rollback.length > 0 && ' · rollback included'}
                      {snippet.lockout_risk === 'high' && (
                        <span className="block font-medium text-fail">Lockout risk: apply last</span>
                      )}
                    </>
                  ) : (
                    step.statement
                  )}
                </Td>
                <Td>
                  {actionable ? (
                    <button
                      type="button"
                      onClick={() => review.toggle(step.rule_id)}
                      aria-pressed={reviewed}
                      className={`inline-flex h-8 items-center gap-1.5 rounded border px-2.5 transition-colors
                        ${
                          reviewed
                            ? 'border-pass-br bg-pass-bg text-pass'
                            : 'border-border bg-paper text-ink-2 hover:bg-surface'
                        }`}
                    >
                      {reviewed ? (
                        <Check className="h-4 w-4" aria-hidden="true" />
                      ) : (
                        <Square className="h-4 w-4" aria-hidden="true" />
                      )}
                      {reviewed ? 'Reviewed' : 'Mark reviewed'}
                    </button>
                  ) : (
                    <span className="text-muted">Nothing to review</span>
                  )}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>

      {actionableSteps.length > 0 && (
        <p className="border-t border-border px-4 py-3 text-micro text-muted">
          Review marks are stored in this browser only. They gate the report below; they are not
          written to the operational store and do not appear in the activity log.
        </p>
      )}
    </div>
  );
}
