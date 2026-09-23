/**
 * One device, and everything the system knows about it.
 *
 * The tabs are the pipeline in order — what was read, what was decided, what
 * needs a person, what to type, and the document at the end. Nothing here
 * navigates away: an operator working a device stays on the device.
 */
import { Lock, RefreshCw } from 'lucide-react';
import { useState } from 'react';

import { VerdictCounts } from '@/components/domain/VerdictCounts';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { Button, Field, NotAvailable, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, Loading } from '@/components/ui/States';
import { useToast } from '@/hooks/useToast';
import { ApiError } from '@/services/api';
import { deviceLabel, formatTimestamp, platformLabel, shortId } from '@/utils/format';

import { FindingsPanel } from './Findings';
import { RemediationTab } from './Remediation';
import { ReportPanel } from './Report';
import { ReviewPanel } from './Review';
import { useDeviceWorkspace } from './useDeviceWorkspace';

type TabId = 'overview' | 'findings' | 'review' | 'remediation' | 'report';

export function DeviceWorkspace({ deviceId }: { deviceId: string }) {
  const workspace = useDeviceWorkspace(deviceId);
  const { push } = useToast();
  const [tab, setTab] = useState<TabId>('overview');

  const {
    device,
    latest,
    runs,
    findings,
    undecided,
    reviewRestricted,
    actionableSteps,
    blockers,
    gateLoading,
  } = workspace;

  /**
   * Run the audit, and report what actually happened.
   *
   * A 409 is not a failure. The backend answers it when the file's platform was
   * never identified, and the sentence it returns ends "This is UNKNOWN, not a
   * failure" — announcing that under a red "Audit failed" heading contradicts
   * the text directly beneath it, and teaches the operator that abstention is a
   * kind of breakage. Rule 3 is defeated at the presentation layer if UNKNOWN
   * ever looks like FAIL, so the refusal gets the neutral treatment its own
   * message asks for.
   */
  async function onAudit() {
    const result = await workspace.audit.run(deviceId);
    if (result) {
      // An access list recognised and then dropped is not the same as a device
      // with no access lists, and both look like silence. If the backend names
      // one, the operator hears about it here rather than discovering an empty
      // ACL panel and drawing the wrong conclusion.
      const notAnalysed = result.acl_analysis?.not_analysed ?? [];
      if (notAnalysed.length > 0) {
        push(
          'info',
          `Audit complete · ${notAnalysed.length} access list${
            notAnalysed.length === 1 ? '' : 's'
          } not analysed`,
          [
            `${result.rules_evaluated} rules evaluated.`,
            ...notAnalysed.map((f) => f.summary),
          ].join('\n'),
        );
      } else {
        push('success', 'Audit complete', `${result.rules_evaluated} rules evaluated.`);
      }
      workspace.reloadAll();
      return;
    }
    if (!workspace.audit.error) return;

    const refused = workspace.audit.cause instanceof ApiError && workspace.audit.cause.isRefusal;
    if (refused) {
      push('info', 'Nothing to audit', workspace.audit.error);
    } else {
      push('error', 'Audit failed', workspace.audit.error);
    }
  }

  if (device.loading) return <Loading label="Loading device" />;
  if (device.error) return <ErrorState message={device.error} onRetry={device.reload} />;
  if (!device.data) {
    return <EmptyState title="Device not found" detail="It may belong to another user." />;
  }

  const d = device.data;

  const tabs: { id: TabId; label: string; count?: number; locked?: boolean }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: 'Findings', count: findings.data?.count },
    {
      id: 'review',
      label: 'Needs review',
      count: reviewRestricted ? undefined : undecided.length,
    },
    { id: 'remediation', label: 'Remediation', count: actionableSteps.length },
    // Closed while the gate is still being computed, for the same reason the
    // panel is: an unlocked tab that locks a moment later is a false promise.
    { id: 'report', label: 'Report', locked: gateLoading || blockers.length > 0 },
  ];

  return (
    <div className="card">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3.5">
        <div className="min-w-0">
          <h2 className="text-xl font-semibold tracking-tight text-ink">{deviceLabel(d)}</h2>
          <p className="text-muted">
            {platformLabel(d.vendor, d.os_family)}
            {latest && <> · last audited {formatTimestamp(latest.evaluated_at)}</>}
          </p>
        </div>
        <Button variant="primary" onClick={onAudit} disabled={workspace.audit.pending}>
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          {workspace.audit.pending ? 'Auditing…' : latest ? 'Re-run audit' : 'Run audit'}
        </Button>
      </div>

      <div className="border-b border-border" role="tablist">
        <div className="flex gap-1 overflow-x-auto px-2">
          {tabs.map((item) => {
            const selected = item.id === tab;
            return (
              <button
                key={item.id}
                role="tab"
                type="button"
                aria-selected={selected}
                onClick={() => setTab(item.id)}
                className={`-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2.5
                  transition-colors
                  ${
                    selected
                      ? 'border-accent font-medium text-ink'
                      : 'border-transparent text-muted hover:text-ink'
                  }`}
              >
                {item.label}
                {item.count !== undefined && <span className="num text-muted">{item.count}</span>}
                {item.locked && <Lock className="h-3.5 w-3.5 text-muted" aria-label="Blocked" />}
              </button>
            );
          })}
        </div>
      </div>

      {tab === 'overview' && (
        <div className="p-4">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Hostname">
              {d.hostname ?? <NotAvailable reason="no identity pattern matched" />}
            </Field>
            <Field label="Vendor">{d.vendor ?? <NotAvailable />}</Field>
            <Field label="OS family">{d.os_family ?? <NotAvailable />}</Field>
            <Field label="OS version" mono>
              {d.os_version ?? <NotAvailable reason="not read from the configuration" />}
            </Field>
            <Field label="Model" mono>
              {d.model ?? <NotAvailable reason="not read from the configuration" />}
            </Field>
            <Field label="Configuration file" mono>
              <span title={d.device_id}>{shortId(d.device_id, 20)}</span>
            </Field>
          </div>

          {latest && (
            <div className="mt-5 border-t border-border pt-4">
              <p className="label mb-2">Latest run</p>
              <VerdictCounts counts={latest.verdicts} />
              <p className="mt-2 text-muted">
                <span className="num">{latest.rules_evaluated}</span> rules · rulepack{' '}
                <span className="mono">
                  {latest.rulepack_id} {latest.rulepack_version}
                </span>
              </p>
            </div>
          )}

          {runs.length > 1 && (
            <div className="mt-5 border-t border-border pt-4">
              <p className="label mb-2">Previous runs</p>
              <Table caption="Previous audit runs">
                <thead>
                  <tr>
                    <Th>Evaluated</Th>
                    <Th>Rulepack</Th>
                    <Th>Verdicts</Th>
                  </tr>
                </thead>
                <tbody>
                  {runs.slice(1, 6).map((run) => (
                    <tr key={run.audit_id}>
                      <Td className="text-muted">{formatTimestamp(run.evaluated_at)}</Td>
                      <Td className="mono text-muted">
                        {run.rulepack_id} {run.rulepack_version}
                      </Td>
                      <Td>
                        <VerdictCounts counts={run.verdicts} size="sm" />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
        </div>
      )}

      {tab === 'findings' && (
        <ErrorBoundary label="Findings">
          <FindingsPanel workspace={workspace} />
        </ErrorBoundary>
      )}
      {tab === 'review' && (
        <ErrorBoundary label="Needs review">
          <ReviewPanel workspace={workspace} />
        </ErrorBoundary>
      )}
      {tab === 'remediation' && (
        <ErrorBoundary label="Remediation">
          <RemediationTab workspace={workspace} />
        </ErrorBoundary>
      )}
      {tab === 'report' && (
        <ErrorBoundary label="The report">
          <ReportPanel workspace={workspace} />
        </ErrorBoundary>
      )}
    </div>
  );
}
