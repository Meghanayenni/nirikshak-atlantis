/**
 * Compliance across every device the caller can see.
 *
 * Findings are scoped to an audit run at the backend, so this composes the runs
 * the caller already has rather than claiming a fleet-wide query that does not
 * exist. A row opens its findings underneath it; nothing navigates.
 */
import { ChevronDown, ChevronRight } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';

import { VerdictCounts } from '@/components/domain/VerdictCounts';
import { SeverityLabel, VerdictChip } from '@/components/domain/Verdict';
import { PageHeader } from '@/components/ui/Page';
import { Card, NotAvailable, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { getFindings, listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import { getFleetBaseline } from '@/services/fleet';
import type { AuditRun } from '@/types/api';
import { deviceLabel, formatTimestamp, ruleLabel } from '@/utils/format';

function RunFindings({ auditId }: { auditId: string }) {
  const findings = useApi(() => getFindings(auditId), [auditId]);

  if (findings.loading) return <SkeletonRows rows={4} cols={3} />;
  if (findings.error) return <ErrorState message={findings.error} onRetry={findings.reload} />;

  const rows = (findings.data?.findings ?? []).filter((finding) => finding.status !== 'pass');
  if (rows.length === 0) {
    return <p className="px-4 py-3 text-muted">Nothing failed or abstained in this run.</p>;
  }

  return (
    <Table caption="Findings needing attention">
      <thead>
        <tr>
          <Th style={{ width: 116 }}>Verdict</Th>
          <Th>Control</Th>
          <Th style={{ width: 130 }}>Severity</Th>
          <Th>Cited line</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((finding) => (
          <tr key={finding.finding_id}>
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
        ))}
      </tbody>
    </Table>
  );
}

export function CompliancePage() {
  const { isAdmin } = useAuth();
  const devices = useApi(() => listDevices(), []);
  const audits = useApi(() => listAudits(200), []);
  // Admin-only at the backend; a user simply does not see the card.
  const fleet = useApi(() => (isAdmin ? getFleetBaseline() : Promise.resolve(null)), [isAdmin]);
  const [open, setOpen] = useState<string | null>(null);

  const latest = useMemo(() => {
    const map = new Map<string, AuditRun>();
    for (const run of audits.data ?? []) {
      const existing = map.get(run.device_id);
      if (!existing || (run.evaluated_at ?? '') > (existing.evaluated_at ?? '')) {
        map.set(run.device_id, run);
      }
    }
    return map;
  }, [audits.data]);

  const rows = useMemo(
    () =>
      (devices.data ?? [])
        .map((device) => ({ device, run: latest.get(device.device_id) ?? null }))
        .filter((row) => row.run !== null),
    [devices.data, latest],
  );

  const loading = devices.loading || audits.loading;

  return (
    <>
      <PageHeader title="Compliance" subtitle="The most recent evaluation of every device" />

      {fleet.data && (
        <Card className="mb-4">
          <div className="flex flex-wrap items-baseline justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <p className="label">Peer baselines</p>
              <p className="mt-0.5 text-ink-2">{fleet.data.summary}</p>
            </div>
            <p className="text-muted">
              <span className="num">{fleet.data.outliers.length}</span> outlier(s)
            </p>
          </div>
        </Card>
      )}

      <Card>
        {loading && <SkeletonRows rows={6} cols={4} />}
        {audits.error && !loading && <ErrorState message={audits.error} onRetry={audits.reload} />}
        {!loading && !audits.error && rows.length === 0 && (
          <EmptyState
            title="No audits yet"
            detail="Run an audit on a device to populate this view."
          />
        )}

        {rows.length > 0 && (
          <Table caption="Compliance by device">
            <thead>
              <tr>
                <Th style={{ width: 36 }}>
                  <span className="sr-only">Expand</span>
                </Th>
                <Th>Device</Th>
                <Th style={{ width: 180 }}>Evaluated</Th>
                <Th style={{ width: 300 }}>Verdicts</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ device, run }) => {
                const expanded = open === device.device_id;
                return (
                  <Fragment key={device.device_id}>
                    <tr
                      className="row-button"
                      onClick={() => setOpen(expanded ? null : device.device_id)}
                    >
                      <Td>
                        <button
                          type="button"
                          aria-expanded={expanded}
                          aria-label={expanded ? 'Collapse' : 'Expand'}
                          className="text-muted"
                          onClick={(event) => {
                            event.stopPropagation();
                            setOpen(expanded ? null : device.device_id);
                          }}
                        >
                          {expanded ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </Td>
                      <Td className="font-medium text-ink">{deviceLabel(device)}</Td>
                      <Td className="text-muted">{formatTimestamp(run!.evaluated_at)}</Td>
                      <Td>
                        <VerdictCounts counts={run!.verdicts} size="sm" />
                      </Td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td colSpan={4} className="border-b border-border bg-surface p-0">
                          <RunFindings auditId={run!.audit_id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
