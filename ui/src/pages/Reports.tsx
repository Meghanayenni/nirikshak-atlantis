/**
 * Reports.
 *
 * Each row carries the same gate the device workspace applies: a report is
 * available once the device has been audited, its unrecognised lines have been
 * decided, and its vetted commands have been looked at.
 */
import { ChevronDown, ChevronRight } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';

import { ReportPanel } from '@/components/device/Report';
import { useDeviceWorkspace } from '@/components/device/useDeviceWorkspace';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { PageHeader } from '@/components/ui/Page';
import { Card, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import type { AuditRun } from '@/types/api';
import { deviceLabel, formatTimestamp } from '@/utils/format';

function DeviceReport({ deviceId }: { deviceId: string }) {
  const workspace = useDeviceWorkspace(deviceId);
  return <ReportPanel workspace={workspace} />;
}

export function ReportsPage() {
  const devices = useApi(() => listDevices(), []);
  const audits = useApi(() => listAudits(200), []);
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const latest = new Map<string, AuditRun>();
    for (const run of audits.data ?? []) {
      const existing = latest.get(run.device_id);
      if (!existing || (run.evaluated_at ?? '') > (existing.evaluated_at ?? '')) {
        latest.set(run.device_id, run);
      }
    }
    return (devices.data ?? [])
      .map((device) => ({ device, run: latest.get(device.device_id) ?? null }))
      .filter((row) => row.run !== null);
  }, [devices.data, audits.data]);

  const loading = devices.loading || audits.loading;

  return (
    <>
      <PageHeader title="Reports" subtitle="One document per audited device" />

      <Card>
        {loading && <SkeletonRows rows={5} cols={3} />}
        {audits.error && !loading && <ErrorState message={audits.error} onRetry={audits.reload} />}
        {!loading && !audits.error && rows.length === 0 && (
          <EmptyState title="No audits yet" detail="A report needs an audited configuration." />
        )}

        {rows.length > 0 && (
          <Table caption="Reports by device">
            <thead>
              <tr>
                <Th style={{ width: 36 }}>
                  <span className="sr-only">Expand</span>
                </Th>
                <Th>Device</Th>
                <Th style={{ width: 200 }}>Evaluated</Th>
                <Th style={{ width: 220 }}>Rulepack</Th>
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
                      <Td className="whitespace-nowrap text-muted">{formatTimestamp(run!.evaluated_at)}</Td>
                      <Td className="mono text-muted">
                        {run!.rulepack_id} {run!.rulepack_version}
                      </Td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td colSpan={4} className="border-b border-border bg-surface p-0">
                          <ErrorBoundary label="This report">
                            <DeviceReport deviceId={device.device_id} />
                          </ErrorBoundary>
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
