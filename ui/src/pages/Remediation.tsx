/**
 * The fix queue across every device.
 *
 * Rule 4: every command shown came from the vetted snippet library. A device
 * with failures and no vetted command says so — omitting it would understate
 * the work by exactly the amount nobody has vetted yet.
 */
import { ChevronDown, ChevronRight } from 'lucide-react';
import { Fragment, useMemo, useState } from 'react';

import { RemediationTab } from '@/components/device/Remediation';
import { useDeviceWorkspace } from '@/components/device/useDeviceWorkspace';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { PageHeader } from '@/components/ui/Page';
import { Card, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import type { AuditRun, Device } from '@/types/api';
import { deviceLabel, formatTimestamp } from '@/utils/format';

/** Mounted only while a row is open, so one device is fetched at a time. */
function DeviceRemediation({ deviceId }: { deviceId: string }) {
  const workspace = useDeviceWorkspace(deviceId);
  return <RemediationTab workspace={workspace} />;
}

export function RemediationPage() {
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
      .map((device: Device) => ({ device, run: latest.get(device.device_id) ?? null }))
      .filter((row) => row.run !== null && (row.run.verdicts.fail ?? 0) > 0);
  }, [devices.data, audits.data]);

  const loading = devices.loading || audits.loading;

  return (
    <>
      <PageHeader title="Remediation" subtitle="Devices with failing checks" />

      <Card>
        {loading && <SkeletonRows rows={5} cols={3} />}
        {audits.error && !loading && <ErrorState message={audits.error} onRetry={audits.reload} />}
        {!loading && !audits.error && rows.length === 0 && (
          <EmptyState title="Nothing failing" detail="No audited device has a failing check." />
        )}

        {rows.length > 0 && (
          <Table caption="Devices with failing checks">
            <thead>
              <tr>
                <Th style={{ width: 36 }}>
                  <span className="sr-only">Expand</span>
                </Th>
                <Th>Device</Th>
                <Th style={{ width: 120 }}>Failing</Th>
                <Th style={{ width: 200 }}>Evaluated</Th>
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
                      <Td className="num font-semibold text-fail">{run!.verdicts.fail ?? 0}</Td>
                      <Td className="whitespace-nowrap text-muted">{formatTimestamp(run!.evaluated_at)}</Td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td colSpan={4} className="border-b border-border bg-surface p-0">
                          <ErrorBoundary label="This remediation plan">
                            <DeviceRemediation deviceId={device.device_id} />
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
