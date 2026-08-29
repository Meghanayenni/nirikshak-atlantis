/**
 * Fleet — which devices need attention.
 *
 * The second level of zoom (§10), and a direct translation of §3 of the visual
 * reference. Where the reference draws a compliance percentage and a "CAT I"
 * severity, this shows verdict counts and NIRIKSHAK's own severity names,
 * because those are what the backend produces. The reference's numbers are
 * illustrative; its structure is the specification.
 *
 * A user sees only devices they uploaded; an administrator sees the fleet. That
 * scoping is the backend's, applied to `/ingest/devices`.
 *
 * There are no quarantine, disable or remove actions. The API exposes no device
 * lifecycle endpoint, and a button that pretended to change a device's state
 * would be the worst kind of interface: one that reports an outcome that never
 * happened.
 */
import { Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { PageHeader } from '@/components/ui/Page';
import { Card, NotAvailable, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import type { AuditRun, Device } from '@/types/api';
import { deviceLabel, formatTimestamp, isHostnameKnown, platformLabel } from '@/utils/format';

/** The most recent audit per device, from the runs the caller can see. */
function latestByDevice(audits: AuditRun[]): Map<string, AuditRun> {
  const latest = new Map<string, AuditRun>();
  for (const audit of audits) {
    const existing = latest.get(audit.device_id);
    if (!existing) {
      latest.set(audit.device_id, audit);
      continue;
    }
    const a = existing.evaluated_at ?? '';
    const b = audit.evaluated_at ?? '';
    if (b > a) latest.set(audit.device_id, audit);
  }
  return latest;
}

export function DevicesPage() {
  const { isAdmin } = useAuth();
  const devices = useApi(() => listDevices(), []);
  const audits = useApi(() => listAudits(200), []);

  const [query, setQuery] = useState('');
  const [vendor, setVendor] = useState('');

  const vendors = useMemo(
    () => Array.from(new Set((devices.data ?? []).map((d) => d.vendor).filter(Boolean))) as string[],
    [devices.data],
  );

  const rows = useMemo(() => {
    const latest = latestByDevice(audits.data ?? []);
    const needle = query.trim().toLowerCase();
    return (devices.data ?? [])
      .filter((d) => (vendor ? d.vendor === vendor : true))
      .filter((d) => {
        if (!needle) return true;
        return [d.hostname, d.vendor, d.os_family, d.os_version, d.model, d.device_id]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(needle));
      })
      .map((device: Device) => ({ device, audit: latest.get(device.device_id) ?? null }))
      .sort((a, b) => {
        // Devices with failures first, then by name. Not an exposure ranking —
        // it is a table sorted by a column, and it says so.
        const failA = a.audit?.verdicts.fail ?? 0;
        const failB = b.audit?.verdicts.fail ?? 0;
        if (failA !== failB) return failB - failA;
        return deviceLabel(a.device).localeCompare(deviceLabel(b.device));
      });
  }, [devices.data, audits.data, query, vendor]);

  const loading = devices.loading || audits.loading;
  const error = devices.error ?? audits.error;

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Fleet' : 'My devices'}
        subtitle={
          isAdmin
            ? 'Every ingested configuration and its most recent audit'
            : 'Configurations you uploaded'
        }
      />

      <Card>
        <div className="p-3 border-b border-border flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search
              className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted"
              aria-hidden="true"
            />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search hostname, vendor, model…"
              aria-label="Search devices"
              className="w-full h-8 pl-8 pr-3 rounded border border-border bg-paper text-[13px]"
            />
          </div>
          <select
            value={vendor}
            onChange={(e) => setVendor(e.target.value)}
            aria-label="Filter by vendor"
            className="h-8 px-2 rounded border border-border bg-paper text-[13px] text-ink"
          >
            <option value="">All vendors</option>
            {vendors.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </div>

        {loading && <SkeletonRows rows={6} cols={5} />}
        {error && !loading && <ErrorState message={error} onRetry={devices.reload} />}

        {!loading && !error && rows.length === 0 && (
          <EmptyState
            title="No devices"
            detail={
              devices.data?.length === 0
                ? 'Upload a configuration from the Audits page to get started.'
                : 'No device matches the current filters.'
            }
          />
        )}

        {!loading && !error && rows.length > 0 && (
          <Table caption="Devices and their most recent audit">
            <thead>
              <tr>
                <Th>Device</Th>
                <Th>Vendor / OS</Th>
                <Th>Version</Th>
                <Th>Last audit</Th>
                <Th>Verdicts</Th>
                <Th>Unrecognised</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ device, audit }) => (
                <tr key={device.device_id}>
                  <Td>
                    <Link to={`/devices/${device.device_id}`} className="link font-medium">
                      {deviceLabel(device)}
                    </Link>
                    {!isHostnameKnown(device) && (
                      <span
                        className="ml-2 text-2xs text-muted"
                        title="No hostname was read from this configuration; this is a file identifier"
                      >
                        no hostname
                      </span>
                    )}
                  </Td>
                  <Td>{platformLabel(device.vendor, device.os_family)}</Td>
                  <Td className="mono">
                    {device.os_version ?? <NotAvailable reason="not read from the configuration" />}
                  </Td>
                  <Td className="text-muted">
                    {audit ? (
                      <Link to={`/audits/${audit.audit_id}`} className="link">
                        {formatTimestamp(audit.evaluated_at)}
                      </Link>
                    ) : (
                      <span className="text-muted">Never audited</span>
                    )}
                  </Td>
                  <Td>
                    {audit ? (
                      <VerdictCounts counts={audit.verdicts} size="sm" />
                    ) : (
                      <NotAvailable reason="no audit has been run" />
                    )}
                  </Td>
                  <Td className="num text-muted">—</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
