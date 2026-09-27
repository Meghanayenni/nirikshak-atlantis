/**
 * Peer baseline — one device against its cohort, chosen from a list.
 *
 * The page adds nothing to the baseline itself: it renders the same
 * `PeerBaseline` component, with the same endpoint and the same four states,
 * for whichever device is selected. What it adds is the choice of device.
 *
 * The list is the devices the API returns, narrowed to those with at least one
 * audit run in `/compliance/audits` — a join over rows the API returned, not a
 * computation. Admin-only: the endpoint behind the card answers 403 to anyone
 * else, so a non-admin is sent back to Devices rather than shown a page that
 * can only fail.
 */
import { useMemo, useState } from 'react';
import { Navigate } from 'react-router-dom';

import { PeerBaseline } from '@/components/device/PeerBaseline';
import { PageHeader } from '@/components/ui/Page';
import { Card } from '@/components/ui/Primitives';
import { ErrorState } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import { deviceLabel } from '@/utils/format';

export function PeerBaselinePage() {
  const { isAdmin } = useAuth();
  const devices = useApi(() => (isAdmin ? listDevices() : Promise.resolve(null)), [isAdmin]);
  const audits = useApi(() => (isAdmin ? listAudits(200) : Promise.resolve(null)), [isAdmin]);
  const [selectedId, setSelectedId] = useState('');

  const audited = useMemo(() => {
    const withRun = new Set((audits.data ?? []).map((run) => run.device_id));
    return (devices.data ?? []).filter((device) => withRun.has(device.device_id));
  }, [devices.data, audits.data]);

  if (!isAdmin) return <Navigate to="/devices" replace />;

  const selected = audited.find((device) => device.device_id === selectedId) ?? null;
  const loading = devices.loading || audits.loading;
  const error = devices.error ?? audits.error;

  return (
    <>
      <PageHeader
        title="Peer baseline"
        subtitle="Compare a device against others in its vendor cohort"
      />

      <Card>
        <div className="px-4 py-3">
          <label htmlFor="peer-baseline-device" className="label mb-1.5 block">
            Device
          </label>
          {loading && <p className="text-muted">Loading devices…</p>}
          {error && !loading && (
            <ErrorState
              message={error}
              onRetry={() => {
                devices.reload();
                audits.reload();
              }}
            />
          )}
          {!loading && !error && (
            <select
              id="peer-baseline-device"
              className="h-8 w-full max-w-md rounded border border-border bg-paper px-2 text-base text-ink"
              value={selectedId}
              onChange={(event) => setSelectedId(event.target.value)}
            >
              <option value="">
                {audited.length === 0 ? 'No audited device yet' : 'Choose a device…'}
              </option>
              {audited.map((device) => (
                <option key={device.device_id} value={device.device_id}>
                  {deviceLabel(device)} — {device.vendor ?? '?'}/{device.os_family ?? '?'}
                </option>
              ))}
            </select>
          )}

          {selected ? (
            <div className="mt-4">
              <p className="text-ink-2">
                Showing peer baseline for:{' '}
                <span className="font-medium text-ink">{deviceLabel(selected)}</span>{' '}
                <span className="mono">
                  ({selected.vendor ?? '?'}/{selected.os_family ?? '?'})
                </span>
              </p>
              <PeerBaseline key={selected.device_id} deviceId={selected.device_id} />
            </div>
          ) : (
            !loading &&
            !error && <p className="mt-4 text-muted">Select a device to view its peer baseline</p>
          )}
        </div>
      </Card>
    </>
  );
}
