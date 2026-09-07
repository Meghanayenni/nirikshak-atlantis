/**
 * Devices — ingest and parse, and the way into everything else.
 *
 * Two panes, one screen. Selecting a device swaps the right-hand pane and
 * nothing else: the list stays where it was, and the operator keeps their place
 * in it. The URL follows the selection so a refresh and the back button still
 * work, but no navigation redraws the page.
 */
import { Search, Upload } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { DeviceWorkspace } from '@/components/device/DeviceWorkspace';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { Button } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useToast } from '@/hooks/useToast';
import { listAudits } from '@/services/audits';
import { listDevices, upload } from '@/services/devices';
import type { AuditRun } from '@/types/api';
import { deviceLabel, formatTimestamp, platformLabel } from '@/utils/format';

function latestByDevice(audits: AuditRun[]): Map<string, AuditRun> {
  const latest = new Map<string, AuditRun>();
  for (const audit of audits) {
    const existing = latest.get(audit.device_id);
    if (!existing || (audit.evaluated_at ?? '') > (existing.evaluated_at ?? '')) {
      latest.set(audit.device_id, audit);
    }
  }
  return latest;
}

export function DevicesPage() {
  const { deviceId } = useParams();
  const navigate = useNavigate();
  const { push } = useToast();

  const devices = useApi(() => listDevices(), []);
  const audits = useApi(() => listAudits(200), []);
  const [query, setQuery] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const uploadFiles = useMutation(upload);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (devices.data ?? []).filter((device) => {
      if (!needle) return true;
      return [device.hostname, device.vendor, device.os_family, device.model, device.device_id]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [devices.data, query]);

  const latest = useMemo(() => latestByDevice(audits.data ?? []), [audits.data]);

  // Select the first device when none is chosen, so the workspace is never an
  // empty right-hand pane the operator has to activate.
  useEffect(() => {
    if (!deviceId && rows.length > 0) {
      navigate(`/devices/${rows[0].device_id}`, { replace: true });
    }
  }, [deviceId, rows, navigate]);

  async function onUpload(list: FileList | null) {
    if (!list || list.length === 0) return;
    const result = await uploadFiles.run(Array.from(list));
    if (result) {
      push(
        result.rejected.length > 0 ? 'info' : 'success',
        `${result.accepted.length} configuration(s) accepted`,
        result.rejected.length > 0 ? `${result.rejected.length} rejected.` : undefined,
      );
      devices.reload();
    } else if (uploadFiles.error) {
      push('error', 'Upload failed', uploadFiles.error);
    }
    if (fileInput.current) fileInput.current.value = '';
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[19rem_minmax(0,1fr)]">
      <div className="card flex max-h-[calc(100vh-7.5rem)] flex-col lg:sticky lg:top-[4.5rem]">
        <div className="border-b border-border p-3">
          <input
            ref={fileInput}
            type="file"
            multiple
            className="sr-only"
            aria-label="Configuration files"
            onChange={(event) => onUpload(event.target.files)}
          />
          <Button
            variant="primary"
            className="w-full"
            onClick={() => fileInput.current?.click()}
            disabled={uploadFiles.pending}
          >
            <Upload className="h-4 w-4" aria-hidden="true" />
            {uploadFiles.pending ? 'Uploading…' : 'Upload configuration'}
          </Button>

          <div className="relative mt-3">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted"
              aria-hidden="true"
            />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search devices"
              aria-label="Search devices"
              className="h-9 w-full rounded border border-border bg-paper pl-8 pr-2"
            />
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {devices.loading && <SkeletonRows rows={6} cols={1} />}
          {devices.error && !devices.loading && (
            <ErrorState message={devices.error} onRetry={devices.reload} />
          )}
          {!devices.loading && !devices.error && rows.length === 0 && (
            <EmptyState
              title={query ? 'No match' : 'No configurations yet'}
              detail={query ? undefined : 'Upload a configuration file to begin.'}
            />
          )}

          <ul className="divide-y divide-border">
            {rows.map((device) => {
              const run = latest.get(device.device_id);
              const selected = device.device_id === deviceId;
              return (
                <li key={device.device_id}>
                  <button
                    type="button"
                    onClick={() => navigate(`/devices/${device.device_id}`)}
                    aria-current={selected ? 'true' : undefined}
                    className={`w-full border-l-2 px-3 py-2.5 text-left transition-colors
                      ${
                        selected
                          ? 'border-accent bg-accent-bg'
                          : 'border-transparent hover:bg-surface'
                      }`}
                  >
                    <p className="truncate font-medium text-ink">{deviceLabel(device)}</p>
                    <p className="truncate text-micro text-muted">
                      {platformLabel(device.vendor, device.os_family)}
                    </p>
                    <p className="mt-1 text-micro text-muted">
                      {run ? (
                        <>
                          <span className="num font-medium text-fail">
                            {run.verdicts.fail ?? 0}
                          </span>{' '}
                          fail ·{' '}
                          <span className="num">{run.verdicts.unknown ?? 0}</span> unknown ·{' '}
                          {formatTimestamp(run.evaluated_at)}
                        </>
                      ) : (
                        'Never audited'
                      )}
                    </p>
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      <div className="min-w-0">
        {deviceId ? (
          <ErrorBoundary key={deviceId} label="This device">
            <DeviceWorkspace deviceId={deviceId} />
          </ErrorBoundary>
        ) : (
          <div className="card">
            <EmptyState
              title="Select a device"
              detail="Choose a configuration to see what was read, what failed and what to do about it."
            />
          </div>
        )}
      </div>
    </div>
  );
}
