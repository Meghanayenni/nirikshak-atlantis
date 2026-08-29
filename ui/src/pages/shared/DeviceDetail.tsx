/**
 * Device — what is wrong with this one.
 *
 * §4 of the visual reference, and the second level of zoom. The device identity
 * shown here is the one ingestion detected (DEF-15, fixed at P12): hostname,
 * model and OS version are read from the configuration and cited, rather than
 * the interface falling back to a content hash.
 *
 * The `config_file_id` is shown for what it is, and labelled. It changes when
 * the file is edited (DEF-3, open), so it is never presented as a stable device
 * identity — a point the HTML report makes in prose for the same reason.
 */
import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { PrioritisationPanel, VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { SeverityLabel, VerdictChip } from '@/components/domain/Verdict';
import { PageHeader } from '@/components/ui/Page';
import { Button, Card, Field, NotAvailable, Table, Tabs, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, Loading, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useToast } from '@/hooks/useToast';
import { getFindings, listAudits, runAudit } from '@/services/audits';
import { getDevice } from '@/services/devices';
import { deviceLabel, formatTimestamp, platformLabel, ruleLabel, shortId } from '@/utils/format';

export function DeviceDetailPage() {
  const { deviceId = '' } = useParams();
  const { push } = useToast();
  const [tab, setTab] = useState('overview');

  const device = useApi(() => getDevice(deviceId), [deviceId]);
  const audits = useApi(() => listAudits(200), [deviceId]);

  const deviceAudits = useMemo(
    () =>
      (audits.data ?? [])
        .filter((a) => a.device_id === deviceId)
        .sort((a, b) => (b.evaluated_at ?? '').localeCompare(a.evaluated_at ?? '')),
    [audits.data, deviceId],
  );

  const latest = deviceAudits[0] ?? null;
  const findings = useApi(
    () => (latest ? getFindings(latest.audit_id) : Promise.resolve(null)),
    [latest?.audit_id],
  );

  const audit = useMutation(runAudit);

  async function onAudit() {
    const result = await audit.run(deviceId);
    if (result) {
      push('success', 'Audit complete', `${result.rules_evaluated} rules evaluated.`);
      audits.reload();
      findings.reload();
    } else if (audit.error) {
      push('error', 'Audit failed', audit.error);
    }
  }

  if (device.loading) return <Loading label="Loading device" />;
  if (device.error) return <ErrorState message={device.error} onRetry={device.reload} />;
  if (!device.data) {
    return (
      <EmptyState
        title="Device not found"
        detail="This configuration does not exist, or it was uploaded by another user."
      />
    );
  }

  const d = device.data;

  return (
    <>
      <PageHeader
        breadcrumb={[{ label: 'Fleet', to: '/devices' }, { label: deviceLabel(d) }]}
        title={deviceLabel(d)}
        subtitle={platformLabel(d.vendor, d.os_family)}
        actions={
          <Button variant="primary" onClick={onAudit} disabled={audit.pending}>
            {audit.pending ? 'Auditing…' : 'Run audit'}
          </Button>
        }
      />

      <Card className="mb-4">
        <Tabs
          tabs={[
            { id: 'overview', label: 'Overview' },
            { id: 'findings', label: 'Findings', count: findings.data?.count },
            { id: 'history', label: 'Audit history', count: deviceAudits.length },
            { id: 'exposure', label: 'Exposure' },
          ]}
          active={tab}
          onChange={setTab}
        />

        {tab === 'overview' && (
          <div className="p-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
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
            <Field label="Configuration file id" mono>
              <span title={d.device_id}>{shortId(d.device_id, 20)}</span>
            </Field>
            <div className="sm:col-span-2 lg:col-span-3 text-2xs text-muted leading-relaxed">
              The configuration file id is the SHA-256 of the uploaded file&rsquo;s contents. It
              changes whenever the file is edited, so it identifies <em>this configuration</em>{' '}
              rather than the physical device over time.
            </div>
          </div>
        )}

        {tab === 'findings' && (
          <>
            {!latest && (
              <EmptyState
                title="No audit yet"
                detail="Run an audit to evaluate this configuration against the rulepack."
              />
            )}
            {latest && findings.loading && <SkeletonRows rows={5} cols={4} />}
            {latest && findings.error && (
              <ErrorState message={findings.error} onRetry={findings.reload} />
            )}
            {latest && findings.data && (
              <Table caption="Findings from the most recent audit">
                <thead>
                  <tr>
                    <Th style={{ width: 104 }}>Verdict</Th>
                    <Th>Control</Th>
                    <Th style={{ width: 120 }}>Severity</Th>
                    <Th style={{ width: 200 }}>Evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data.findings.map((f) => (
                    <tr key={f.finding_id}>
                      <Td>
                        <VerdictChip verdict={f.status} />
                      </Td>
                      <Td>
                        <Link
                          to={`/audits/${latest.audit_id}/findings/${encodeURIComponent(f.finding_id)}`}
                          className="link font-medium"
                        >
                          {ruleLabel(f.rule_id)}
                        </Link>
                        <div className="mono text-muted text-[12px]">{f.rule_id}</div>
                      </Td>
                      <Td>
                        <SeverityLabel severity={f.severity} />
                      </Td>
                      <Td className="mono text-[12px] text-muted">
                        {f.evidence[0]?.raw_line ?? <NotAvailable reason="no line cited" />}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}

        {tab === 'history' && (
          <>
            {deviceAudits.length === 0 ? (
              <EmptyState title="No audits" detail="This configuration has not been audited." />
            ) : (
              <Table caption="Audit history">
                <thead>
                  <tr>
                    <Th>Run</Th>
                    <Th>Evaluated</Th>
                    <Th>Rulepack</Th>
                    <Th>Verdicts</Th>
                  </tr>
                </thead>
                <tbody>
                  {deviceAudits.map((a) => (
                    <tr key={a.audit_id}>
                      <Td>
                        <Link to={`/audits/${a.audit_id}`} className="link mono">
                          {shortId(a.audit_id, 16)}
                        </Link>
                      </Td>
                      <Td className="text-muted">{formatTimestamp(a.evaluated_at)}</Td>
                      <Td className="mono text-muted">
                        {a.rulepack_id} {a.rulepack_version}
                      </Td>
                      <Td>
                        <VerdictCounts counts={a.verdicts} size="sm" />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}

        {tab === 'exposure' && (
          <div className="p-4">
            {!latest ? (
              <EmptyState title="No audit yet" detail="Run an audit to assess exposure." />
            ) : (
              <BlockedState
                title="Exposure could not be determined for this device"
                reason={
                  'Exposure needs interfaces to say where a control lives and access lists to say ' +
                  'who can reach it. No vendor pack extracts either yet, so every finding on this ' +
                  'device is undetermined. Run an audit to see the per-run breakdown.'
                }
                unblockedBy="An ACL-bearing configuration and interface parsing patterns."
              />
            )}
          </div>
        )}
      </Card>
    </>
  );
}

/** Re-exported so the audit page can show the same panel. */
export { PrioritisationPanel };
