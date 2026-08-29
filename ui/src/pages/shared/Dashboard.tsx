/**
 * The dashboard.
 *
 * Composition, not computation. Every number here is either returned by the
 * backend or a count of rows the backend returned; nothing is derived into a
 * score, a percentage or a health grade.
 *
 * §10: "No chart that a sentence or a sorted table would carry better. No
 * decorative visualisation of pass/fail ratios." So this is metric tiles and a
 * sorted table — which is also why there is no charting dependency in this
 * project (decision D3).
 *
 * Admins see the fleet; users see what they uploaded. The scoping is the
 * backend's, and the heading says which view is being shown.
 */
import { Link } from 'react-router-dom';

import { VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { listAudits } from '@/services/audits';
import { listDevices } from '@/services/devices';
import { getFleetBaseline } from '@/services/fleet';
import { getHealth } from '@/services/health';
import { formatTimestamp, shortId } from '@/utils/format';

function MetricTile({
  label,
  value,
  note,
  to,
}: {
  label: string;
  value: string | number;
  note?: string;
  to?: string;
}) {
  const body = (
    <div className="card p-4 h-full">
      <p className="label">{label}</p>
      <p className="mt-1 text-[26px] leading-none num font-semibold text-ink">{value}</p>
      {note && <p className="mt-1.5 text-2xs text-muted leading-snug">{note}</p>}
    </div>
  );
  return to ? (
    <Link to={to} className="block hover:opacity-90 transition-opacity">
      {body}
    </Link>
  ) : (
    body
  );
}

export function DashboardPage() {
  const { isAdmin, session } = useAuth();
  const devices = useApi(() => listDevices(), []);
  const audits = useApi(() => listAudits(200), []);
  const health = useApi(() => getHealth(), []);
  // Admin-only; a user receives 403 and the tile simply is not shown.
  const fleet = useApi(() => (isAdmin ? getFleetBaseline() : Promise.resolve(null)), [isAdmin]);

  const runs = audits.data ?? [];
  const totals = runs.reduce(
    (acc, run) => {
      acc.fail += run.verdicts.fail ?? 0;
      acc.unknown += run.verdicts.unknown ?? 0;
      acc.pass += run.verdicts.pass ?? 0;
      acc.not_applicable += run.verdicts.not_applicable ?? 0;
      return acc;
    },
    { fail: 0, unknown: 0, pass: 0, not_applicable: 0 } as Record<string, number>,
  );

  const auditedDevices = new Set(runs.map((r) => r.device_id)).size;
  const deviceCount = devices.data?.length ?? 0;
  const loading = devices.loading || audits.loading;

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Security command centre' : 'My security dashboard'}
        subtitle={
          isAdmin
            ? 'Fleet-wide visibility across every ingested configuration'
            : `Signed in as ${session?.username} — showing only what you uploaded`
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
        <MetricTile
          label={isAdmin ? 'Devices' : 'My devices'}
          value={loading ? '—' : deviceCount}
          note="One configuration file each"
          to="/devices"
        />
        <MetricTile
          label="Audited"
          value={loading ? '—' : auditedDevices}
          note={
            deviceCount > auditedDevices
              ? `${deviceCount - auditedDevices} never audited`
              : 'Every device has a run'
          }
          to="/audits"
        />
        <MetricTile
          label="Failing checks"
          value={loading ? '—' : totals.fail}
          note="Across the most recent runs"
        />
        <MetricTile
          label="Abstentions"
          value={loading ? '—' : totals.unknown}
          note="Checks the engine declined to decide"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Recent audit activity"
            subtitle="Most recent runs, newest first"
            actions={
              <Link to="/audits" className="link text-[13px]">
                All audits
              </Link>
            }
          />
          {loading && <SkeletonRows rows={5} cols={3} />}
          {audits.error && !loading && (
            <ErrorState message={audits.error} onRetry={audits.reload} />
          )}
          {!loading && !audits.error && runs.length === 0 && (
            <EmptyState
              title="No audits yet"
              detail="Upload a configuration and run an audit to populate this view."
            />
          )}
          {!loading && !audits.error && runs.length > 0 && (
            <Table caption="Recent audit runs">
              <thead>
                <tr>
                  <Th>Run</Th>
                  <Th>Evaluated</Th>
                  <Th>Verdicts</Th>
                </tr>
              </thead>
              <tbody>
                {[...runs]
                  .sort((a, b) => (b.evaluated_at ?? '').localeCompare(a.evaluated_at ?? ''))
                  .slice(0, 8)
                  .map((run) => (
                    <tr key={run.audit_id}>
                      <Td>
                        <Link to={`/audits/${run.audit_id}`} className="link mono">
                          {shortId(run.audit_id, 14)}
                        </Link>
                      </Td>
                      <Td className="text-muted">{formatTimestamp(run.evaluated_at)}</Td>
                      <Td>
                        <VerdictCounts counts={run.verdicts} size="sm" />
                      </Td>
                    </tr>
                  ))}
              </tbody>
            </Table>
          )}
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Verdict totals" />
            <div className="p-4">
              <VerdictCounts counts={totals} />
              <p className="mt-3 text-2xs text-muted leading-relaxed">
                Reported as counts. No compliance percentage is shown: an abstention is neither a
                pass nor a failure, and any single ratio would have to hide one of the three.
              </p>
            </div>
          </Card>

          {isAdmin && (
            <Card>
              <CardHeader title="Peer baselines" />
              <div className="p-4">
                {fleet.loading && <p className="text-[13px] text-muted">Loading…</p>}
                {fleet.error && <p className="text-[13px] text-muted">{fleet.error}</p>}
                {fleet.data && (
                  <>
                    <p className="text-[13px] text-ink-2 leading-relaxed">{fleet.data.summary}</p>
                    <Link to="/prioritisation" className="link text-[13px] mt-2 inline-block">
                      Open prioritisation →
                    </Link>
                  </>
                )}
              </div>
            </Card>
          )}

          <Card>
            <CardHeader title="Engine" />
            <div className="p-4 space-y-2 text-[13px]">
              {health.data ? (
                <>
                  <p className="text-ink-2">
                    <span className="label mr-2">Phase</span>
                    <span className="mono">{health.data.phase}</span>
                  </p>
                  <p className="text-ink-2">
                    <span className="label mr-2">Similarity model</span>
                    {health.data.similarity_model.available ? 'available' : 'unavailable'}
                  </p>
                  <p className="text-ink-2">
                    <span className="label mr-2">PDF reporting</span>
                    {health.data.pdf_reporting.available ? 'available' : 'unavailable'}
                  </p>
                  <Link to="/health" className="link inline-block mt-1">
                    System health →
                  </Link>
                </>
              ) : (
                <p className="text-muted">Loading…</p>
              )}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
