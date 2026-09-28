/**
 * How far one device complies with each sourced framework (ADR 0068).
 *
 * Every state, count and percentage here is the backend's. The interface maps
 * a gate state to a link and draws what it is given; it computes no verdict, no
 * score and no gate.
 *
 * Two rules this component holds structurally:
 *
 *   **A gated device shows no number.** Not a fraction, not a count of
 *   controls, not a bar — the API sends none, and nothing here could draw one.
 *   The only figure in a gated state is review progress.
 *
 *   **The headline never stands alone, and is never a percentage.** It is
 *   "N of M assessed controls fully satisfied". `Headline` takes the counts and
 *   the coverage together, so it cannot render without the other three counts,
 *   the legend and the coverage line. "No violation found" is the pass colour at
 *   lower weight — outlined, never a new hue — because a partial check that
 *   passed is not a satisfied control. Undetermined is dashed slate, never
 *   amber: abstention is off the severity axis (DEVELOPER_GUIDE.md §10). There
 *   is no severity on this panel.
 */
import { Link } from 'react-router-dom';

import { RemediationPanel } from '@/components/domain/RemediationPanel';
import { ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { getDevicePosture } from '@/services/audits';
import type { DevicePosture, FrameworkPosture, PostureControl } from '@/types/api';
import { humanise, ruleLabel } from '@/utils/format';

function GateLink({ posture, deviceId }: { posture: DevicePosture; deviceId: string }) {
  const { isAdmin } = useAuth();
  const { state } = posture.gate;
  const cls = 'text-accent underline';

  if (state === 'not_audited') {
    if (!posture.platform.vendor) {
      return isAdmin ? (
        <Link to={`/bootstrap/${deviceId}`} className={cls}>
          Describe this platform on the bootstrap page
        </Link>
      ) : null;
    }
    return (
      <Link to={`/devices/${deviceId}`} className={cls}>
        Open the device to run an audit
      </Link>
    );
  }
  if (state === 'review_pending') {
    return isAdmin ? (
      <Link to={`/devices/${deviceId}?tab=review`} className={cls}>
        Open Needs review
      </Link>
    ) : null;
  }
  if (state === 'rerun_required') {
    return (
      <Link to={`/devices/${deviceId}`} className={cls}>
        Open the device to re-run the audit
      </Link>
    );
  }
  return null;
}

function Gated({ posture, deviceId }: { posture: DevicePosture; deviceId: string }) {
  const { gate } = posture;
  return (
    <section
      aria-label="Compliance score withheld"
      className="rounded border border-dashed border-unknown-br bg-unknown-bg px-4 py-3"
    >
      <p className="font-medium text-ink">{gate.message}</p>
      {gate.state === 'review_pending' && gate.review && (
        <p className="mt-1 text-ink-2">
          <span className="num">{gate.review.reviewed}</span> of{' '}
          <span className="num">{gate.review.total}</span> lines reviewed
        </p>
      )}
      {gate.next_step && <p className="mt-1 text-ink-2">{gate.next_step}</p>}
      <p className="mt-1.5">
        <GateLink posture={posture} deviceId={deviceId} />
      </p>
    </section>
  );
}

type Counts = NonNullable<FrameworkPosture['counts']>;

/**
 * The four segments, in one place so the bar and its legend cannot disagree.
 * The same phrases appear in the report (ADR 0068).
 */
const SEGMENTS: { key: keyof Omit<Counts, 'assessed'>; className: string; legend: string }[] = [
  {
    key: 'satisfied',
    className: 'bg-pass',
    legend: 'Fully satisfied — a check testing the whole control passed',
  },
  {
    key: 'no_violation_found',
    className: 'border border-pass bg-pass-bg',
    legend: 'No violation found — checks passed, but each tests only part of the control',
  },
  { key: 'violated', className: 'bg-fail', legend: 'Violated — a mapped check failed' },
  {
    key: 'undetermined',
    className: 'border border-dashed border-unknown bg-unknown-bg',
    legend: 'Undetermined — a mapped check could not be answered',
  },
];

/** One stacked bar, drawn from counts with no arithmetic: each segment grows by its count. */
function PostureBar({ counts }: { counts: Counts }) {
  return (
    <div
      role="img"
      aria-label={`${counts.satisfied} fully satisfied, ${counts.no_violation_found} no violation found, ${counts.violated} violated, ${counts.undetermined} undetermined`}
      className="flex h-2.5 gap-0.5"
      data-testid="posture-bar"
    >
      {SEGMENTS.filter((seg) => counts[seg.key] > 0).map((seg) => (
        <span
          key={seg.key}
          data-segment={seg.key}
          className={`rounded-sm ${seg.className}`}
          style={{ flexGrow: counts[seg.key] }}
        />
      ))}
    </div>
  );
}

function Legend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted" aria-label="Legend">
      {SEGMENTS.map((seg) => (
        <li key={seg.key} className="flex items-center gap-1.5">
          <span className={`inline-block h-2 w-3 rounded-sm ${seg.className}`} aria-hidden="true" />
          {seg.legend}
        </li>
      ))}
    </ul>
  );
}

/** The fraction, the other counts, the legend and the coverage line — only ever together. */
function Headline({ framework }: { framework: FrameworkPosture }) {
  const counts = framework.counts!;
  const { coverage } = framework;
  return (
    <div className="space-y-1" data-testid="posture-headline">
      <PostureBar counts={counts} />
      <p className="text-ink">
        <span className="font-semibold">
          <span className="num">{counts.satisfied}</span> of{' '}
          <span className="num">{counts.assessed}</span> assessed controls fully satisfied
        </span>{' '}
        · <span className="num">{counts.no_violation_found}</span> no violation found (partial
        check) · <span className="num">{counts.violated}</span> violated ·{' '}
        <span className="num">{counts.undetermined}</span> undetermined
      </p>
      <Legend />
      <p className="text-muted" title={coverage.basis}>
        {coverage.catalog_total != null ? (
          <>
            <span className="num">{coverage.assessed}</span> of{' '}
            <span className="num">{coverage.catalog_total}</span> catalog controls assessed by
            NIRIKSHAK
          </>
        ) : (
          <>Catalog total not available — {coverage.basis}</>
        )}
      </p>
    </div>
  );
}

function Violated({ control, deviceId }: { control: PostureControl; deviceId: string }) {
  return (
    <li className="border-t border-border py-3">
      <p>
        <span className="mono font-semibold text-ink">{control.control_id}</span>
        <span className="ml-2 text-muted">edition {control.edition}</span>
      </p>
      {control.rules.map((rule) => (
        <div key={rule.rule_id} className="mt-2 space-y-2 pl-3">
          <p className="text-ink-2">
            <span className="font-medium text-ink">{ruleLabel(rule.rule_id)}</span>
            <span className="mono ml-2 text-muted">{rule.rule_id}</span>
          </p>
          {rule.evidence.length === 0 ? (
            <p className="text-muted">
              No line is cited — {rule.absence_reason ?? 'this verdict rests on an absence'}.
            </p>
          ) : (
            <ul className="space-y-1">
              {rule.evidence.map((e) => (
                <li key={e.cite} className="mono text-ink-2">
                  <Link
                    to={`/devices/${deviceId}?tab=findings&finding=${rule.finding_id ?? ''}`}
                    className="text-accent underline"
                  >
                    {e.file_path}:{e.line_start}
                  </Link>{' '}
                  {e.raw_line}
                </li>
              ))}
            </ul>
          )}
          {rule.remediation && <RemediationPanel remediation={rule.remediation} />}
        </div>
      ))}
    </li>
  );
}

function NoViolationFound({ control }: { control: PostureControl }) {
  return (
    <li className="border-t border-border py-2.5">
      <p>
        <span className="mono font-semibold text-ink">{control.control_id}</span>
        <span className="ml-2 text-muted">edition {control.edition}</span>
      </p>
      <p className="mt-0.5 pl-3 text-ink-2">
        partial check: NIRIKSHAK tests only part of this control
      </p>
      <ul className="mt-1 space-y-0.5 pl-3 text-ink-2">
        {control.rules.map((rule) => (
          <li key={rule.rule_id}>
            <span className="mono mr-2">{rule.rule_id}</span>
            {rule.coverage_reason}
          </li>
        ))}
      </ul>
    </li>
  );
}

function Undetermined({ control }: { control: PostureControl }) {
  return (
    <li className="border-t border-border py-2.5">
      <p>
        <span className="mono font-semibold text-ink">{control.control_id}</span>
        <span className="ml-2 text-muted">edition {control.edition}</span>
      </p>
      <ul className="mt-1 space-y-0.5 pl-3 text-ink-2">
        {control.rules.map((rule) => (
          <li key={rule.rule_id}>
            <span className="mono mr-2">{rule.rule_id}</span>
            {rule.verdict === 'unknown'
              ? `UNKNOWN — ${rule.unknown_reason ? humanise(rule.unknown_reason) : 'no reason recorded'}`
              : rule.verdict === 'not_applicable'
                ? 'Not applicable on this platform'
                : 'Not evaluated in this run'}
            {rule.absence_reason && <span className="text-muted"> · {rule.absence_reason}</span>}
          </li>
        ))}
      </ul>
    </li>
  );
}

function FrameworkBlock({ framework, deviceId }: { framework: FrameworkPosture; deviceId: string }) {
  return (
    <section
      aria-label={`${framework.document} posture`}
      className="rounded border border-border bg-paper px-4 py-3"
    >
      <p className="font-medium text-ink">
        {framework.document} <span className="text-muted">· edition {framework.edition}</span>
      </p>

      {framework.status !== 'assessed' ? (
        <p className="mt-1 text-muted">
          {framework.status === 'not_applicable' ? 'Not applicable' : 'Not in this run’s scope'}
          {' — '}
          {framework.reason}
        </p>
      ) : (
        <>
          <div className="mt-2">
            <Headline framework={framework} />
          </div>

          <details open className="mt-3">
            <summary className="label cursor-pointer">
              Did not comply <span className="num">{framework.violated?.length ?? 0}</span>
            </summary>
            {(framework.violated ?? []).length === 0 ? (
              <p className="mt-1 text-muted">No assessed control was violated.</p>
            ) : (
              <ul>
                {framework.violated!.map((control) => (
                  <Violated key={control.control_id} control={control} deviceId={deviceId} />
                ))}
              </ul>
            )}
          </details>

          {(framework.no_violation_found ?? []).length > 0 && (
            <details className="mt-2">
              <summary className="label cursor-pointer">
                No violation found{' '}
                <span className="num">{framework.no_violation_found!.length}</span>
              </summary>
              <ul>
                {framework.no_violation_found!.map((control) => (
                  <NoViolationFound key={control.control_id} control={control} />
                ))}
              </ul>
            </details>
          )}

          {(framework.undetermined ?? []).length > 0 && (
            <details className="mt-2">
              <summary className="label cursor-pointer">
                Could not be determined{' '}
                <span className="num">{framework.undetermined!.length}</span>
              </summary>
              <ul>
                {framework.undetermined!.map((control) => (
                  <Undetermined key={control.control_id} control={control} />
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  );
}

export function PostureView({ data, deviceId }: { data: DevicePosture; deviceId: string }) {
  if (data.gate.state !== 'ready' || !data.posture) {
    return <Gated posture={data} deviceId={deviceId} />;
  }
  const { posture } = data;
  if (!posture.mappings_attached) {
    return (
      <section
        aria-label="Compliance score withheld"
        className="rounded border border-dashed border-unknown-br bg-unknown-bg px-4 py-3"
      >
        <p className="font-medium text-ink">Control mappings are withheld for this run.</p>
        <p className="mt-1 text-ink-2">{posture.withheld_reason}</p>
        <p className="mt-1.5">
          <Link to={`/devices/${deviceId}`} className="text-accent underline">
            Open the device to re-run the audit
          </Link>
        </p>
      </section>
    );
  }
  return (
    <div className="space-y-3">
      {posture.frameworks.map((framework) => (
        <FrameworkBlock key={framework.framework} framework={framework} deviceId={deviceId} />
      ))}
      {Object.entries(posture.unsourced).map(([name, why]) => (
        <p key={name} className="text-xs text-muted">
          <span className="uppercase">{name}</span> — {why}.
        </p>
      ))}
      <p className="text-xs text-muted">{posture.note}</p>
    </div>
  );
}

export function CompliancePosture({ deviceId }: { deviceId: string }) {
  const posture = useApi(() => getDevicePosture(deviceId), [deviceId]);
  if (posture.loading) return <SkeletonRows rows={3} cols={2} />;
  if (posture.error) return <ErrorState message={posture.error} onRetry={posture.reload} />;
  if (!posture.data) return null;
  return <PostureView data={posture.data} deviceId={deviceId} />;
}
