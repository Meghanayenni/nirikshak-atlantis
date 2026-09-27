/**
 * One device against its peer group — `/fleet/baseline/device/{id}`.
 *
 * The API decides everything shown here: which of the three states the answer
 * is in (`status`), which fields were compared, and which deviate. The card
 * decides nothing and computes nothing beyond counting rows it was given.
 *
 * Three things it must never do, each of which the design exists to prevent:
 *
 *   - Call a field that is UNKNOWN on this device "matching". An abstention is
 *     not agreement; it is drawn dashed slate and says UNKNOWN.
 *   - Present "no deviation" when nothing was compared. A cohort above the floor
 *     whose pack reads no field (JunOS, EOS) gets one muted line saying so.
 *   - Look like a verdict. A deviation is an observation about the fleet, not a
 *     compliance failure (`is_verdict: false`), so there is no green, no red and
 *     no amber: agreeing fields are neutral, deviating fields are heavier ink
 *     (DEVELOPER_GUIDE.md §10 — weight, not colour).
 *
 * Admin-only at the backend, because a cohort's majority is a fact about other
 * people's devices; a non-admin never sees the card at all.
 */
import { type ReactNode, useState } from 'react';

import { STATE_LABEL } from '@/components/domain/Verdict';
import { useApi } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { ApiError } from '@/services/api';
import { getDeviceBaseline } from '@/services/fleet';
import type { DeviceBaselineField } from '@/types/api';

/** Pills shown before "show all". */
export const COLLAPSED_PILLS = 6;

type PillState = 'deviates' | 'unknown' | 'compared' | 'not-compared';

function pillState(row: DeviceBaselineField): PillState {
  if (row.device_state === 'unknown') return 'unknown';
  if (row.deviation) return 'deviates';
  if (row.outcome === 'compared') return 'compared';
  return 'not-compared';
}

const PILL_CLASS: Record<PillState, string> = {
  // Heavier ink and border, never a verdict colour: an anomaly, not a failure.
  deviates: 'border-ink-2 border-2 bg-paper text-ink font-semibold',
  // The UNKNOWN treatment used everywhere else: dashed, neutral slate.
  unknown: 'border-unknown-br border-dashed bg-unknown-bg text-unknown',
  compared: 'border-border bg-paper text-ink-2',
  'not-compared': 'border-border bg-surface text-muted',
};

const OUTCOME_NOTE: Record<string, string> = {
  no_majority: 'cohort split',
  no_determinable_states: 'no readable device',
  cohort_too_small: 'cohort too small',
};

function Pill({ row }: { row: DeviceBaselineField }) {
  const state = pillState(row);
  const cohort =
    row.majority_state !== null
      ? `${STATE_LABEL[row.majority_state]} ${row.agreeing} of ${row.of_readable}`
      : null;

  let detail: string;
  if (state === 'unknown') detail = 'UNKNOWN';
  else if (state === 'deviates') detail = `${STATE_LABEL[row.device_state]} vs cohort ${cohort}`;
  else if (state === 'compared') detail = `${STATE_LABEL[row.device_state]} · ${cohort}`;
  else detail = OUTCOME_NOTE[row.outcome] ?? row.outcome;

  return (
    <li
      data-state={state}
      title={row.explanation}
      className={`inline-flex max-w-full items-baseline gap-1.5 rounded border px-2 py-0.5 text-sm ${PILL_CLASS[state]}`}
    >
      <span className="mono break-all">{row.field}</span>
      <span className="text-micro">{detail}</span>
    </li>
  );
}

export function PeerBaseline({ deviceId }: { deviceId: string }) {
  const { isAdmin } = useAuth();
  const baseline = useApi(
    () => (isAdmin ? getDeviceBaseline(deviceId) : Promise.resolve(null)),
    [isAdmin, deviceId],
  );
  const [expanded, setExpanded] = useState(false);

  if (!isAdmin) return null;

  const frame = (children: ReactNode) => (
    <section aria-label="Peer baseline" className="mt-5 border-t border-border pt-4">
      {children}
    </section>
  );

  if (baseline.loading) return frame(<p className="text-muted">Reading peer baseline…</p>);
  // A refusal (409) is the API's own sentence, which names no identifier. Any
  // other failure is stated by its status only: an error message can carry the
  // request URL, and with it the full configuration hash, which is never shown
  // as a name (DEF-3). Neither is hidden — an absent card would read as
  // "nothing unusual".
  if (baseline.error) {
    const cause = baseline.cause;
    const said =
      cause instanceof ApiError && cause.isRefusal
        ? cause.detail
        : `the request failed${cause instanceof ApiError ? ` (${cause.status})` : ''}`;
    return frame(<p className="text-muted">No peer baseline — {said}</p>);
  }
  const data = baseline.data;
  if (!data) return null;

  if (data.status === 'cohort_too_small') {
    return frame(
      <p className="text-muted">
        No peer baseline — cohort has <span className="num">{data.cohort_size}</span> device(s),{' '}
        <span className="num">{data.floor}</span> needed for comparison
      </p>,
    );
  }
  if (data.status === 'nothing_compared') {
    return frame(
      <p className="text-muted">
        No peer baseline — cohort has <span className="num">{data.cohort_size}</span> devices but
        no fields are compared
      </p>,
    );
  }

  // Deviations first, so collapsing never hides the one thing worth seeing.
  const rows = [
    ...data.per_field.filter((r) => pillState(r) === 'deviates'),
    ...data.per_field.filter((r) => pillState(r) !== 'deviates'),
  ];
  const shown = expanded ? rows : rows.slice(0, COLLAPSED_PILLS);
  const hidden = rows.length - shown.length;
  const deviating = data.per_field.filter((r) => r.deviation).length;
  const unknown = data.per_field.filter((r) => r.device_state === 'unknown').length;

  return frame(
    <>
      <p className="label mb-1">
        Peer baseline — <span className="num">{data.cohort_size}</span>{' '}
        <span className="mono normal-case">{data.cohort}</span> devices
      </p>
      {data.overall_deviation ? (
        <p className="mb-2 font-semibold text-ink">
          Differs from its cohort on <span className="num">{deviating}</span> field(s)
        </p>
      ) : (
        <p className="mb-2 text-ink-2">No compared field differs from the cohort majority</p>
      )}
      {unknown > 0 && (
        <p className="mb-2 text-muted">
          <span className="num">{unknown}</span> field(s) unknown on this device, so not compared
        </p>
      )}
      <ul className="flex flex-wrap gap-1.5" aria-label="Fields compared with the cohort">
        {shown.map((row) => (
          <Pill key={row.field} row={row} />
        ))}
      </ul>
      {(hidden > 0 || expanded) && rows.length > COLLAPSED_PILLS && (
        <button
          type="button"
          className="link mt-2 text-sm"
          aria-expanded={expanded}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? 'Show fewer' : `Show all (${hidden} more)`}
        </button>
      )}
      <p className="mt-2 text-micro text-muted">{data.note}</p>
    </>,
  );
}
