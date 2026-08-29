/**
 * Prioritisation and peer baselines (P12). Admin-only.
 *
 * Both halves of the P12 stage meet here, and on this build both abstain:
 *
 *   **Exposure** needs interfaces to say where a control lives and access lists
 *   to say who can reach it. The corpus has zero of both, so no finding carries a
 *   score or a rank.
 *
 *   **Peer baselines** need a cohort. `minimum_cohort_size` is 5 (decision D54)
 *   and the largest cohort here holds four devices, so no baseline is
 *   established and no device is called an outlier.
 *
 * The page therefore shows the refusals *with their explanations*, which is the
 * useful content on a corpus this size. A view listing only comparable baselines
 * would be an empty page that reads as a uniform fleet — and an operator would
 * conclude their estate had no drift when the truth is that nothing was compared.
 */
import { Link } from 'react-router-dom';

import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Table, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { getFleetBaseline } from '@/services/fleet';
import { humanise } from '@/utils/format';

const OUTCOME_LABEL: Record<string, string> = {
  compared: 'Compared',
  cohort_too_small: 'Cohort too small',
  no_determinable_states: 'Nothing readable',
  no_majority: 'No majority',
};

export function PrioritisationPage() {
  const fleet = useApi(() => getFleetBaseline(), []);

  return (
    <>
      <PageHeader
        title="Prioritisation"
        subtitle="Exposure-aware ranking and peer-baseline drift, from the P12 stage"
      />

      <Card className="mb-4">
        <CardHeader title="Exposure ranking" />
        <BlockedState
          title="No exposure ranking is produced on this build"
          reason={
            'Exposure is a claim about where a control lives and who can reach it, so it needs ' +
            'interface data and access lists. No vendor pack extracts either, and the corpus ' +
            'contains no access list in any split — so every finding on every device is ' +
            'undetermined and both exposure_score and priority_rank stay unset. Ranking by ' +
            'severity alone is deliberately not offered in their place: severity alone must not ' +
            'determine remediation order.'
          }
          unblockedBy="An ACL-bearing configuration, plus interface parsing patterns in a vendor pack."
        />
      </Card>

      <Card>
        <CardHeader
          title="Peer baselines"
          subtitle="Each device compared against its own platform cohort"
        />

        {fleet.loading && <SkeletonRows rows={6} cols={4} />}
        {fleet.error && !fleet.loading && (
          <ErrorState message={fleet.error} onRetry={fleet.reload} />
        )}

        {fleet.data && (
          <>
            <div className="p-4 border-b border-border">
              <p className="text-[13px] text-ink-2 leading-relaxed">{fleet.data.summary}</p>
              <p className="mt-2 text-2xs text-muted leading-relaxed">
                {fleet.data.note} A cohort must hold at least{' '}
                <span className="num">{fleet.data.minimum_cohort_size}</span> devices before a
                deviation is reported: among three devices, &ldquo;one differs from two&rdquo; is a
                coin landing rather than drift.
              </p>
            </div>

            <div className="p-4 border-b border-border">
              <p className="label mb-2">Cohorts</p>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {fleet.data.cohorts.map((cohort) => (
                  <div key={cohort.cohort} className="border border-border rounded px-3 py-2">
                    <div className="flex items-baseline justify-between gap-2">
                      <p className="text-[13px] font-medium text-ink">{cohort.cohort}</p>
                      <p className="num text-[13px] text-ink">
                        {cohort.size}
                        <span className="text-muted">/{fleet.data!.minimum_cohort_size}</span>
                      </p>
                    </div>
                    <p className="mt-1 text-2xs text-muted truncate" title={cohort.devices.join(', ')}>
                      {cohort.devices.join(', ')}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {fleet.data.outliers.length > 0 ? (
              <Table caption="Devices deviating from their cohort">
                <thead>
                  <tr>
                    <Th>Device</Th>
                    <Th>Cohort</Th>
                    <Th>Field</Th>
                    <Th>Explanation</Th>
                  </tr>
                </thead>
                <tbody>
                  {fleet.data.outliers.map((outlier, index) => (
                    <tr key={`${outlier.device_id}-${outlier.field}-${index}`}>
                      <Td>
                        <Link to={`/devices/${outlier.device_id}`} className="link font-medium">
                          {outlier.device}
                        </Link>
                      </Td>
                      <Td className="text-muted">{outlier.cohort}</Td>
                      <Td className="mono">{outlier.field}</Td>
                      <Td className="text-ink-2">{outlier.explanation}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState
                title="No deviations reported"
                detail={
                  'This is not a statement that the fleet is uniform. No cohort reached the ' +
                  'minimum size, so no baseline was established and nothing was compared.'
                }
              />
            )}

            <div className="border-t border-border">
              <div className="px-4 py-3">
                <p className="label">Every baseline, including the refusals</p>
              </div>
              <Table caption="Baseline outcomes per cohort and field">
                <thead>
                  <tr>
                    <Th>Cohort</Th>
                    <Th>Field</Th>
                    <Th style={{ width: 150 }}>Outcome</Th>
                    <Th style={{ width: 90 }}>Readable</Th>
                    <Th>Explanation</Th>
                  </tr>
                </thead>
                <tbody>
                  {fleet.data.baselines.map((baseline, index) => (
                    <tr key={`${baseline.cohort}-${baseline.field}-${index}`}>
                      <Td className="text-muted">{baseline.cohort}</Td>
                      <Td className="mono">{baseline.field}</Td>
                      <Td>
                        <span className="text-[13px] text-ink-2">
                          {OUTCOME_LABEL[baseline.outcome] ?? humanise(baseline.outcome)}
                        </span>
                      </Td>
                      <Td className="num text-muted">
                        {baseline.determinable}
                        {baseline.indeterminate > 0 && (
                          <span title="devices that abstained on this field">
                            {' '}
                            (+{baseline.indeterminate})
                          </span>
                        )}
                      </Td>
                      <Td className="text-ink-2">{baseline.explanation}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
