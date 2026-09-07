/**
 * Everything one device knows about itself, fetched once.
 *
 * The workspace panels all read from here rather than fetching independently,
 * so the report gate and the tab counts cannot disagree with the tabs they
 * describe.
 */
import { useCallback, useMemo } from 'react';

import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { useLocalReview } from '@/hooks/useLocalReview';
import { ApiError } from '@/services/api';
import { getFindings, getRemediation, listAudits, runAudit } from '@/services/audits';
import { getDevice } from '@/services/devices';
import { getQueue, listExamples } from '@/services/training';
import type { AuditRun, QueueEntry } from '@/types/api';

export interface Blocker {
  id: string;
  label: string;
}

export function useDeviceWorkspace(deviceId: string) {
  const { isAdmin } = useAuth();

  const device = useApi(() => getDevice(deviceId), [deviceId]);
  const audits = useApi(() => listAudits(200), [deviceId]);

  const runs = useMemo(
    () =>
      (audits.data ?? [])
        .filter((run) => run.device_id === deviceId)
        .sort((a, b) => (b.evaluated_at ?? '').localeCompare(a.evaluated_at ?? '')),
    [audits.data, deviceId],
  );

  const latest: AuditRun | null = runs[0] ?? null;
  const auditId = latest?.audit_id ?? null;

  const findings = useApi(
    () => (auditId ? getFindings(auditId) : Promise.resolve(null)),
    [auditId],
  );
  const remediation = useApi(
    () => (auditId ? getRemediation(auditId) : Promise.resolve(null)),
    [auditId],
  );

  // Training is admin-only at the backend. A user receives 403, which is a
  // fact about their role rather than a fault, and is reported as such.
  const queue = useApi(
    () => (isAdmin ? getQueue({ file_id: deviceId }) : Promise.resolve(null)),
    [deviceId, isAdmin],
  );
  const examples = useApi(
    () => (isAdmin ? listExamples(500) : Promise.resolve(null)),
    [isAdmin, deviceId],
  );

  const reviewRestricted =
    !isAdmin || (queue.cause instanceof ApiError && queue.cause.isForbidden);

  /**
   * A queue entry counts as decided once an administrator has recorded a
   * decision for that exact line — including "not security relevant". Confirming
   * does not delete the residue row, so an empty queue is not the signal; a
   * decided queue is.
   */
  const decidedLines = useMemo(
    () => new Set((examples.data?.examples ?? []).map((example) => example.line)),
    [examples.data],
  );

  const undecided: QueueEntry[] = useMemo(
    () => (queue.data?.entries ?? []).filter((entry) => !decidedLines.has(entry.line)),
    [queue.data, decidedLines],
  );

  const steps = useMemo(() => remediation.data?.steps ?? [], [remediation.data]);

  // Commands are nested under `snippet`, which is null when the vetted library
  // resolved nothing for the rule — the ordinary case while that library is
  // empty. Reading them off the step would be reading a key the API never sends.
  const actionableSteps = useMemo(
    () => steps.filter((step) => (step.snippet?.commands.length ?? 0) > 0),
    [steps],
  );

  const review = useLocalReview(auditId);
  const unreviewedSteps = useMemo(
    () => actionableSteps.filter((step) => !review.isReviewed(step.rule_id)),
    [actionableSteps, review],
  );

  /**
   * Whether the gate below is knowable yet.
   *
   * `blockers` is derived from four independent requests, and an empty list
   * means two very different things: "nothing is outstanding" and "nothing has
   * arrived yet". Reading the second as the first is what made the report screen
   * offer a Generate button for a fraction of a second and then withdraw it — the
   * audit list landed first, so `latest` was set while the remediation plan and
   * the review queue were still in flight, and a gate with no inputs is open.
   *
   * The trailing clauses cover the frame after `auditId` first appears: the
   * effects that fetch from it have not run yet, so their `loading` flags are
   * still false from the previous, null-keyed run.
   */
  const gateLoading =
    audits.loading ||
    remediation.loading ||
    (auditId !== null && remediation.data === null && remediation.error === null) ||
    (isAdmin &&
      (queue.loading ||
        examples.loading ||
        (queue.data === null && queue.error === null) ||
        (examples.data === null && examples.error === null)));

  /** What stands between this device and a report, in pipeline order. */
  const blockers: Blocker[] = useMemo(() => {
    const list: Blocker[] = [];
    if (!latest) {
      list.push({ id: 'audit', label: 'This configuration has not been audited yet.' });
      return list;
    }
    if (!reviewRestricted && undecided.length > 0) {
      list.push({
        id: 'review',
        label: `${undecided.length} configuration line${undecided.length === 1 ? '' : 's'} still await a decision in Needs review.`,
      });
    }
    if (unreviewedSteps.length > 0) {
      list.push({
        id: 'remediation',
        label: `${unreviewedSteps.length} remediation command${unreviewedSteps.length === 1 ? '' : 's'} have not been marked reviewed.`,
      });
    }
    return list;
  }, [latest, reviewRestricted, undecided.length, unreviewedSteps.length]);

  const audit = useMutation(runAudit);

  const reloadAll = useCallback(() => {
    audits.reload();
    findings.reload();
    remediation.reload();
    if (isAdmin) {
      queue.reload();
      examples.reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  return {
    device,
    runs,
    latest,
    auditId,
    findings,
    remediation,
    queue,
    examples,
    reviewRestricted,
    undecided,
    decidedLines,
    steps,
    actionableSteps,
    review,
    blockers,
    gateLoading,
    audit,
    reloadAll,
  };
}

export type DeviceWorkspace = ReturnType<typeof useDeviceWorkspace>;
