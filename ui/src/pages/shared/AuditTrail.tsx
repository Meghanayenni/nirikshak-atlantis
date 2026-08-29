/**
 * The hash-chained audit trail (P2).
 *
 * Read-only by design: records are appended by the services that perform the
 * actions, never by an HTTP caller. This page renders what the chain holds and
 * verifies nothing itself — `ok` comes from `/audit/verify`, because a
 * client-side integrity badge that could disagree with the server would be worse
 * than none.
 *
 * Two things stated on the page rather than assumed:
 *
 *   **Tamper-evident, not tamper-proof** (ADR 0008). The chain detects
 *   modification, deletion, reordering and corruption. It does not detect an
 *   attacker with unrestricted database write access who recomputes the whole
 *   unkeyed chain.
 *
 *   **A filtered listing is not attested.** The links between rows are absent
 *   once a filter is applied, and the response says so with `verifiable: false`.
 *
 * `audit_run` appears here because P12 fixed DEF-14 — until then the one action
 * DEVELOPER_GUIDE.md §9 names alongside suggestions, corrections and pack changes was the
 * only one the chain never held.
 */
import { useState } from 'react';

import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { listRecords, verifyChain } from '@/services/auditTrail';
import { formatTimestamp, humanise, shortId } from '@/utils/format';

const ACTIONS = [
  'file_ingested',
  'file_rejected',
  'audit_run',
  'ai_suggested',
  'admin_confirmed',
  'admin_corrected',
  'pack_created',
  'pack_activated',
  'pack_rolled_back',
  'report_generated',
];

/** Security-sensitive actions, drawn with more weight than routine ones. */
const SENSITIVE = new Set([
  'admin_confirmed',
  'admin_corrected',
  'pack_created',
  'pack_activated',
  'pack_rolled_back',
  'file_rejected',
]);

export function AuditTrailPage() {
  const [action, setAction] = useState('');
  const records = useApi(() => listRecords(action ? { action } : {}), [action]);
  const verification = useApi(() => verifyChain(), []);

  return (
    <>
      <PageHeader
        title="Audit trail"
        subtitle="Every AI suggestion, human correction, pack change and audit result"
      />

      <Card className="mb-4">
        <CardHeader title="Chain integrity" />
        <div className="p-4">
          {verification.loading && <p className="text-[13px] text-muted">Verifying…</p>}
          {verification.error && (
            <ErrorState message={verification.error} onRetry={verification.reload} />
          )}
          {verification.data && (
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
              <span
                className={`inline-flex items-center gap-1 h-[22px] px-2 rounded border text-2xs
                  ${
                    verification.data.ok
                      ? 'bg-pass-bg text-pass border-pass-br'
                      : 'bg-fail text-white border-fail font-semibold'
                  }`}
              >
                <span aria-hidden="true">{verification.data.ok ? '✓' : '✗'}</span>
                {verification.data.ok ? 'VERIFIED' : 'FAILED'}
              </span>
              <p className="text-[13px] text-muted">
                <span className="num">{verification.data.checked}</span> record(s) checked ·{' '}
                <span className="mono">{verification.data.algo}</span>
              </p>
              {verification.data.first_failure_seq !== null && (
                <p className="text-[13px] text-fail">
                  First failure at sequence{' '}
                  <span className="num">{verification.data.first_failure_seq}</span>
                </p>
              )}
            </div>
          )}
          <p className="mt-3 text-2xs text-muted leading-relaxed">
            Tamper-evident, not tamper-proof. The chain detects record modification, deletion,
            reordering and corruption. It does not detect an attacker with unrestricted database
            write access who recomputes the complete unkeyed chain.
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Records"
          actions={
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              aria-label="Filter by action"
              className="h-8 px-2 rounded border border-border bg-paper text-[13px]"
            >
              <option value="">All actions</option>
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {humanise(a)}
                </option>
              ))}
            </select>
          }
        />

        {records.data && !records.data.verifiable && (
          <p className="px-4 py-2 text-2xs text-muted border-b border-border">
            {records.data.reason}
          </p>
        )}

        {records.loading && <SkeletonRows rows={8} cols={5} />}
        {records.error && !records.loading && (
          <ErrorState message={records.error} onRetry={records.reload} />
        )}
        {records.data && records.data.records.length === 0 && (
          <EmptyState title="No records" detail="Nothing matches this filter." />
        )}

        {records.data && records.data.records.length > 0 && (
          <Table caption="Audit chain records">
            <thead>
              <tr>
                <Th style={{ width: 60 }}>Seq</Th>
                <Th style={{ width: 170 }}>Timestamp</Th>
                <Th style={{ width: 160 }}>Action</Th>
                <Th style={{ width: 160 }}>Actor</Th>
                <Th>Subject</Th>
              </tr>
            </thead>
            <tbody>
              {records.data.records.map((record) => (
                <tr key={record.seq}>
                  <Td className="num text-muted">{record.seq}</Td>
                  <Td className="text-muted">{formatTimestamp(record.timestamp)}</Td>
                  <Td>
                    <span
                      className={
                        SENSITIVE.has(record.action)
                          ? 'text-ink font-medium'
                          : 'text-ink-2'
                      }
                    >
                      {humanise(record.action)}
                    </span>
                  </Td>
                  <Td>
                    <span className="text-ink-2">{record.actor.id}</span>
                    <span className="text-muted text-2xs ml-1.5 uppercase">
                      {record.actor.type}
                    </span>
                  </Td>
                  <Td className="mono text-[12px] text-muted">
                    {record.subject.kind} · {shortId(record.subject.id, 20)}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}

        <p className="px-4 py-3 text-2xs text-muted border-t border-border leading-relaxed">
          Payloads carry identifiers, counts, versions and digests — never configuration content.
          The audit database and the operational database are separate files precisely so that is
          provable by opening one.
        </p>
      </Card>
    </>
  );
}
