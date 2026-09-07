/**
 * The activity log — every action the system recorded, in one place.
 *
 * This is the hash-chained audit trail: configurations taken in, audits run,
 * suggestions the model made, decisions an administrator confirmed or
 * corrected, vendor pack versions created, activated and rolled back, and
 * reports generated.
 *
 * Read-only. Records are appended by the services that perform the actions,
 * never by an HTTP caller — an endpoint that could inject a record would attest
 * to whatever a client claimed rather than to what the system did.
 */
import { useState } from 'react';

import { PageHeader } from '@/components/ui/Page';
import { Card, Table, Td, Th } from '@/components/ui/Primitives';
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

/** Actions where a person changed what the system will believe next. */
const SENSITIVE = new Set([
  'admin_confirmed',
  'admin_corrected',
  'pack_created',
  'pack_activated',
  'pack_rolled_back',
  'file_rejected',
]);

export function ActivityPage() {
  const [action, setAction] = useState('');
  const records = useApi(() => listRecords(action ? { action } : {}), [action]);
  const verification = useApi(() => verifyChain(), []);

  return (
    <>
      <PageHeader
        title="Activity log"
        subtitle="Configurations taken in, audits run, decisions confirmed, packs changed, reports generated"
        actions={
          verification.data && (
            <span
              className={`inline-flex h-[26px] items-center gap-1 rounded border px-2.5 text-micro
                ${
                  verification.data.ok
                    ? 'border-pass-br bg-pass-bg text-pass'
                    : 'border-fail bg-fail font-semibold text-white'
                }`}
            >
              <span aria-hidden="true">{verification.data.ok ? '✓' : '✗'}</span>
              {verification.data.ok ? 'CHAIN VERIFIED' : 'CHAIN FAILED'}
              <span className="num ml-1 opacity-80">{verification.data.records_checked}</span>
            </span>
          )
        }
      />

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
          <select
            value={action}
            onChange={(event) => setAction(event.target.value)}
            aria-label="Filter by action"
            className="h-9 rounded border border-border bg-paper px-2"
          >
            <option value="">All actions</option>
            {ACTIONS.map((name) => (
              <option key={name} value={name}>
                {humanise(name)}
              </option>
            ))}
          </select>
          {records.data && (
            <span className="text-muted">
              <span className="num">{records.data.count}</span> record(s)
            </span>
          )}
        </div>

        {records.loading && <SkeletonRows rows={8} cols={5} />}
        {records.error && !records.loading && (
          <ErrorState message={records.error} onRetry={records.reload} />
        )}
        {records.data && records.data.records.length === 0 && (
          <EmptyState title="No records" detail="Nothing matches this filter." />
        )}

        {records.data && records.data.records.length > 0 && (
          <Table caption="Recorded actions">
            <thead>
              <tr>
                <Th style={{ width: 70 }}>Seq</Th>
                <Th style={{ width: 190 }}>When</Th>
                <Th style={{ width: 180 }}>Action</Th>
                <Th style={{ width: 180 }}>Who</Th>
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
                        SENSITIVE.has(record.action) ? 'font-medium text-ink' : 'text-ink-2'
                      }
                    >
                      {humanise(record.action)}
                    </span>
                  </Td>
                  <Td>
                    <span className="text-ink-2">{record.actor.id}</span>
                    <span className="ml-1.5 text-micro uppercase text-muted">
                      {record.actor.type}
                    </span>
                  </Td>
                  <Td className="mono text-muted">
                    {record.subject.kind} · {shortId(record.subject.id, 20)}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}

        <p className="border-t border-border px-4 py-3 text-micro text-muted">
          Payloads carry identifiers, counts and versions — never configuration content. Remediation
          review marks are not here: they are notes in your browser, not recorded actions.
        </p>
      </Card>
    </>
  );
}
