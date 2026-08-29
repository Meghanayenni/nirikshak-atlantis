/**
 * The hash-chained audit log (P2), read-only by design.
 *
 * Records are appended by the services that perform the actions, never by an
 * HTTP caller, so there is no write path here and there must never be one.
 *
 * The frontend also never recomputes the chain. `verifyChain` returns the
 * backend's answer, and a client-side "verified" badge that could disagree with
 * it would be worse than no badge: an integrity indicator that is sometimes
 * wrong is an integrity indicator nobody can use.
 *
 * The chain is **tamper-evident, not tamper-proof** (ADR 0008), and the UI says
 * so wherever it reports a verification result.
 */
import type { AuditRecordList, ChainHead, ChainVerification } from '@/types/api';

import { request } from './api';

export interface TrailFilters {
  action?: string;
  actor_id?: string;
  subject_kind?: string;
  subject_id?: string;
  limit?: number;
  offset?: number;
}

/**
 * Filtered history.
 *
 * The response carries `verifiable: false` whenever a filter is applied, because
 * the links between the returned rows are absent. Callers must present a
 * filtered listing as history, not as attested history.
 */
export function listRecords(filters: TrailFilters = {}): Promise<AuditRecordList> {
  return request<AuditRecordList>('/audit/records', { query: { limit: 100, ...filters } });
}

export function chainHead(): Promise<ChainHead> {
  return request<ChainHead>('/audit/head');
}

export function verifyChain(): Promise<ChainVerification> {
  return request<ChainVerification>('/audit/verify');
}
