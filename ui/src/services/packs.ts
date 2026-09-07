/**
 * The vendor pack inventory, and withdrawing a mapping from it.
 *
 * Packs are data (Rule 5), and this is the screen where an administrator reads
 * that data back. Both endpoints are admin-only at the backend; a non-admin
 * receives 403, which is a fact about their role and is reported as one.
 *
 * There is no delete. `withdraw` drafts a new pack version without the pattern,
 * validates it and activates it — the version that contained the mapping stays
 * on disk, because an audit run under it still has to be explainable.
 */
import type { VendorPackList, WithdrawResult } from '@/types/api';

import { request } from './api';

export function listPacks(): Promise<VendorPackList> {
  return request<VendorPackList>('/training/packs');
}

export interface WithdrawInput {
  packId: string;
  patternId: string;
  reason?: string;
}

/**
 * Retire one admin-trained pattern.
 *
 * `withdrawn_by` is deliberately absent from the body: the backend takes it from
 * the authenticated identity, for the same reason `confirmed_by` is not sendable.
 */
export function withdrawPattern(input: WithdrawInput): Promise<WithdrawResult> {
  return request<WithdrawResult>('/training/withdraw', {
    method: 'POST',
    body: {
      pack_id: input.packId,
      pattern_id: input.patternId,
      reason: input.reason ?? null,
    },
  });
}
