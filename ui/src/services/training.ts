/**
 * The administrator confirmation loop (P10 retrieval, P11 confirmation).
 *
 * This is the one workflow in NIRIKSHAK where a person creates trust, so the
 * client's job is to carry their decision faithfully and add nothing to it:
 *
 *     queue -> confirm -> compile (DRAFT) -> review the regex -> activate
 *
 * Two steps, never one. `compile` returns a DRAFT and the generated pattern;
 * `activate` is a separate call. DEVELOPER_GUIDE.md §4 requires the pattern be shown to
 * the administrator and editable before activation, and collapsing the two into
 * one convenient call would delete that review while appearing to be a
 * convenience.
 *
 * Every endpoint is admin-only at the backend.
 */
import type {
  ActivationResult,
  BootstrapAssessment,
  BootstrapInput,
  BootstrapResult,
  ConfirmResult,
  DiscardResult,
  DraftResult,
  TrainingExampleList,
  TrainingOutcome,
  TrainingQueue,
} from '@/types/api';

import { request } from './api';

export function getQueue(filters: { file_id?: string; vendor?: string } = {}) {
  return request<TrainingQueue>('/training/queue', { query: filters });
}

export interface ConfirmInput {
  cluster_id: string;
  line: string;
  vendor: string;
  os_family: string;
  outcome: TrainingOutcome;
  field?: string | null;
  value_semantics?: string | null;
}

/**
 * Record one administrator decision.
 *
 * `confirmed_by` is deliberately absent from the request body: the backend takes
 * it from the authenticated identity and rejects the field outright. A caller
 * able to set it could attribute their confirmation to a colleague.
 */
export function confirm(input: ConfirmInput): Promise<ConfirmResult> {
  return request<ConfirmResult>('/training/confirm', { method: 'POST', body: input });
}

export interface CompileInput {
  example_id: string;
  value_token?: number | null;
  literal_value?: string | null;
  cast?: string;
  block_path?: string[];
  generalise_numeric_scope?: boolean;
  /** An edited regex. Re-validated by the backend, never trusted as supplied. */
  pattern_override?: string | null;
}

export function compileDraft(input: CompileInput): Promise<DraftResult> {
  return request<DraftResult>('/training/compile', { method: 'POST', body: input });
}

export function activate(packId: string, packVersion: string): Promise<ActivationResult> {
  return request<ActivationResult>('/training/activate', {
    method: 'POST',
    body: { pack_id: packId, pack_version: packVersion },
  });
}

export function rollback(packId: string, toVersion: string): Promise<ActivationResult> {
  return request<ActivationResult>('/training/rollback', {
    method: 'POST',
    body: { pack_id: packId, to_version: toVersion },
  });
}

export function listExamples(limit = 100): Promise<TrainingExampleList> {
  return request<TrainingExampleList>('/training/examples', { query: { limit } });
}

/**
 * Bootstrapping a platform no pack knows (ADR 0067).
 *
 * The assessment is what the file shows; the input is the administrator's
 * choices over it. The client proposes nothing of its own.
 */
export function getBootstrap(fileId: string): Promise<BootstrapAssessment> {
  return request<BootstrapAssessment>(`/training/bootstrap/${encodeURIComponent(fileId)}`);
}

export function createBootstrap(input: BootstrapInput): Promise<BootstrapResult> {
  return request<BootstrapResult>('/training/bootstrap', { method: 'POST', body: input });
}

export function discardBootstrap(packId: string): Promise<DiscardResult> {
  const [vendor, osFamily] = packId.split('/');
  return request<DiscardResult>(
    `/training/bootstrap/${encodeURIComponent(vendor)}/${encodeURIComponent(osFamily)}`,
    { method: 'DELETE' },
  );
}
