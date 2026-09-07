/**
 * Creating, editing and retiring a human-verified mapping.
 *
 * Every one of these composes endpoints that already existed for the residue
 * workflow. Nothing here is a shortcut around that workflow — in particular the
 * **two-step review is preserved** (decision D51, DEVELOPER_GUIDE.md §4):
 *
 *     describe  ->  compile  ->  READ THE REGEX  ->  activate
 *
 * `compile` returns a DRAFT and the generated pattern; `activate` is a separate
 * call the administrator makes after looking at it. Collapsing them into one
 * convenient function would delete the review while appearing to be a
 * convenience, so this module deliberately exposes them as two.
 *
 * **Editing is withdraw-then-create, not an in-place rewrite.** A pattern is
 * never mutated where it stands: the version holding the old mapping stays on
 * disk so an audit run under it remains explainable, and the new mapping is a
 * fresh decision by a named person at a known moment. That is also why an edit
 * re-runs `confirm` rather than reusing the old example — the administrator is
 * deciding again, and the record should say so.
 */
import type { ActivationResult, DraftResult, WithdrawResult } from '@/types/api';

import { request } from './api';
import { activate, compileDraft, confirm } from './training';
import { withdrawPattern } from './packs';

export interface MappingDraftInput {
  vendor: string;
  osFamily: string;
  /** The configuration line, exactly as it appears on the device. */
  line: string;
  /** The canonical field this line establishes. */
  field: string;
  /**
   * Which whitespace-separated token carries the value, zero-based.
   * `null` means the line's presence is the fact — `no ip http server` has
   * nothing to capture — and `literalValue` then supplies what the field becomes.
   */
  valueToken: number | null;
  literalValue?: string | null;
  cast: string;
  /** An edited regex. Re-validated by the backend, never trusted as supplied. */
  patternOverride?: string | null;
}

/**
 * Record the decision and compile it into a DRAFT. Nothing is live yet.
 *
 * `cluster_id` is the administrator's own label rather than a queue id. The
 * backend looks it up to attach any suggestions that were shown, and finding
 * nothing is normal here: an authored mapping had no ranked suggestions because
 * nobody was asked to rank anything.
 */
export async function draftMapping(input: MappingDraftInput): Promise<DraftResult> {
  const recorded = await confirm({
    cluster_id: `authored:${input.field}`,
    line: input.line,
    vendor: input.vendor,
    os_family: input.osFamily,
    // The administrator supplied the field outright rather than accepting a
    // ranked suggestion, which is what CORRECTED means.
    outcome: 'corrected',
    field: input.field,
  });

  return compileDraft({
    example_id: recorded.example_id,
    value_token: input.valueToken,
    literal_value: input.literalValue ?? null,
    cast: input.cast,
    pattern_override: input.patternOverride ?? null,
  });
}

/** The second step. Separate on purpose — see the module note. */
export function activateMapping(draft: DraftResult): Promise<ActivationResult> {
  return activate(draft.pack_id, draft.pack_version);
}

export function retireMapping(
  packId: string,
  patternId: string,
  reason?: string,
): Promise<WithdrawResult> {
  return withdrawPattern({ packId, patternId, reason });
}

/** Re-read the canonical schema. Exposed for the form's field selector. */
export function canonicalSchema(): Promise<{ canonical_fields: string[]; casts: string[] }> {
  return request<{ canonical_fields: string[]; casts: string[] }>('/training/packs');
}
