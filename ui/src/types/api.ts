/**
 * Types mirroring the NIRIKSHAK backend contracts.
 *
 * These were derived by calling every endpoint against the real application and
 * reading the responses, not by guessing from route names. The backend schema in
 * `api/models/` remains authoritative: nothing here re-implements a rule, a
 * verdict, a score or a ranking. The frontend renders what it is given.
 *
 * Where a field is nullable in the backend it is nullable here. `null` is a
 * meaningful answer throughout this system — an abstention, an undetermined
 * exposure, an unread hostname — and collapsing it to a default in the type
 * layer would be the first step towards showing a guess as a fact.
 */

// ---------------------------------------------------------------------------
// Shared enums, spelled exactly as the API serialises them
// ---------------------------------------------------------------------------

export type Verdict = 'pass' | 'fail' | 'unknown' | 'not_applicable';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FieldState = 'present' | 'absent_default' | 'absent_unsupported' | 'unknown';
export type Role = 'admin' | 'user';

/**
 * How a confidence value was arrived at (decision R7).
 *
 * The distinction the UI must never blur: `deterministic` and `admin_confirmed`
 * are exact 1.0 populations, `platform_default` is inferred rather than
 * observed, and `uncalibrated_similarity` is a raw score that is NOT a
 * probability and forces the field to UNKNOWN.
 */
export type ConfidenceMethod =
  | 'deterministic'
  | 'admin_confirmed'
  | 'platform_default'
  | 'calibrated_similarity'
  | 'uncalibrated_similarity';

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

export interface User {
  user_id: string;
  username: string;
  role: Role;
  disabled: boolean;
  created_at: string;
}

export interface UserList {
  count: number;
  users: User[];
}

// ---------------------------------------------------------------------------
// Ingestion / devices
// ---------------------------------------------------------------------------

/**
 * A device as ingestion detected it.
 *
 * `device_id` is the SHA-256 of the configuration file's contents, not a stable
 * device identity across time (DEF-3, open). The UI therefore labels devices by
 * `hostname` and falls back to a truncated identifier — never presenting a
 * content hash as though it were a device name.
 */
export interface Device {
  device_id: string;
  hostname: string | null;
  vendor: string | null;
  os_family: string | null;
  os_version: string | null;
  model: string | null;
}

export interface DeviceList {
  count: number;
  devices: Device[];
}

export interface ConfigFile {
  file_id: string;
  size_bytes: number;
  line_count: number;
  encoding: string;
  format: string;
  vendor: string | null;
  os_family: string | null;
  detection_reason: string;
  detection_score: number | null;
}

export interface FileList {
  count: number;
  files: ConfigFile[];
}

export interface ConfigLine {
  line_number: number;
  text: string;
  sha256: string;
}

export interface FileLines {
  file_id: string;
  total_lines: number;
  lines: ConfigLine[];
}

export interface IngestStats {
  distinct_lines: number;
  total_line_positions: number;
  deduplicated: number;
}

/**
 * Whether ingestion identified the platform, and if not, why not.
 *
 * `vendor` and `os_family` live HERE, not on the accepted file. The previous
 * declaration put them at the top level with an index signature, so reading
 * `accepted[0].vendor` type-checked and always returned undefined.
 */
export interface UploadDetection {
  outcome: 'detected' | 'no_signature_matched' | 'below_threshold' | 'ambiguous' | 'no_packs_available';
  vendor: string | null;
  os_family: string | null;
  score: number;
  margin: number;
  /** The backend's own sentence, e.g. "best candidate cisco/ios scored 0.25, below the 0.60 threshold". */
  explanation: string;
}

export interface UploadAccepted {
  file_id: string;
  filename: string;
  size_bytes: number;
  line_count: number;
  encoding: string;
  format: string;
  /** True when these exact bytes were already stored. Still an acceptance. */
  duplicate: boolean;
  detection: UploadDetection;
  identity: Record<string, unknown>;
}

export interface UploadRejected {
  filename: string;
  /** Machine-readable `RejectionReason`, e.g. `empty`, `binary_content`. */
  reason: string;
  /** The operator-facing sentence, e.g. "the file is empty (0 bytes)". */
  detail: string;
  size_bytes: number;
}

export interface UploadResult {
  batch_id: string;
  accepted: UploadAccepted[];
  rejected: UploadRejected[];
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export type VerdictCounts = Record<Verdict, number>;

export interface AuditRun {
  audit_id: string;
  device_id: string;
  owner_id: string | null;
  engine_version: string;
  rulepack_id: string;
  rulepack_version: string;
  pack_versions: Record<string, string>;
  rules_evaluated: number;
  verdicts: VerdictCounts;
  evaluated_at: string | null;
}

export interface AuditList {
  count: number;
  audits: AuditRun[];
}

/** ACL observations are a separate rail from findings (decision D22). */
export interface AclAnalysis {
  analysed_nothing: boolean;
  summary: {
    shadowed: number;
    redundant: number;
    overly_permissive: number;
    undetermined: number;
  };
  /**
   * Lists recognised and then dropped because one entry could not be read.
   *
   * Carried separately because a dropped list and a device with no access lists
   * both arrive as an empty analysis, and they call for opposite responses.
   */
  not_analysed: AclNotAnalysed[];
}

/**
 * The P12 Prioritise stage.
 *
 * `ranked` is false whenever exposure could not be determined, and `blockers`
 * names which input was missing. The UI must read `ranked` before presenting any
 * order: a client that sorted the findings list itself would be inventing the
 * exposure-aware ranking the backend deliberately declined to produce.
 */
export interface Prioritisation {
  ranked: boolean;
  reason: string;
  determined: number;
  undetermined: number;
  blockers: Record<string, number>;
}

export interface AclNotAnalysed {
  acl_name: string;
  entry_line: number;
  entry_text: string;
  reason: string;
  /** A ready-made operator-facing sentence from the backend. */
  summary: string;
}

export interface AuditResult {
  audit_id: string;
  device_id: string;
  verdicts: VerdictCounts;
  rules_evaluated: number;
  residue_lines: number;
  acl_analysis: AclAnalysis;
  prioritisation: Prioritisation;
}

export interface Evidence {
  file_id: string;
  file_path: string;
  line_start: number;
  line_end: number;
  raw_line: string;
  cite: string;
}

export interface ObservedValue {
  value: unknown;
  state: FieldState;
  confidence: number;
  confidence_method: ConfidenceMethod;
  is_probability: boolean;
}

/**
 * One control a finding's rule is mapped to, as the API resolved it (ADR 0057).
 *
 * Every field is rendered. A control identifier shown without its edition and
 * its provenance claims more than the repository supports: `project_asserted`
 * means the mapping is this project's judgement, not a published crosswalk.
 */
export interface FrameworkRef {
  framework: string;
  control_id: string;
  edition: string | null;
  citation: string | null;
  mapping_provenance: 'project_asserted' | 'official';
}

/** A sourced framework the rule deliberately does not map to, and why. */
export interface DeclinedMapping {
  framework: string;
  reason: string;
}

/**
 * What the API says about frameworks for the whole run. The interface resolves
 * none of it: `attached` is false when the run's rules are not the active
 * rules, and `withheld_reason` says so; `absent` names each framework that
 * contributes nothing on this device, with why.
 */
export interface FrameworkView {
  attached: boolean;
  withheld_reason: string | null;
  absent: Record<string, string>;
  selection: string[] | null;
  not_applied: Record<string, string>;
  not_assessed: { rule_id: string; reason: string }[];
}

/**
 * Remediation as the resolver returned it.
 *
 * `commands` is populated only from the vetted snippet library (Rule 4). The
 * library ships empty, so `outcome` is `no_snippet` or `not_actionable` and
 * `statement` carries the sentence an operator should read. The UI never
 * synthesises a command to fill the gap.
 */
export interface RemediationRef {
  outcome: string;
  statement: string;
  snippet_id: string | null;
  commands: string[];
  rollback: string[];
  vetted_by: string | null;
  reference: string | null;
}

export interface Finding {
  finding_id: string;
  rule_id: string;
  status: Verdict;
  severity: Severity;
  expected: string;
  observed: ObservedValue;
  unknown_reason: string | null;
  absence_reason: string | null;
  evidence: Evidence[];
  frameworks: FrameworkRef[];
  declined: DeclinedMapping[];
  remediation: RemediationRef;
  /** Populated by P12 only when exposure was determined. Null otherwise. */
  priority_rank?: number | null;
  exposure_score?: number | null;
}

export interface FindingList {
  audit_id: string;
  count: number;
  snippet_library_version: string;
  framework_view: FrameworkView;
  findings: Finding[];
}

/**
 * The vetted snippet attached to a plan step, or `null` when none resolved.
 *
 * **Commands live here, not on the step.** `/compliance/audits/{id}/remediation`
 * nests them, while `finding.remediation` from `/findings` is flat — two shapes
 * for two endpoints, and this type describes the nested one. An earlier version
 * of this interface declared `commands` and `rollback` at the step level with an
 * `[key: string]: unknown` escape hatch; the escape hatch let the declaration
 * disagree with the API without the compiler noticing, and the first code to
 * dereference `step.commands` crashed the application. No index signature here:
 * if the contract moves, this must fail to compile.
 */
export interface RemediationStepSnippet {
  snippet_id: string;
  vendor: string;
  os_family: string;
  commands: string[];
  rollback: string[];
  preconditions: string[];
  verification: string[];
  lockout_risk: string;
  service_affecting: boolean;
  requires_reload: boolean;
  depends_on: string[];
  vetted_by: string | null;
  reference: string | null;
}

export interface RemediationStep {
  /** The backend's own sequence number. `null` when nothing resolved. */
  apply_order: number | null;
  rule_id: string;
  severity: Severity;
  expected: string;
  outcome: string;
  statement: string;
  snippet: RemediationStepSnippet | null;
}

export interface RemediationPlan {
  audit_id: string;
  config_file_id: string;
  platform: string;
  failing_findings: number;
  resolved: number;
  snippet_library_version: string;
  steps: RemediationStep[];
  note: string;
}

// ---------------------------------------------------------------------------
// Fleet — peer baselines (P12)
// ---------------------------------------------------------------------------

export type BaselineOutcome =
  | 'compared'
  | 'cohort_too_small'
  | 'no_determinable_states'
  | 'no_majority';

export interface Cohort {
  cohort: string;
  size: number;
  devices: string[];
}

export interface FieldBaseline {
  cohort: string;
  field: string;
  outcome: BaselineOutcome;
  cohort_size: number;
  determinable: number;
  indeterminate: number;
  majority_state: FieldState | null;
  majority_count: number;
  counts: Record<string, number> | null;
  explanation: string;
}

export interface Outlier {
  device_id: string;
  device: string;
  cohort: string;
  field: string;
  device_state: FieldState;
  majority_state: FieldState;
  cohort_size: number;
  agreeing: number;
  of_readable: number;
  explanation: string;
}

export interface FleetBaseline {
  devices: number;
  skipped_files: number;
  cohorts: Cohort[];
  minimum_cohort_size: number;
  summary: string;
  baselines: FieldBaseline[];
  comparable_baselines: number;
  outliers: Outlier[];
  is_verdict: false;
  note: string;
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

export interface AuditActor {
  type: 'human' | 'system' | 'model';
  id: string;
  role: string | null;
}

export interface AuditSubject {
  kind: string;
  id: string;
}

export interface AuditRecord {
  seq: number;
  timestamp: string;
  actor: AuditActor;
  action: string;
  subject: AuditSubject;
  /** Canonical JSON, byte-exact as hashed. A string, not an object. */
  payload: string;
}

export interface AuditRecordList {
  /** A filtered listing is history, not attested history — the links are absent. */
  verifiable: boolean;
  reason: string;
  count: number;
  records: AuditRecord[];
}

export interface ChainHead {
  last_seq: number;
  last_hash: string;
  record_count: number;
  updated_at: string;
}

export interface ChainVerification {
  ok: boolean;
  /** The API's own field name. It is `records_checked`, not `checked`. */
  records_checked: number;
  algo: string;
  tamper_evident_not_tamper_proof: boolean;
  first_failure_seq: number | null;
  failures: string[];
}

// ---------------------------------------------------------------------------
// Training (P10 / P11)
// ---------------------------------------------------------------------------

export type SuggestionState =
  | 'ranked'
  | 'model_unavailable'
  | 'index_empty'
  | 'not_confirmable';

export interface Suggestion {
  rank: number;
  field: string;
  raw_score: number;
  calibrated_confidence: number | null;
  confidence_method: ConfidenceMethod;
}

export interface ModelAvailability {
  available: boolean;
  summary: string;
  package_installed: boolean;
  weights_present: boolean;
  airgap: boolean;
}

export interface QueueEntry {
  cluster_id: string;
  signature: string;
  line: string;
  occurrences: number;
  file_count: number;
  confirmable: boolean;
  block_path: string[];
  file_id: string;
  line_number: number;
  state: SuggestionState;
  reason: string;
  /** Always false. A similarity score is a ranking, never a probability. */
  is_probability: false;
  confidence_note: string;
  suggestions: Suggestion[];
}

export interface TrainingQueue {
  size: number;
  confirmable: number;
  index: string;
  model: ModelAvailability;
  scrubbed: boolean;
  entries: QueueEntry[];
}

export type TrainingOutcome =
  | 'accepted_rank_1'
  | 'accepted_rank_2'
  | 'accepted_rank_3'
  | 'corrected'
  | 'rejected_not_security_relevant';

export interface TrainingExample {
  example_id: string;
  vendor: string;
  os_family: string;
  line: string;
  field: string | null;
  outcome: TrainingOutcome;
  confirmed_by: string;
  audit_seq: number | null;
  top3_hit: boolean;
}

export interface TrainingExampleList {
  count: number;
  examples: TrainingExample[];
}

export interface ConfirmResult {
  example_id: string;
  field: string | null;
  outcome: TrainingOutcome;
  confirmed_by: string;
  audit_seq: number | null;
  improved_coverage: boolean;
}

export interface DraftResult {
  pack_id: string;
  pack_version: string;
  parent_version: string | null;
  status: string;
  pattern_id: string;
  field: string;
  pattern: string;
  scope: string[];
  capture: string;
  cast: string;
  edited: boolean;
  examples: string[];
}

export interface PackPattern {
  id: string;
  field: string;
  /** 'builtin' | 'admin-trained' | 'seed'. Governs whether it may be withdrawn. */
  source: string;
  match_type: string;
  /** The regular expression, shown in full — §4 requires it be readable. */
  pattern: string;
  capture: string;
  cast: string;
  scope_block: string[];
  examples: string[];
  training_example_id: string | null;
  audit_seq: number | null;
  /** The backend's own rule, not re-derived here: only admin-trained may go. */
  withdrawable: boolean;
}

export interface VendorPackSummary {
  pack_id: string;
  vendor: string;
  os_family: string;
  pack_version: string;
  parent_version: string | null;
  status: string;
  /** 'builtin' (repository content) or 'trained' (written by the loop). */
  origin: string;
  is_active: boolean;
  checksum: string | null;
  created_at: string | null;
  pattern_count: number;
  admin_trained_count: number;
  patterns: PackPattern[];
}

export interface VendorPackList {
  count: number;
  /** The canonical schema, served rather than hardcoded here (Rule 5). */
  canonical_fields: string[];
  casts: string[];
  packs: VendorPackSummary[];
}

export interface WithdrawResult {
  pack_id: string;
  pack_version: string;
  previous_version: string | null;
  withdrawn_pattern_id: string;
  checksum: string;
  pattern_count: number;
}

export interface ActivationResult {
  pack_id: string;
  pack_version: string;
  previous_version: string | null;
  checksum: string;
  patterns: string[];
  note: string;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface Health {
  status: string;
  version: string;
  schema_version: number;
  schema_versions: Record<string, number>;
  airgap: boolean;
  confidence_threshold: number;
  platform_default_min_confidence: number;
  platform_default_confidence: number;
  similarity_model: {
    available: boolean;
    model: string;
    package_installed: boolean;
    weights_present: boolean;
    summary: string;
    calibrated: boolean;
    note: string;
  };
  pdf_reporting: {
    available: boolean;
    weasyprint_installed: boolean;
    missing_libraries: string[];
    detail: string;
  };
  /**
   * The vetted snippet library this deployment resolves against.
   *
   * Was `Record<string, unknown>` while the library was empty and nothing read
   * it. `version` is a digest over the library's own bytes, or the literal
   * `"empty"` — a hash of nothing looks exactly like a hash of something, so the
   * empty case is named rather than hashed.
   */
  remediation_library: {
    snippets: number;
    version: string;
  };
}
