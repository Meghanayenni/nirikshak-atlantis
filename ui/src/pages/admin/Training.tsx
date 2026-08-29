/**
 * The training centre — the administrator confirmation loop (P10/P11).
 *
 * This is the one screen where a person creates permanent trust, and §10 makes
 * it the deliberate exception to the product's density:
 *
 *   "The training interface is the exception: it is a focused judgement task and
 *   should be spacious, one line at a time. A cramped training screen produces
 *   careless confirmations, and a careless confirmation enters a vendor pack
 *   permanently."
 *
 * So the queue is a list to choose from, and the decision itself gets the whole
 * panel: one line, its shape, how often it occurs, and what it might mean.
 *
 * Two rules the UI must not bend:
 *
 *   **Similarity scores are rankings, not probabilities.** The backend sends
 *   `is_probability: false` and a note saying so; this page prints the rank and
 *   the raw score, and never formats either as a percentage.
 *
 *   **Two steps, never one.** Confirm records the decision; compile produces a
 *   DRAFT and shows the generated regex; activation is a separate, explicit
 *   action. DEVELOPER_GUIDE.md §4 requires the pattern be shown and editable first, and
 *   collapsing the steps would delete that review while looking like a
 *   convenience.
 */
import { AlertTriangle, Check, X } from 'lucide-react';
import { useState } from 'react';

import { PageHeader } from '@/components/ui/Page';
import { Button, Card, CardHeader, Field, Table, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useToast } from '@/hooks/useToast';
import {
  activate,
  compileDraft,
  confirm,
  getQueue,
  listExamples,
} from '@/services/training';
import { listFiles } from '@/services/devices';
import type { DraftResult, QueueEntry } from '@/types/api';

const CANONICAL_FIELDS = [
  'ssh_version',
  'telnet_enabled',
  'http_server_enabled',
  'https_server_enabled',
  'min_password_length',
  'idle_timeout_seconds',
  'logging_enabled',
  'logging_hosts',
  'ntp_servers',
  'snmp_v3_only',
  'banner_present',
  'aaa_enabled',
  'weak_ciphers',
];

const CASTS = ['str', 'int', 'bool', 'list', 'cidr', 'duration'];

export function TrainingPage() {
  const { push } = useToast();
  const queue = useApi(() => getQueue(), []);
  const examples = useApi(() => listExamples(), []);
  // The queue entry carries the file it came from but not that file's platform,
  // and the backend needs vendor + os_family to find the pack a confirmation
  // extends. Resolving it here from the file list is a lookup, not a guess.
  const files = useApi(() => listFiles(undefined, 200), []);

  const [selected, setSelected] = useState<QueueEntry | null>(null);
  const [field, setField] = useState('');
  const [valueToken, setValueToken] = useState<number | ''>('');
  const [cast, setCast] = useState('str');
  const [draft, setDraft] = useState<DraftResult | null>(null);
  const [editedPattern, setEditedPattern] = useState<string>('');

  const doConfirm = useMutation(confirm);
  const doCompile = useMutation(compileDraft);
  const doActivate = useMutation(activate);

  function reset() {
    setSelected(null);
    setField('');
    setValueToken('');
    setCast('str');
    setDraft(null);
    setEditedPattern('');
  }

  async function onConfirm(reject: boolean) {
    if (!selected) return;
    const source = (files.data ?? []).find((f) => f.file_id === selected.file_id);
    if (!source?.vendor || !source.os_family) {
      push(
        'error',
        'Platform unknown for this line',
        'The configuration it came from was not identified, so there is no vendor pack for a ' +
          'confirmation to extend.',
      );
      return;
    }

    const result = await doConfirm.run({
      cluster_id: selected.cluster_id,
      line: selected.line,
      vendor: source.vendor,
      os_family: source.os_family,
      outcome: reject ? 'rejected_not_security_relevant' : 'corrected',
      field: reject ? null : field,
    });

    if (!result) {
      push('error', 'Could not record the decision', doConfirm.error ?? undefined);
      return;
    }

    push('success', reject ? 'Recorded as not security relevant' : 'Mapping confirmed',
      `Audit sequence ${result.audit_seq ?? '—'}.`);
    examples.reload();
    queue.reload();

    if (reject) {
      reset();
      return;
    }

    // Step two: compile to a DRAFT so the pattern can be reviewed.
    const compiled = await doCompile.run({
      example_id: result.example_id,
      value_token: valueToken === '' ? null : Number(valueToken),
      cast,
      block_path: selected.block_path,
    });

    if (compiled) {
      setDraft(compiled);
      setEditedPattern(compiled.pattern);
    } else {
      push('error', 'Could not compile the pattern', doCompile.error ?? undefined);
    }
  }

  async function onActivate() {
    if (!draft) return;
    const result = await doActivate.run(draft.pack_id, draft.pack_version);
    if (result) {
      push(
        'success',
        `Pack ${result.pack_id} ${result.pack_version} activated`,
        `Previous version ${result.previous_version ?? '—'}. Re-audit affected files to apply it.`,
      );
      reset();
      queue.reload();
    } else {
      push('error', 'Activation failed', doActivate.error ?? undefined);
    }
  }

  const model = queue.data?.model;

  return (
    <>
      <PageHeader
        title="Training centre"
        subtitle="Unrecognised configuration lines, one judgement at a time"
      />

      {model && !model.available && (
        <Card className="mb-4">
          <div className="p-4 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-inferred" aria-hidden="true" />
            <div>
              <p className="text-[13px] font-medium text-ink">
                No suggestions are being produced
              </p>
              <p className="mt-1 text-[13px] text-ink-2 leading-relaxed">{model.summary}</p>
              <p className="mt-1 text-2xs text-muted leading-relaxed">
                Nothing here has been assessed by a model. A mapping may still be confirmed — the
                administrator is the authority, not the ranking. An empty suggestion list would be
                indistinguishable from &ldquo;the model looked and found nothing&rdquo;, which is a
                different statement entirely.
              </p>
            </div>
          </div>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Queue"
            subtitle={queue.data ? `${queue.data.confirmable} confirmable of ${queue.data.size}` : undefined}
          />
          {queue.loading && <SkeletonRows rows={8} cols={2} />}
          {queue.error && !queue.loading && (
            <ErrorState message={queue.error} onRetry={queue.reload} />
          )}
          {queue.data && queue.data.entries.length === 0 && (
            <EmptyState
              title="Queue is empty"
              detail="Every line in every ingested configuration was recognised by a pack."
            />
          )}
          {queue.data && queue.data.entries.length > 0 && (
            <>
              <p className="px-4 py-2 text-2xs text-muted border-b border-border">
                {queue.data.index}
              </p>
              <ul className="max-h-[560px] overflow-y-auto divide-y divide-border">
                {queue.data.entries.map((entry) => (
                  <li key={entry.cluster_id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelected(entry);
                        setDraft(null);
                        setField('');
                        setValueToken('');
                      }}
                      disabled={!entry.confirmable}
                      className={`w-full text-left px-4 py-3 transition-colors
                        ${selected?.cluster_id === entry.cluster_id ? 'bg-accent-bg' : 'hover:bg-surface'}
                        ${entry.confirmable ? '' : 'opacity-60 cursor-not-allowed'}`}
                    >
                      <p className="mono text-[12px] text-ink break-all">{entry.line}</p>
                      <p className="mt-1 text-2xs text-muted">
                        <span className="num">{entry.occurrences}</span> occurrence(s) in{' '}
                        <span className="num">{entry.file_count}</span> file(s)
                        {!entry.confirmable && ' · too generic to confirm as one decision'}
                      </p>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader title="Decision" subtitle="One line, given room" />

          {!selected && (
            <EmptyState
              title="Select a line"
              detail="Choose an unrecognised line from the queue to map it to a canonical field."
            />
          )}

          {selected && (
            <div className="p-5 space-y-5">
              <div>
                <p className="label mb-1">Unrecognised line</p>
                <p className="mono text-[14px] text-ink bg-surface border border-border rounded px-3 py-2.5 break-all">
                  {selected.line}
                </p>
                <p className="mt-1.5 text-2xs text-muted">
                  Shape <span className="mono">{selected.signature}</span>
                  {selected.block_path.length > 0 && (
                    <> · inside <span className="mono">{selected.block_path.join(' / ')}</span></>
                  )}
                </p>
              </div>

              <div>
                <p className="label mb-1.5">Suggestions</p>
                {selected.suggestions.length === 0 ? (
                  <div className="rounded border border-unknown-br bg-unknown-bg px-3 py-2">
                    <p className="text-[13px] text-ink-2">{selected.reason}</p>
                  </div>
                ) : (
                  <>
                    <ul className="space-y-1.5">
                      {selected.suggestions.map((s) => (
                        <li key={s.rank}>
                          <button
                            type="button"
                            onClick={() => setField(s.field)}
                            className={`w-full flex items-center gap-3 text-left border rounded px-3 py-2
                              ${field === s.field ? 'border-accent bg-accent-bg' : 'border-border hover:bg-surface'}`}
                          >
                            <span className="num text-muted">#{s.rank}</span>
                            <span className="mono text-[13px] text-ink flex-1">{s.field}</span>
                            <span className="num text-2xs text-muted">
                              score {s.raw_score.toFixed(3)}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-1.5 text-2xs text-inferred">{selected.confidence_note}</p>
                  </>
                )}
              </div>

              <div className="grid gap-4 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <label htmlFor="field" className="label block mb-1">
                    Canonical field
                  </label>
                  <select
                    id="field"
                    value={field}
                    onChange={(e) => setField(e.target.value)}
                    className="w-full h-9 px-2 rounded border border-border-strong bg-paper text-[13px]"
                  >
                    <option value="">Select a field…</option>
                    {CANONICAL_FIELDS.map((f) => (
                      <option key={f} value={f}>
                        {f}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="cast" className="label block mb-1">
                    Value type
                  </label>
                  <select
                    id="cast"
                    value={cast}
                    onChange={(e) => setCast(e.target.value)}
                    className="w-full h-9 px-2 rounded border border-border-strong bg-paper text-[13px]"
                  >
                    {CASTS.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="token" className="label block mb-1">
                  Which token carries the value?
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {selected.line.split(/\s+/).map((token, index) => (
                    <button
                      key={`${token}-${index}`}
                      type="button"
                      onClick={() => setValueToken(index)}
                      className={`mono text-[12px] px-2 py-1 rounded border transition-colors
                        ${valueToken === index ? 'border-accent bg-accent-bg text-ink' : 'border-border text-ink-2 hover:bg-surface'}`}
                    >
                      <span className="text-muted mr-1">{index}</span>
                      {token}
                    </button>
                  ))}
                </div>
                <p className="mt-1.5 text-2xs text-muted">
                  The selected token becomes <span className="mono">(\S+)</span> in the generated
                  pattern; every other token is escaped literally.
                </p>
              </div>

              <div className="flex flex-wrap gap-2 pt-1">
                <Button
                  variant="primary"
                  onClick={() => onConfirm(false)}
                  disabled={!field || doConfirm.pending || doCompile.pending}
                >
                  <Check className="h-3.5 w-3.5" aria-hidden="true" />
                  {doConfirm.pending || doCompile.pending ? 'Working…' : 'Confirm mapping'}
                </Button>
                <Button onClick={() => onConfirm(true)} disabled={doConfirm.pending}>
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                  Not security relevant
                </Button>
                <Button variant="ghost" onClick={reset}>
                  Cancel
                </Button>
              </div>

              {draft && (
                <div className="border-t border-border pt-4 space-y-3">
                  <p className="text-[13px] font-medium text-ink">
                    Review before activation — {draft.pack_id} {draft.pack_version} ({draft.status})
                  </p>
                  <div>
                    <label htmlFor="pattern" className="label block mb-1">
                      Generated pattern
                    </label>
                    <textarea
                      id="pattern"
                      value={editedPattern}
                      onChange={(e) => setEditedPattern(e.target.value)}
                      rows={2}
                      className="w-full mono text-[12px] px-3 py-2 rounded border
                                 border-border-strong bg-surface text-ink"
                    />
                    <p className="mt-1 text-2xs text-muted">
                      Editing is allowed and the backend re-validates any change: it must stay
                      anchored, compile, and still match the line it was confirmed from.
                      {editedPattern !== draft.pattern &&
                        ' Re-compiling with an edited pattern is not wired into this screen yet — activate the generated pattern, or cancel and start again.'}
                    </p>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-3">
                    <Field label="Field" mono>
                      {draft.field}
                    </Field>
                    <Field label="Capture" mono>
                      {draft.capture}
                    </Field>
                    <Field label="Scope" mono>
                      {draft.scope.length > 0 ? draft.scope.join(', ') : 'root level'}
                    </Field>
                  </div>
                  <Button variant="primary" onClick={onActivate} disabled={doActivate.pending}>
                    {doActivate.pending ? 'Activating…' : 'Activate pack version'}
                  </Button>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Recorded decisions"
          subtitle={examples.data ? `${examples.data.count} confirmation(s)` : undefined}
        />
        {examples.loading && <SkeletonRows rows={3} cols={4} />}
        {examples.data && examples.data.examples.length === 0 && (
          <BlockedState
            title="No confirmations recorded yet"
            reason={
              'Top-3 mapping accuracy and confidence calibration both need this population, and ' +
              'it fills through use rather than through a labelling exercise. No accuracy figure ' +
              'is computed from it here.'
            }
          />
        )}
        {examples.data && examples.data.examples.length > 0 && (
          <Table caption="Recorded training decisions">
            <thead>
              <tr>
                <Th>Line</Th>
                <Th>Field</Th>
                <Th>Outcome</Th>
                <Th>Confirmed by</Th>
                <Th>Audit seq</Th>
              </tr>
            </thead>
            <tbody>
              {examples.data.examples.map((example) => (
                <tr key={example.example_id}>
                  <Td className="mono text-[12px]">{example.line}</Td>
                  <Td className="mono">{example.field ?? '—'}</Td>
                  <Td className="text-muted">{example.outcome.replace(/_/g, ' ')}</Td>
                  <Td>{example.confirmed_by}</Td>
                  <Td className="num text-muted">{example.audit_seq ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
