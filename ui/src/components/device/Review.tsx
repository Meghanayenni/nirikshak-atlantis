/**
 * Needs review — the lines this device's pack did not recognise.
 *
 * The confirmation loop lives here, inside the device it concerns, because that
 * is where the operator has the context to judge a line.
 *
 * Two rules that do not bend:
 *
 *   **Similarity scores are rankings, not probabilities.** The rank and the raw
 *   score are printed as they arrive; neither is formatted as a percentage.
 *
 *   **Two steps, never one.** Confirming records the decision; compiling
 *   produces a DRAFT whose pattern is shown and editable; activation is a
 *   separate action. Collapsing them would delete the review step while looking
 *   like a convenience.
 *
 * §10 makes this screen the deliberate exception to the product's density: one
 * line at a time, given room. A cramped review produces careless confirmations,
 * and a careless confirmation enters a vendor pack permanently.
 */
import { Check, X } from 'lucide-react';
import { useState } from 'react';

import { Button, Field, Table, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useMutation } from '@/hooks/useApi';
import { useToast } from '@/hooks/useToast';
import { activate, compileDraft, confirm } from '@/services/training';
import type { Device, DraftResult, QueueEntry } from '@/types/api';

import type { DeviceWorkspace } from './useDeviceWorkspace';

const SECURITY_FIELDS = [
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

const VALUE_TYPES = ['str', 'int', 'bool', 'list', 'cidr', 'duration'];

export function ReviewPanel({ workspace }: { workspace: DeviceWorkspace }) {
  const { queue, undecided, reviewRestricted, device, examples, reloadAll } = workspace;
  const { push } = useToast();

  const [selected, setSelected] = useState<QueueEntry | null>(null);
  const [field, setField] = useState('');
  const [valueType, setValueType] = useState('str');
  const [valueToken, setValueToken] = useState<number | ''>('');
  const [draft, setDraft] = useState<DraftResult | null>(null);
  const [pattern, setPattern] = useState('');

  const doConfirm = useMutation(confirm);
  const doCompile = useMutation(compileDraft);
  const doActivate = useMutation(activate);

  function reset() {
    setSelected(null);
    setField('');
    setValueType('str');
    setValueToken('');
    setDraft(null);
    setPattern('');
  }

  if (reviewRestricted) {
    return (
      <BlockedState
        title="Clarification is an administrator step"
        reason="The confirmation loop writes into a vendor pack, so the backend restricts it to administrators. Your account can read this device's findings and evidence, but not decide what an unrecognised line means."
        unblockedBy="An administrator working through this device's queue."
      />
    );
  }

  if (queue.loading) return <SkeletonRows rows={6} cols={2} />;
  if (queue.error) return <ErrorState message={queue.error} onRetry={queue.reload} />;

  const entries = queue.data?.entries ?? [];
  const model = queue.data?.model;
  const dev = device.data as Device | null;

  async function decide(reject: boolean) {
    if (!selected) return;
    if (!dev?.vendor || !dev.os_family) {
      push(
        'error',
        'Platform not identified',
        'This configuration has no detected vendor or OS family, so there is no pack for a confirmation to extend.',
      );
      return;
    }

    const recorded = await doConfirm.run({
      cluster_id: selected.cluster_id,
      line: selected.line,
      vendor: dev.vendor,
      os_family: dev.os_family,
      outcome: reject ? 'rejected_not_security_relevant' : 'corrected',
      field: reject ? null : field,
    });

    if (!recorded) {
      push('error', 'Could not record the decision', doConfirm.error ?? undefined);
      return;
    }

    push(
      'success',
      reject ? 'Recorded as not security relevant' : 'Mapping confirmed',
      `Audit sequence ${recorded.audit_seq ?? '—'}.`,
    );
    examples.reload();
    queue.reload();

    if (reject) {
      reset();
      return;
    }

    const compiled = await doCompile.run({
      example_id: recorded.example_id,
      value_token: valueToken === '' ? null : Number(valueToken),
      cast: valueType,
      block_path: selected.block_path,
    });

    if (compiled) {
      setDraft(compiled);
      setPattern(compiled.pattern);
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
        'Re-run the audit to apply it to this device.',
      );
      reset();
      reloadAll();
    } else {
      push('error', 'Activation failed', doActivate.error ?? undefined);
    }
  }

  const decided = entries.length - undecided.length;

  return (
    <div className="p-4">
      {model && !model.available && (
        <div className="mb-4 rounded border border-inferred-br bg-inferred-bg px-4 py-3">
          <p className="font-medium text-ink">No suggestions are being produced</p>
          <p className="mt-1 text-ink-2">{model.summary}</p>
        </div>
      )}

      {entries.length === 0 ? (
        <EmptyState
          title="Every line was recognised"
          detail="No residue was left for this configuration, so there is nothing to clarify."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-5">
          <div className="card lg:col-span-2">
            <div className="card-header">
              <h3 className="card-title">Queue</h3>
              <span className="text-muted">
                <span className="num">{decided}</span> of{' '}
                <span className="num">{entries.length}</span> decided
              </span>
            </div>
            <ul className="max-h-[560px] divide-y divide-border overflow-y-auto">
              {entries.map((entry) => {
                const isDecided = !undecided.includes(entry);
                return (
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
                      className={`w-full px-4 py-3 text-left transition-colors
                        ${selected?.cluster_id === entry.cluster_id ? 'bg-accent-bg' : 'hover:bg-surface'}
                        ${entry.confirmable ? '' : 'cursor-not-allowed opacity-60'}`}
                    >
                      <div className="flex items-start gap-2">
                        {isDecided && (
                          <Check
                            className="mt-1 h-3.5 w-3.5 shrink-0 text-pass"
                            aria-label="Decided"
                          />
                        )}
                        <p className="mono break-all text-ink">{entry.line}</p>
                      </div>
                      <p className="mt-1 text-micro text-muted">
                        <span className="num">{entry.occurrences}</span> occurrence(s)
                        {!entry.confirmable && ' · too generic to confirm as one decision'}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="card lg:col-span-3">
            <div className="card-header">
              <h3 className="card-title">Decision</h3>
            </div>

            {!selected ? (
              <EmptyState
                title="Select a line"
                detail="Choose a line to map it to a security field, or mark it as not security relevant."
              />
            ) : (
              <div className="space-y-5 p-5">
                <div>
                  <p className="label mb-1">Unrecognised line</p>
                  <p className="mono break-all rounded border border-border bg-surface px-3 py-2.5 text-lg text-ink">
                    {selected.line}
                  </p>
                  <p className="mt-1.5 text-micro text-muted">
                    Shape <span className="mono">{selected.signature}</span>
                    {selected.block_path.length > 0 && (
                      <>
                        {' · inside '}
                        <span className="mono">{selected.block_path.join(' / ')}</span>
                      </>
                    )}
                  </p>
                </div>

                {selected.suggestions.length > 0 ? (
                  <div>
                    <p className="label mb-1.5">Ranked suggestions</p>
                    <ul className="space-y-1.5">
                      {selected.suggestions.map((suggestion) => (
                        <li key={suggestion.rank}>
                          <button
                            type="button"
                            onClick={() => setField(suggestion.field)}
                            className={`flex w-full items-center gap-3 rounded border px-3 py-2 text-left
                              ${
                                field === suggestion.field
                                  ? 'border-accent bg-accent-bg'
                                  : 'border-border hover:bg-surface'
                              }`}
                          >
                            <span className="num text-muted">#{suggestion.rank}</span>
                            <span className="mono flex-1 text-ink">{suggestion.field}</span>
                            <span className="num text-micro text-muted">
                              score {suggestion.raw_score.toFixed(3)}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                    <p className="mt-1.5 text-micro text-inferred">{selected.confidence_note}</p>
                  </div>
                ) : (
                  <div className="rounded border border-unknown-br bg-unknown-bg px-3 py-2">
                    <p className="text-ink-2">{selected.reason}</p>
                  </div>
                )}

                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="sm:col-span-2">
                    <label htmlFor="field" className="label mb-1 block">
                      Security field
                    </label>
                    <select
                      id="field"
                      value={field}
                      onChange={(event) => setField(event.target.value)}
                      className="h-10 w-full rounded border border-border-strong bg-paper px-2"
                    >
                      <option value="">Select a field…</option>
                      {SECURITY_FIELDS.map((name) => (
                        <option key={name} value={name}>
                          {name}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="cast" className="label mb-1 block">
                      Data type
                    </label>
                    <select
                      id="cast"
                      value={valueType}
                      onChange={(event) => setValueType(event.target.value)}
                      className="h-10 w-full rounded border border-border-strong bg-paper px-2"
                    >
                      {VALUE_TYPES.map((type) => (
                        <option key={type} value={type}>
                          {type}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <p className="label mb-1.5">Which token carries the value?</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.line.split(/\s+/).map((token, index) => (
                      <button
                        key={`${token}-${index}`}
                        type="button"
                        onClick={() => setValueToken(index)}
                        className={`mono rounded border px-2 py-1 transition-colors
                          ${
                            valueToken === index
                              ? 'border-accent bg-accent-bg text-ink'
                              : 'border-border text-ink-2 hover:bg-surface'
                          }`}
                      >
                        <span className="mr-1 text-muted">{index}</span>
                        {token}
                      </button>
                    ))}
                  </div>
                  <p className="mt-1.5 text-micro text-muted">
                    The selected token becomes <span className="mono">(\S+)</span>; every other
                    token is escaped literally.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button
                    variant="primary"
                    onClick={() => decide(false)}
                    disabled={!field || doConfirm.pending || doCompile.pending}
                  >
                    <Check className="h-4 w-4" aria-hidden="true" />
                    {doConfirm.pending || doCompile.pending ? 'Working…' : 'Confirm mapping'}
                  </Button>
                  <Button onClick={() => decide(true)} disabled={doConfirm.pending}>
                    <X className="h-4 w-4" aria-hidden="true" />
                    Not security relevant
                  </Button>
                  <Button variant="ghost" onClick={reset}>
                    Cancel
                  </Button>
                </div>

                {draft && (
                  <div className="space-y-3 border-t border-border pt-4">
                    <p className="font-medium text-ink">
                      Review before activation — {draft.pack_id} {draft.pack_version} (
                      {draft.status})
                    </p>
                    <div>
                      <label htmlFor="pattern" className="label mb-1 block">
                        Generated pattern
                      </label>
                      <textarea
                        id="pattern"
                        value={pattern}
                        onChange={(event) => setPattern(event.target.value)}
                        rows={2}
                        className="mono w-full rounded border border-border-strong bg-surface px-3 py-2 text-ink"
                      />
                      {pattern !== draft.pattern && (
                        <p className="mt-1 text-micro text-inferred">
                          Re-compiling an edited pattern is not wired into this screen. Activate the
                          generated pattern, or cancel and start again.
                        </p>
                      )}
                    </div>
                    <div className="grid gap-3 sm:grid-cols-4">
                      <Field label="Security field" mono>
                        {draft.field}
                      </Field>
                      <Field label="Data type" mono>
                        {draft.cast}
                      </Field>
                      <Field label="Scope" mono>
                        {draft.scope.length > 0 ? draft.scope.join(' / ') : 'root level'}
                      </Field>
                      <Field label="Pack version" mono>
                        {draft.pack_version}
                      </Field>
                    </div>
                    <Button variant="primary" onClick={onActivate} disabled={doActivate.pending}>
                      {doActivate.pending ? 'Activating…' : 'Activate pack version'}
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {examples.data && examples.data.examples.length > 0 && (
        <div className="card mt-4">
          <div className="card-header">
            <h3 className="card-title">Recorded decisions</h3>
            <span className="num text-muted">{examples.data.count}</span>
          </div>
          <Table caption="Recorded decisions">
            <thead>
              <tr>
                <Th>Line</Th>
                <Th style={{ width: 190 }}>Security field</Th>
                <Th style={{ width: 200 }}>Outcome</Th>
                <Th style={{ width: 150 }}>Confirmed by</Th>
                <Th style={{ width: 90 }}>Seq</Th>
              </tr>
            </thead>
            <tbody>
              {examples.data.examples.map((example) => (
                <tr key={example.example_id}>
                  <Td className="mono">{example.line}</Td>
                  <Td className="mono">{example.field ?? '—'}</Td>
                  <Td className="text-muted">{example.outcome.replace(/_/g, ' ')}</Td>
                  <Td>{example.confirmed_by}</Td>
                  <Td className="num text-muted">{example.audit_seq ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
    </div>
  );
}
