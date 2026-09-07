/**
 * Teaching the system one mapping, in two steps.
 *
 *     describe  ->  compile  ->  READ THE REGEX  ->  activate
 *
 * The second step is not a formality and this dialog cannot skip it. DEVELOPER_GUIDE.md
 * §4 requires the generated pattern be shown to the administrator and be
 * editable before activation, because a pattern nobody read is one nobody can
 * vouch for — and this one will read every future configuration of the platform,
 * for everyone, until somebody withdraws it. The two backend calls stay two
 * calls for the same reason (decision D51).
 *
 * **The administrator says which token carries the value.** The compiler does
 * not guess, and neither does this form: the line is shown tokenised and the
 * value is chosen by clicking it. Whether the `2` in `ip ssh version 2` is the
 * value or part of the command name is a judgement only a person holds, and a
 * form that inferred it would be making that judgement silently.
 *
 * A line whose *presence* is the fact — `no ip http server` — captures nothing,
 * and the literal value the field takes is stated instead.
 *
 * §10 calls the training interface the deliberate exception to density: it is a
 * focused judgement task and should be spacious, one line at a time. A cramped
 * screen produces careless confirmations, and a careless confirmation enters a
 * vendor pack permanently.
 */
import { AlertCircle, ArrowLeft, Check, Loader2 } from 'lucide-react';
import { useMemo, useState } from 'react';

import { Button } from '@/components/ui/Primitives';
import { useMutation } from '@/hooks/useApi';
import { activateMapping, draftMapping } from '@/services/mappings';
import type { DraftResult } from '@/types/api';
import { humanise } from '@/utils/format';

export interface MappingFormProps {
  vendor: string;
  osFamily: string;
  fields: string[];
  casts: string[];
  /** Pre-filled when an existing mapping is being replaced. */
  initial?: {
    line: string;
    field: string;
  };
  /** What this dialog is doing, which changes only the wording. */
  mode: 'create' | 'edit';
  onCancel: () => void;
  onActivated: (result: { patternId: string; packVersion: string }) => void;
}

/** A guess at which token is the value, offered as a starting point only. */
function suggestToken(tokens: string[]): number | null {
  // The last token, when it is not obviously part of the command name. This is
  // a cursor position, not an inference: the administrator confirms or changes
  // it, and nothing is compiled from the guess alone.
  if (tokens.length < 2) return null;
  return tokens.length - 1;
}

export function MappingForm({
  vendor,
  osFamily,
  fields,
  casts,
  initial,
  mode,
  onCancel,
  onActivated,
}: MappingFormProps) {
  const [line, setLine] = useState(initial?.line ?? '');
  const [field, setField] = useState(initial?.field ?? fields[0] ?? '');
  const [cast, setCast] = useState('str');
  const [presenceOnly, setPresenceOnly] = useState(false);
  const [literalValue, setLiteralValue] = useState('true');
  const [valueToken, setValueToken] = useState<number | null>(null);
  const [touchedToken, setTouchedToken] = useState(false);

  const [draft, setDraft] = useState<DraftResult | null>(null);
  const [editedPattern, setEditedPattern] = useState('');

  const compile = useMutation(draftMapping);
  const activate = useMutation(activateMapping);

  const tokens = useMemo(() => line.trim().split(/\s+/).filter(Boolean), [line]);

  // Until the administrator picks one, offer a starting position.
  const effectiveToken = touchedToken ? valueToken : suggestToken(tokens);

  const canCompile =
    line.trim().length > 0 &&
    field.length > 0 &&
    (presenceOnly ? literalValue.trim().length > 0 : effectiveToken !== null);

  async function onCompile() {
    const result = await compile.run({
      vendor,
      osFamily,
      line: line.trim(),
      field,
      valueToken: presenceOnly ? null : effectiveToken,
      literalValue: presenceOnly ? literalValue.trim() : null,
      cast: presenceOnly ? 'bool' : cast,
    });
    if (result) {
      setDraft(result);
      setEditedPattern(result.pattern);
    }
  }

  async function onActivate() {
    if (!draft) return;

    // An edited expression goes back through the compiler, which re-validates
    // it. The interface never writes a regex straight into a pack.
    let target = draft;
    if (editedPattern.trim() !== draft.pattern) {
      const recompiled = await compile.run({
        vendor,
        osFamily,
        line: line.trim(),
        field,
        valueToken: presenceOnly ? null : effectiveToken,
        literalValue: presenceOnly ? literalValue.trim() : null,
        cast: presenceOnly ? 'bool' : cast,
        patternOverride: editedPattern.trim(),
      });
      if (!recompiled) return;
      target = recompiled;
      setDraft(recompiled);
    }

    const result = await activate.run(target);
    if (result) {
      onActivated({ patternId: target.pattern_id, packVersion: result.pack_version });
    }
  }

  const busy = compile.pending || activate.pending;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink/30 p-4
                 animate-fade-in sm:p-8"
      role="dialog"
      aria-modal="true"
      aria-label={mode === 'create' ? 'Add a mapping' : 'Replace this mapping'}
      onClick={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <div className="card w-full max-w-2xl">
        <header className="border-b border-border px-6 py-5">
          <h2 className="text-xl font-semibold tracking-tight text-ink">
            {mode === 'create' ? 'Teach a new mapping' : 'Replace this mapping'}
          </h2>
          <p className="mt-1 text-ink-2">
            {draft
              ? 'Read the expression before it goes live. It will read every future configuration of this platform.'
              : `What does this line mean on ${vendor} ${osFamily}?`}
          </p>
        </header>

        {/* ---------------------------------------------------------------
            Step one: what the line means.
            --------------------------------------------------------------- */}
        {!draft && (
          <div className="space-y-6 px-6 py-6">
            <label className="block">
              <span className="label">Configuration line</span>
              <p className="mb-1.5 text-muted">
                Exactly as it appears on the device, without leading indentation.
              </p>
              <input
                type="text"
                value={line}
                onChange={(event) => {
                  setLine(event.target.value);
                  setTouchedToken(false);
                }}
                placeholder="ip ssh version 2"
                autoFocus
                className="mono h-11 w-full rounded border border-border bg-paper px-3 text-ink"
              />
            </label>

            {tokens.length > 0 && !presenceOnly && (
              <div>
                <span className="label">Which token carries the value?</span>
                <p className="mb-2 text-muted">
                  Click it. NIRIKSHAK does not guess this — whether a number is the value or part
                  of the command name is yours to say.
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {tokens.map((token, index) => {
                    const chosen = effectiveToken === index;
                    return (
                      <button
                        key={`${token}-${index}`}
                        type="button"
                        onClick={() => {
                          setTouchedToken(true);
                          setValueToken(index);
                        }}
                        aria-pressed={chosen}
                        className={`mono h-9 rounded border px-2.5 transition-colors
                          ${
                            chosen
                              ? 'border-accent bg-accent-bg font-medium text-accent'
                              : 'border-border bg-paper text-ink-2 hover:bg-surface'
                          }`}
                      >
                        {token}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <label className="flex items-start gap-2.5">
              <input
                type="checkbox"
                checked={presenceOnly}
                onChange={(event) => setPresenceOnly(event.target.checked)}
                className="mt-1 h-4 w-4"
              />
              <span className="min-w-0">
                <span className="font-medium text-ink">
                  The line captures nothing; its presence is the fact
                </span>
                <span className="block text-muted">
                  For a directive like <span className="mono">no ip http server</span>, where there
                  is no value to read and the field simply becomes something.
                </span>
              </span>
            </label>

            <div className="grid gap-5 sm:grid-cols-2">
              <label className="block">
                <span className="label">Canonical field</span>
                <p className="mb-1.5 text-muted">What this line establishes.</p>
                <select
                  value={field}
                  onChange={(event) => setField(event.target.value)}
                  className="h-11 w-full rounded border border-border bg-paper px-2 text-ink"
                >
                  {fields.map((name) => (
                    <option key={name} value={name}>
                      {humanise(name)}
                    </option>
                  ))}
                </select>
              </label>

              {presenceOnly ? (
                <label className="block">
                  <span className="label">The field becomes</span>
                  <p className="mb-1.5 text-muted">The literal value, since nothing is read.</p>
                  <input
                    type="text"
                    value={literalValue}
                    onChange={(event) => setLiteralValue(event.target.value)}
                    className="mono h-11 w-full rounded border border-border bg-paper px-3"
                  />
                </label>
              ) : (
                <label className="block">
                  <span className="label">Read the value as</span>
                  <p className="mb-1.5 text-muted">How the captured token is typed.</p>
                  <select
                    value={cast}
                    onChange={(event) => setCast(event.target.value)}
                    className="h-11 w-full rounded border border-border bg-paper px-2 text-ink"
                  >
                    {casts.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </div>

            {compile.error && (
              <div className="flex items-start gap-2 rounded border border-fail-br bg-fail-bg p-3">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-fail" aria-hidden="true" />
                <p className="text-ink-2">{compile.error}</p>
              </div>
            )}
          </div>
        )}

        {/* ---------------------------------------------------------------
            Step two: read the expression. §4 — this step cannot be skipped.
            --------------------------------------------------------------- */}
        {draft && (
          <div className="space-y-5 px-6 py-6">
            <div>
              <span className="label">Generated expression</span>
              <p className="mb-1.5 text-muted">
                Tokenised, escaped, the value replaced with a capture, anchored at both ends. Edit
                it if it is wrong — an edited expression is re-validated, never trusted as typed.
              </p>
              <textarea
                value={editedPattern}
                onChange={(event) => setEditedPattern(event.target.value)}
                rows={2}
                spellCheck={false}
                className="mono w-full rounded border border-border bg-surface p-3 text-ink"
              />
            </div>

            <dl className="grid gap-4 sm:grid-cols-2">
              <div>
                <dt className="label">Reads into</dt>
                <dd className="text-ink">{humanise(draft.field)}</dd>
              </div>
              <div>
                <dt className="label">Captures</dt>
                <dd className="mono text-ink">
                  {draft.capture} as {draft.cast}
                </dd>
              </div>
              <div>
                <dt className="label">Pack version</dt>
                <dd className="mono text-ink">
                  {draft.pack_id} {draft.pack_version}
                </dd>
              </div>
              <div>
                <dt className="label">Scope</dt>
                <dd className="mono text-ink">
                  {draft.scope.length > 0 ? draft.scope.join(' › ') : 'root level'}
                </dd>
              </div>
            </dl>

            <div>
              <span className="label">Checked against</span>
              <ul className="mt-1 space-y-1">
                {draft.examples.map((example) => (
                  <li key={example} className="mono text-ink-2">
                    {example}
                  </li>
                ))}
              </ul>
              <p className="mt-1.5 text-micro text-muted">
                The pattern is run against its own example before it can be activated. One that
                does not match the line it came from cannot go live.
              </p>
            </div>

            <p className="text-micro leading-relaxed text-muted">
              Activating writes a new version of this vendor pack and makes it live immediately —
              no restart. The version before it stays on disk, so an audit already run can still be
              explained, and this mapping can be withdrawn later.
            </p>

            {(compile.error || activate.error) && (
              <div className="flex items-start gap-2 rounded border border-fail-br bg-fail-bg p-3">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-fail" aria-hidden="true" />
                <p className="text-ink-2">{compile.error ?? activate.error}</p>
              </div>
            )}
          </div>
        )}

        <footer className="flex items-center justify-between gap-3 border-t border-border px-6 py-4">
          <Button
            onClick={draft ? () => setDraft(null) : onCancel}
            disabled={busy}
            variant="ghost"
          >
            {draft ? (
              <>
                <ArrowLeft className="h-4 w-4" aria-hidden="true" />
                Back
              </>
            ) : (
              'Cancel'
            )}
          </Button>

          {draft ? (
            <Button variant="primary" onClick={onActivate} disabled={busy}>
              {busy ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <Check className="h-4 w-4" aria-hidden="true" />
              )}
              {busy ? 'Activating…' : 'Activate mapping'}
            </Button>
          ) : (
            <Button variant="primary" onClick={onCompile} disabled={!canCompile || busy}>
              {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {busy ? 'Compiling…' : 'Compile and review'}
            </Button>
          )}
        </footer>
      </div>
    </div>
  );
}
