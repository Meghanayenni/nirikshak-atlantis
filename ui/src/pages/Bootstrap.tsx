/**
 * Unrecognised vendor — describe a platform no pack knows, from one of its files.
 *
 * The page proposes only what the backend derived from the file (ADR 0067): a
 * syntax mode with the counts behind it, a comment style, plain structural
 * facts, and fingerprint lines no known platform uses. It never proposes a
 * vendor or platform name: that is the design, not a gap in it. The
 * administrator names the platform.
 *
 * Every derived value is editable, not merely confirmable. There is no single
 * "is this right?" gate: the mode is a choice with the derived one selected and
 * its evidence still visible; a fingerprint is unticked until ticked, and not
 * ticking is how one is rejected; a line of the administrator's own can stand
 * in for all of them. Spacious on purpose (DEVELOPER_GUIDE.md §10): what is created here
 * decides which files the new pack claims.
 */
import { useMemo, useState } from 'react';
import { Link, Navigate, useParams } from 'react-router-dom';

import { PageHeader } from '@/components/ui/Page';
import { Button, Card, CardHeader, Field, Table, Td, Th } from '@/components/ui/Primitives';
import { ErrorState, Loading } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/useToast';
import { runAudit } from '@/services/audits';
import { createBootstrap, discardBootstrap, getBootstrap } from '@/services/training';
import type { BootstrapAssessment, BootstrapResult } from '@/types/api';

const NAME = /^[a-z][a-z0-9-]{1,31}$/;

const MODE_LABELS: Record<string, string> = {
  indent: 'Indentation — nesting by leading whitespace',
  brace: 'Braces — nesting by { }',
  set_path: 'Flat set paths — one `set …` line per statement',
  xml: 'XML',
  json: 'JSON',
};
const ALL_MODES = ['indent', 'brace', 'set_path', 'xml', 'json'];

export function BootstrapPage() {
  const { fileId = '' } = useParams();
  const { isAdmin } = useAuth();
  const assessment = useApi(
    () => (isAdmin ? getBootstrap(fileId) : Promise.resolve(null)),
    [fileId, isAdmin],
  );
  const [created, setCreated] = useState<BootstrapResult | null>(null);

  if (!isAdmin) return <Navigate to="/devices" replace />;

  return (
    <>
      <PageHeader
        title="Unrecognised vendor"
        subtitle="Describe a platform no pack knows, from what this file shows"
      />
      {assessment.loading && <Loading label="Reading the file" />}
      {assessment.error && (
        <ErrorState message={assessment.error} onRetry={assessment.reload} />
      )}
      {assessment.data && (
        <div className="mx-auto max-w-3xl space-y-5">
          {created ? (
            <Created
              fileId={fileId}
              result={created}
              onDiscarded={() => {
                setCreated(null);
                assessment.reload();
              }}
            />
          ) : (
            <Assessment
              data={assessment.data}
              onCreated={setCreated}
              onDiscarded={assessment.reload}
            />
          )}
        </div>
      )}
    </>
  );
}

function Assessment({
  data,
  onCreated,
  onDiscarded,
}: {
  data: BootstrapAssessment;
  onCreated: (result: BootstrapResult) => void;
  onDiscarded: () => void;
}) {
  return (
    <>
      <Card>
        <CardHeader title={data.filename || data.file_id} subtitle="What detection found" />
        <div className="space-y-3 px-5 py-4">
          <Field label="Detection">{data.detection.explanation}</Field>
          <Field label="Corpus split">{data.split_check}</Field>
        </div>
      </Card>

      {data.eligible ? (
        <BootstrapForm data={data} onCreated={onCreated} />
      ) : (
        <NotEligible data={data} onDiscarded={onDiscarded} />
      )}
    </>
  );
}

function NotEligible({
  data,
  onDiscarded,
}: {
  data: BootstrapAssessment;
  onDiscarded: () => void;
}) {
  return (
    <section
      aria-label="Not eligible"
      className="rounded border border-dashed border-unknown-br bg-unknown-bg px-5 py-4"
    >
      <p className="label mb-1 text-unknown">Bootstrap is not available for this file</p>
      <p className="text-ink-2">{data.reason}</p>
      {data.bootstrapped_platform && (
        <div className="mt-3 space-y-2">
          <p className="text-ink-2">
            It is detected as <span className="font-mono">{data.bootstrapped_platform}</span>, a
            platform bootstrapped here.
          </p>
          <DiscardButton packId={data.bootstrapped_platform} onDiscarded={onDiscarded} />
        </div>
      )}
    </section>
  );
}

function BootstrapForm({
  data,
  onCreated,
}: {
  data: BootstrapAssessment;
  onCreated: (result: BootstrapResult) => void;
}) {
  const [mode, setMode] = useState(data.syntax.derived);
  const [comment, setComment] = useState(data.comments.prefix ?? '');
  const [chosen, setChosen] = useState<string[]>([]);
  const [pasted, setPasted] = useState<string[]>([]);
  const [draftLine, setDraftLine] = useState('');
  const [vendor, setVendor] = useState('');
  const [platform, setPlatform] = useState('');
  const create = useMutation(createBootstrap);

  const [min, max] = data.fingerprints.choose;
  const count = chosen.length + pasted.length;
  const namesValid = NAME.test(vendor) && NAME.test(platform);
  const modeImplemented = data.syntax.implemented_modes.includes(mode);
  const ready = namesValid && count >= min && count <= max && modeImplemented && !create.pending;

  function toggle(stem: string) {
    setChosen((current) =>
      current.includes(stem) ? current.filter((s) => s !== stem) : [...current, stem],
    );
  }

  async function submit() {
    const result = await create.run({
      file_id: data.file_id,
      vendor,
      os_family: platform,
      syntax_mode: mode,
      fingerprints: chosen,
      pasted_lines: pasted,
      comment_prefixes: comment ? [comment] : [],
    });
    if (result) onCreated(result);
  }

  return (
    <>
      <Card>
        <CardHeader title="1 · Syntax" subtitle="How this file expresses hierarchy" />
        <div className="space-y-3 px-5 py-4">
          <div>
            <p className="label mb-1">Derived from the file</p>
            <p className="font-medium text-ink">{MODE_LABELS[data.syntax.derived] ?? data.syntax.derived}</p>
            <ul aria-label="Syntax evidence" className="mt-1 list-disc pl-5 text-ink-2">
              {data.syntax.evidence.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>
          <label className="block">
            <span className="label mb-1 block">Syntax mode for the new pack</span>
            <select
              aria-label="Syntax mode"
              value={mode}
              onChange={(event) => setMode(event.target.value)}
              className="rounded border border-border-strong bg-paper px-2 py-1.5"
            >
              {ALL_MODES.map((option) => (
                <option
                  key={option}
                  value={option}
                  disabled={!data.syntax.implemented_modes.includes(option)}
                >
                  {MODE_LABELS[option]}
                  {data.syntax.implemented_modes.includes(option) ? '' : ' — declared, not implemented'}
                </option>
              ))}
            </select>
          </label>
          {mode !== data.syntax.derived && (
            <p className="text-ink-2">
              You chose <span className="font-mono">{mode}</span>; the file reads as{' '}
              <span className="font-mono">{data.syntax.derived}</span> for the reasons above.
            </p>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader title="2 · Structure" subtitle="Plain facts, as counted" />
        <div className="space-y-3 px-5 py-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Lines">{data.structure.total_lines}</Field>
            <Field label="Content lines">{data.structure.content_lines}</Field>
            <Field label="Comment lines">{data.structure.comment_lines}</Field>
            <Field label="Indented lines">{data.structure.indented_lines}</Field>
            <Field label="Deepest nesting">{data.structure.max_depth ?? '—'}</Field>
            <Field label="Block headers">{data.structure.block_headers.length}</Field>
          </div>
          {data.structure.section_path_lines > 0 && (
            <p className="text-ink-2">
              {data.structure.section_path_lines} lines at column zero begin with “/”, and no line
              is indented. If those lines open sections, no syntax mode here scopes what follows
              them: those lines will be read without their section.
            </p>
          )}
          <label className="block">
            <span className="label mb-1 block">Comment prefix</span>
            <input
              aria-label="Comment prefix"
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              className="w-24 rounded border border-border-strong bg-paper px-2 py-1.5 font-mono"
            />
            <span className="ml-2 text-muted">
              Counted:{' '}
              {Object.entries(data.comments.counts)
                .map(([prefix, n]) => `${prefix} ×${n}`)
                .join(', ') || 'none'}
            </span>
          </label>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="3 · Fingerprints"
          subtitle={`Choose ${min}–${max} lines that identify this platform. Not ticking one rejects it.`}
        />
        <div className="space-y-3 px-5 py-4">
          <Table caption="Candidate fingerprints">
            <thead>
              <tr>
                <Th style={{ width: 40 }}>
                  <span className="sr-only">Use</span>
                </Th>
                <Th>Line</Th>
                <Th>Becomes the signature</Th>
                <Th style={{ width: 80 }}>Line no.</Th>
              </tr>
            </thead>
            <tbody>
              {data.fingerprints.candidates.map((candidate) => (
                <tr key={candidate.stem}>
                  <Td>
                    <input
                      type="checkbox"
                      aria-label={`Use ${candidate.stem}`}
                      checked={chosen.includes(candidate.stem)}
                      onChange={() => toggle(candidate.stem)}
                    />
                  </Td>
                  <Td className="font-mono">{candidate.example}</Td>
                  <Td className="font-mono text-ink-2">{candidate.pattern}</Td>
                  <Td className="num">{candidate.line_number}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <p className="text-muted">
            {data.fingerprints.excluded_as_used_elsewhere} other line stems were set aside because
            a known platform already uses them.
          </p>
          <div>
            <label className="block">
              <span className="label mb-1 block">None of these — use a line of my own</span>
              <input
                aria-label="Your own fingerprint line"
                value={draftLine}
                onChange={(event) => setDraftLine(event.target.value)}
                placeholder="A line from this file, exactly as it appears at column zero"
                className="w-full rounded border border-border-strong bg-paper px-2 py-1.5 font-mono"
              />
            </label>
            <Button
              className="mt-2"
              disabled={!draftLine.trim() || pasted.includes(draftLine.trim())}
              onClick={() => {
                setPasted((current) => [...current, draftLine.trim()]);
                setDraftLine('');
              }}
            >
              Add this line
            </Button>
            {pasted.length > 0 && (
              <ul aria-label="Your own lines" className="mt-2 space-y-1">
                {pasted.map((line) => (
                  <li key={line} className="flex items-center gap-2">
                    <span className="font-mono">{line}</span>
                    <Button
                      variant="ghost"
                      onClick={() => setPasted((current) => current.filter((l) => l !== line))}
                    >
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <p className="num text-ink-2">
            {count} chosen · {min}–{max} required
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader title="4 · Name the platform" subtitle="Yours to give. NIRIKSHAK proposes none." />
        <div className="grid gap-4 px-5 py-4 sm:grid-cols-2">
          <label className="block">
            <span className="label mb-1 block">Vendor</span>
            <input
              aria-label="Vendor"
              value={vendor}
              onChange={(event) => setVendor(event.target.value.trim())}
              className="w-full rounded border border-border-strong bg-paper px-2 py-1.5 font-mono"
            />
          </label>
          <label className="block">
            <span className="label mb-1 block">Platform</span>
            <input
              aria-label="Platform"
              value={platform}
              onChange={(event) => setPlatform(event.target.value.trim())}
              className="w-full rounded border border-border-strong bg-paper px-2 py-1.5 font-mono"
            />
          </label>
          <p className="text-muted sm:col-span-2">
            Lower-case letters, digits and hyphens, 2–32 characters. A name that already has a pack
            is refused.
          </p>
        </div>
      </Card>

      {create.error && (
        <div role="alert" className="rounded border border-unknown-br bg-unknown-bg px-4 py-3">
          <p className="label">Not created — nothing was written</p>
          <p className="mt-0.5 text-ink-2">{create.error}</p>
        </div>
      )}

      <div className="flex justify-end">
        <Button variant="primary" disabled={!ready} onClick={submit}>
          {create.pending ? 'Creating…' : 'Create platform and re-detect'}
        </Button>
      </div>
    </>
  );
}

function Created({
  fileId,
  result,
  onDiscarded,
}: {
  fileId: string;
  result: BootstrapResult;
  onDiscarded: () => void;
}) {
  const { push } = useToast();
  const audit = useMutation(runAudit);
  const [audited, setAudited] = useState(false);
  const detected = result.detection.outcome === 'detected';

  const weights = useMemo(
    () => result.detect.map((d) => `${d.pattern}  (weight ${d.weight})`),
    [result.detect],
  );

  return (
    <Card>
      <CardHeader
        title={`${result.pack_id} ${result.pack_version}`}
        subtitle="Created and active. Detection signatures only — no field is read yet."
      />
      <div className="space-y-4 px-5 py-4">
        <Field label="Re-detection">{result.detection.explanation}</Field>
        <Field label="Syntax mode">
          {result.syntax_mode}
          {result.syntax_mode !== result.syntax_mode_derived &&
            ` (derived: ${result.syntax_mode_derived})`}
        </Field>
        <div>
          <p className="label mb-1">Detection signatures</p>
          <ul className="space-y-0.5 font-mono text-ink-2">
            {weights.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
        {result.also_matches.length > 0 && (
          <p className="text-ink-2">
            {result.also_matches.length} other stored file(s) would also be claimed by this pack
            when next uploaded.
          </p>
        )}
        <p className="text-ink-2">{result.next}</p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="primary"
            disabled={!detected || audit.pending || audited}
            onClick={async () => {
              const outcome = await audit.run(fileId, []);
              if (outcome) {
                setAudited(true);
                push(
                  'success',
                  'First audit complete',
                  `${outcome.residue_lines} lines are in the review queue.`,
                );
              }
            }}
          >
            {audit.pending ? 'Auditing…' : audited ? 'Audited' : 'Run first audit'}
          </Button>
          <Link to={`/devices/${fileId}`} className="self-center text-accent underline">
            Open the device, then its Needs review tab
          </Link>
        </div>
        {audit.error && <p className="text-ink-2">{audit.error}</p>}
        <DiscardButton packId={result.pack_id} onDiscarded={onDiscarded} />
      </div>
    </Card>
  );
}

function DiscardButton({ packId, onDiscarded }: { packId: string; onDiscarded: () => void }) {
  const { push } = useToast();
  const discard = useMutation(discardBootstrap);
  const [confirming, setConfirming] = useState(false);

  if (!confirming) {
    return (
      <Button variant="ghost" onClick={() => setConfirming(true)}>
        Discard and start over
      </Button>
    );
  }
  return (
    <div role="group" aria-label="Confirm discard" className="space-y-2 rounded border border-border px-4 py-3">
      <p className="text-ink-2">
        Remove every version of <span className="font-mono">{packId}</span>, its activation, and
        any mappings compiled into it. Its files return to undetected. Recorded decisions stay in
        the audit trail.
      </p>
      <div className="flex gap-2">
        <Button
          variant="danger"
          disabled={discard.pending}
          onClick={async () => {
            const result = await discard.run(packId);
            if (result) {
              push('info', 'Discarded', `${result.versions_removed.length} version(s) removed.`);
              onDiscarded();
            }
          }}
        >
          {discard.pending ? 'Discarding…' : `Discard ${packId}`}
        </Button>
        <Button variant="ghost" onClick={() => setConfirming(false)}>
          Keep it
        </Button>
      </div>
      {discard.error && <p className="text-ink-2">{discard.error}</p>}
    </div>
  );
}
