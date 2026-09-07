/**
 * Vendor packs — one box per platform, and inside it, two kinds of knowledge.
 *
 * Rule 5 says packs are data. This is the screen where an administrator reads
 * that data back, adds to it, and takes things out of it again.
 *
 * The split down the middle of a pack detail is the point of the screen:
 *
 *   **Built-in** — shipped with the repository, authored against a real corpus
 *   file, reviewed like any other code. Read-only here. Removing one is a commit
 *   somebody reviews, not a button, and the backend refuses it either way.
 *
 *   **Human-verified** — what an administrator confirmed. Every one of these is
 *   a mapping somebody put their name to, and any of them can be replaced or
 *   withdrawn later.
 *
 * The distinction is not cosmetic. A built-in pattern was verified against a
 * corpus; a human-verified one was verified by a person at a moment, and the row
 * says which person and which moment. Presenting them in one undifferentiated
 * list would lose the only thing that tells an operator how far to trust a row.
 *
 * **Creating and withdrawing take effect immediately.** Activation clears the
 * pack cache, so the next audit in the same process parses with the new pack —
 * asserted end to end in `tests/integration/test_admin_authored_mappings.py`,
 * which is what earns this screen the right to offer the buttons at all. Had
 * activation needed a restart, an interface offering an edit that silently did
 * not apply would be worse than one offering nothing.
 *
 * Nothing here deletes. Withdrawing drafts a new pack version without the
 * pattern; the version that held it stays on disk, and the confirmation that
 * produced it is untouched — a decision an administrator made is an event that
 * happened, and unlearning a mapping is not the same act as pretending nobody
 * ever confirmed it.
 */
import { Boxes, ChevronLeft, Copy, Pencil, Plus, Trash2 } from 'lucide-react';
import { useMemo, useState } from 'react';

import { MappingForm } from '@/components/packs/MappingForm';
import { ContextMenu, type MenuAnchor } from '@/components/ui/ContextMenu';
import { PageHeader } from '@/components/ui/Page';
import { Button, Card, CardHeader, Table, Td, Th } from '@/components/ui/Primitives';
import { BlockedState, EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/useToast';
import { ApiError } from '@/services/api';
import { retireMapping } from '@/services/mappings';
import { listPacks } from '@/services/packs';
import { listExamples } from '@/services/training';
import type { PackPattern, VendorPackSummary } from '@/types/api';
import { humanise, platformLabel } from '@/utils/format';

/** The wire value of `PatternSource.ADMIN_TRAINED`. Underscore, not hyphen. */
const ADMIN_TRAINED = 'admin_trained';

interface Authorship {
  confirmedBy: string | null;
  line: string | null;
}

async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------
   The index: one box per platform.
   ------------------------------------------------------------------------- */

function PackCard({ pack, onOpen }: { pack: VendorPackSummary; onOpen: () => void }) {
  const builtin = pack.pattern_count - pack.admin_trained_count;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="card group flex flex-col gap-4 p-5 text-left transition-colors
                 hover:border-border-strong hover:bg-surface focus-visible:border-accent"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-lg font-semibold tracking-tight text-ink">
            {platformLabel(pack.vendor, pack.os_family)}
          </p>
          <p className="mono mt-0.5 text-muted">{pack.pack_id}</p>
        </div>
        <span
          className="inline-flex h-[22px] shrink-0 items-center gap-1 rounded border
                     border-border-strong bg-surface-2 px-1.5 text-micro font-medium text-ink"
        >
          <Boxes className="h-3 w-3" aria-hidden="true" />
          {pack.pack_version}
        </span>
      </div>

      {/*
        Two counts, weighted differently. Human-verified is the number that
        changes on this screen, so it carries the ink; built-in recedes.
      */}
      <div className="flex items-end gap-6">
        <div>
          <p className="num text-2xl font-semibold text-ink">{pack.admin_trained_count}</p>
          <p className="text-micro uppercase tracking-wider text-muted">human-verified</p>
        </div>
        <div>
          <p className="num text-2xl text-ink-2">{builtin}</p>
          <p className="text-micro uppercase tracking-wider text-muted">built-in</p>
        </div>
      </div>

      <p className="text-muted group-hover:text-ink-2">
        {pack.pattern_count === 0
          ? 'Detection only — this platform is recognised, but nothing is read from it yet.'
          : `Reads ${pack.pattern_count} field${pack.pattern_count === 1 ? '' : 's'} from a configuration.`}
      </p>
    </button>
  );
}

/* -------------------------------------------------------------------------
   One mapping row, shared by both sections.
   ------------------------------------------------------------------------- */

function MappingRow({
  pattern,
  authorship,
  actions,
  onContextMenu,
}: {
  pattern: PackPattern;
  authorship?: Authorship;
  actions?: React.ReactNode;
  onContextMenu?: (event: React.MouseEvent) => void;
}) {
  return (
    <tr onContextMenu={onContextMenu} className={onContextMenu ? 'hover:bg-surface' : undefined}>
      <Td>
        <span className="font-medium text-ink">{humanise(pattern.field)}</span>
        <span className="mono block text-muted">{pattern.id}</span>
      </Td>
      <Td>
        <code className="mono block break-all text-ink">{pattern.pattern}</code>
        {pattern.examples.length > 0 && (
          <span className="mono mt-1 block break-all text-muted">from: {pattern.examples[0]}</span>
        )}
        {pattern.scope_block.length > 0 && (
          <span className="mono mt-1 block break-all text-muted">
            scope: {pattern.scope_block.join(' › ')}
          </span>
        )}
      </Td>
      <Td>
        <span className="mono whitespace-nowrap text-ink-2">
          {pattern.capture} as {pattern.cast}
        </span>
        {authorship?.confirmedBy && (
          <span className="mt-1 block text-micro text-muted">
            by {authorship.confirmedBy}
            {pattern.audit_seq !== null && (
              <>
                {' · audit #'}
                <span className="num">{pattern.audit_seq}</span>
              </>
            )}
          </span>
        )}
      </Td>
      {actions !== undefined && <Td className="whitespace-nowrap">{actions}</Td>}
    </tr>
  );
}

/* -------------------------------------------------------------------------
   The page.
   ------------------------------------------------------------------------- */

export function VendorPacksPage() {
  const { isAdmin } = useAuth();
  const { push } = useToast();

  const packs = useApi(() => (isAdmin ? listPacks() : Promise.resolve(null)), [isAdmin]);
  const examples = useApi(() => (isAdmin ? listExamples(500) : Promise.resolve(null)), [isAdmin]);

  const [openPackId, setOpenPackId] = useState<string | null>(null);
  const [menu, setMenu] = useState<MenuAnchor | null>(null);
  const [form, setForm] = useState<
    null | { mode: 'create' } | { mode: 'edit'; pattern: PackPattern; line: string }
  >(null);
  const [pendingWithdraw, setPendingWithdraw] = useState<PackPattern | null>(null);
  const [reason, setReason] = useState('');

  const withdraw = useMutation(retireMapping);

  const restricted = !isAdmin || (packs.cause instanceof ApiError && packs.cause.isForbidden);
  const loading = packs.loading || examples.loading;

  /** Who confirmed which mapping, joined from the recorded decisions. */
  const authorship = useMemo(() => {
    const map = new Map<string, Authorship>();
    for (const example of examples.data?.examples ?? []) {
      map.set(example.example_id, { confirmedBy: example.confirmed_by, line: example.line });
    }
    return map;
  }, [examples.data]);

  const activePacks = useMemo(
    () => (packs.data?.packs ?? []).filter((pack) => pack.is_active),
    [packs.data],
  );

  const openPack = activePacks.find((pack) => pack.pack_id === openPackId) ?? null;

  /** Every version of the open platform, newest first. */
  const lineage = useMemo(
    () => (packs.data?.packs ?? []).filter((pack) => pack.pack_id === openPackId),
    [packs.data, openPackId],
  );

  const builtinPatterns = openPack?.patterns.filter((p) => p.source !== ADMIN_TRAINED) ?? [];
  const trainedPatterns = openPack?.patterns.filter((p) => p.source === ADMIN_TRAINED) ?? [];

  function authorshipFor(pattern: PackPattern): Authorship | undefined {
    return pattern.training_example_id ? authorship.get(pattern.training_example_id) : undefined;
  }

  function lineFor(pattern: PackPattern): string {
    return authorshipFor(pattern)?.line ?? pattern.examples[0] ?? '';
  }

  async function confirmWithdraw() {
    if (!pendingWithdraw || !openPack) return;
    const result = await withdraw.run(
      openPack.pack_id,
      pendingWithdraw.id,
      reason.trim() || undefined,
    );
    if (result) {
      push(
        'success',
        'Mapping withdrawn',
        `${openPack.pack_id} is now ${result.pack_version}. Version ${
          result.previous_version ?? openPack.pack_version
        } is still on disk.`,
      );
      setPendingWithdraw(null);
      setReason('');
      packs.reload();
    } else if (withdraw.error) {
      push('error', 'Withdrawal refused', withdraw.error);
    }
  }

  function openRowMenu(event: React.MouseEvent, pattern: PackPattern) {
    event.preventDefault();
    setMenu({
      x: event.clientX,
      y: event.clientY,
      items: [
        {
          id: 'copy-pattern',
          label: 'Copy the expression',
          icon: Copy,
          onSelect: async () => {
            const ok = await copy(pattern.pattern);
            push(ok ? 'success' : 'error', ok ? 'Expression copied' : 'Clipboard unavailable');
          },
        },
        {
          id: 'edit',
          label: 'Replace this mapping…',
          icon: Pencil,
          disabled: !pattern.withdrawable,
          hint: 'Built-in patterns are repository content.',
          onSelect: () => setForm({ mode: 'edit', pattern, line: lineFor(pattern) }),
        },
        {
          id: 'withdraw',
          label: 'Withdraw from the pack…',
          icon: Trash2,
          destructive: true,
          disabled: !pattern.withdrawable,
          hint: 'Built-in patterns are repository content.',
          onSelect: () => {
            setReason('');
            setPendingWithdraw(pattern);
          },
        },
      ],
    });
  }

  if (restricted) {
    return (
      <>
        <PageHeader title="Vendor packs" subtitle="How each platform's syntax is read" />
        <Card>
          <BlockedState
            title="This account cannot read the pack inventory"
            reason={
              'Vendor packs are administrator-only at the backend. A confirmation changes how ' +
              'every future device of that platform is parsed, for everyone, so reading and ' +
              'changing those mappings is restricted to an administrator.'
            }
          />
        </Card>
      </>
    );
  }

  /* ----------------------------------------------------------------------
     Index.
     ---------------------------------------------------------------------- */

  if (!openPack) {
    return (
      <>
        <PageHeader
          title="Vendor packs"
          subtitle="One box per platform. Open one to see what it reads, and to teach it more."
        />

        {loading && (
          <Card>
            <SkeletonRows rows={4} cols={3} />
          </Card>
        )}
        {packs.error && !loading && (
          <Card>
            <ErrorState message={packs.error} onRetry={packs.reload} />
          </Card>
        )}
        {!loading && !packs.error && activePacks.length === 0 && (
          <Card>
            <EmptyState title="No active packs" detail="Nothing can be parsed without one." />
          </Card>
        )}

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {activePacks.map((pack) => (
            <PackCard key={pack.pack_id} pack={pack} onOpen={() => setOpenPackId(pack.pack_id)} />
          ))}
        </div>
      </>
    );
  }

  /* ----------------------------------------------------------------------
     Detail: one platform, two kinds of knowledge.
     ---------------------------------------------------------------------- */

  return (
    <>
      <button
        type="button"
        onClick={() => setOpenPackId(null)}
        className="mb-3 inline-flex items-center gap-1 text-ink-2 hover:text-ink"
      >
        <ChevronLeft className="h-4 w-4" aria-hidden="true" />
        All vendor packs
      </button>

      <PageHeader
        title={platformLabel(openPack.vendor, openPack.os_family)}
        subtitle={`Active version ${openPack.pack_version} · reads ${openPack.pattern_count} field${
          openPack.pattern_count === 1 ? '' : 's'
        }`}
      />

      <div className="space-y-4">
        {/* --- Human-verified, first: it is what changes here. ------------- */}
        <Card>
          <CardHeader
            title="Human-verified mappings"
            subtitle="Confirmed by an administrator. Replaceable and withdrawable."
            actions={
              <Button variant="primary" onClick={() => setForm({ mode: 'create' })}>
                <Plus className="h-4 w-4" aria-hidden="true" />
                Add mapping
              </Button>
            }
          />

          {trainedPatterns.length === 0 ? (
            <EmptyState
              title="Nothing confirmed yet for this platform"
              detail="Add a mapping to teach NIRIKSHAK syntax it does not recognise. It takes effect on the next audit, with no restart."
            />
          ) : (
            <>
              <Table caption="Mappings confirmed by an administrator">
                <thead>
                  <tr>
                    <Th style={{ width: 210 }}>Field</Th>
                    <Th>Expression</Th>
                    <Th style={{ width: 180 }}>Reads</Th>
                    <Th style={{ width: 170 }}>
                      <span className="sr-only">Actions</span>
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {trainedPatterns.map((pattern) => (
                    <MappingRow
                      key={pattern.id}
                      pattern={pattern}
                      authorship={authorshipFor(pattern)}
                      onContextMenu={(event) => openRowMenu(event, pattern)}
                      actions={
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            onClick={() =>
                              setForm({ mode: 'edit', pattern, line: lineFor(pattern) })
                            }
                          >
                            <Pencil className="h-4 w-4" aria-hidden="true" />
                            Replace
                          </Button>
                          <Button
                            variant="ghost"
                            className="text-fail hover:bg-fail-bg"
                            aria-label="Withdraw this mapping"
                            onClick={() => {
                              setReason('');
                              setPendingWithdraw(pattern);
                            }}
                          >
                            <Trash2 className="h-4 w-4" aria-hidden="true" />
                          </Button>
                        </div>
                      }
                    />
                  ))}
                </tbody>
              </Table>
              <p className="border-t border-border px-4 py-3 text-micro leading-relaxed text-muted">
                Right-click a row for the same actions. Replacing records a new decision and
                withdraws the old mapping — it is never an edit in place, so the version holding
                the old expression stays on disk and an audit run under it can still be explained.
              </p>
            </>
          )}
        </Card>

        {/* --- Built-in: read-only. ---------------------------------------- */}
        <Card>
          <CardHeader
            title="Built-in mappings"
            subtitle="Shipped with the repository and authored against a real corpus file."
          />

          {builtinPatterns.length === 0 ? (
            <EmptyState
              title="This platform is detected but not parsed"
              detail="No built-in pattern ships for it. A field with no pattern stays UNKNOWN rather than being guessed."
            />
          ) : (
            <>
              <Table caption="Mappings shipped with the repository">
                <thead>
                  <tr>
                    <Th style={{ width: 210 }}>Field</Th>
                    <Th>Expression</Th>
                    <Th style={{ width: 180 }}>Reads</Th>
                  </tr>
                </thead>
                <tbody>
                  {builtinPatterns.map((pattern) => (
                    <MappingRow key={pattern.id} pattern={pattern} />
                  ))}
                </tbody>
              </Table>
              <p className="border-t border-border px-4 py-3 text-micro leading-relaxed text-muted">
                These are repository content. Changing one is a reviewed commit, not an action in
                this interface, and the backend refuses to withdraw them here.
              </p>
            </>
          )}
        </Card>

        {/* --- The lineage. ------------------------------------------------ */}
        <Card>
          <CardHeader
            title="Version history"
            subtitle="Every version is kept, so what this pack read and when stays answerable."
          />
          <Table caption="Versions of this pack on disk">
            <thead>
              <tr>
                <Th style={{ width: 130 }}>Version</Th>
                <Th style={{ width: 120 }}>Status</Th>
                <Th style={{ width: 110 }}>Origin</Th>
                <Th style={{ width: 120 }}>Patterns</Th>
                <Th>Checksum</Th>
              </tr>
            </thead>
            <tbody>
              {lineage.map((version) => (
                <tr key={`${version.pack_version}@${version.origin}`}>
                  <Td className="mono">
                    {version.pack_version}
                    {version.parent_version && (
                      <span className="block text-muted">from {version.parent_version}</span>
                    )}
                  </Td>
                  <Td>
                    {version.is_active ? (
                      <span
                        className="inline-flex h-[22px] items-center gap-1 rounded border
                                   border-border-strong bg-surface-2 px-1.5 text-micro
                                   font-medium text-ink"
                      >
                        <Boxes className="h-3 w-3" aria-hidden="true" />
                        active
                      </span>
                    ) : (
                      <span className="text-muted">{version.status}</span>
                    )}
                  </Td>
                  <Td className="text-muted">{version.origin}</Td>
                  <Td className="num text-ink-2">{version.pattern_count}</Td>
                  <Td className="mono break-all text-muted">{version.checksum ?? 'not stamped'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      </div>

      <ContextMenu anchor={menu} onClose={() => setMenu(null)} />

      {form && packs.data && (
        <MappingForm
          vendor={openPack.vendor}
          osFamily={openPack.os_family}
          fields={packs.data.canonical_fields}
          casts={packs.data.casts}
          mode={form.mode}
          initial={
            form.mode === 'edit' ? { line: form.line, field: form.pattern.field } : undefined
          }
          onCancel={() => setForm(null)}
          onActivated={async ({ packVersion }) => {
            // A replacement is two halves, and the order matters. The new
            // mapping goes live first; the one it replaces comes out second. If
            // the withdrawal fails, the platform is left reading BOTH patterns —
            // visible on this screen and fixable in one click — rather than
            // reading neither, which is what the opposite order would risk.
            if (form.mode === 'edit') {
              const retired = await withdraw.run(
                openPack.pack_id,
                form.pattern.id,
                'replaced by a newer mapping',
              );
              if (!retired) {
                push(
                  'error',
                  'The replacement is live, but the old mapping is still there',
                  withdraw.error ??
                    'Withdraw it from the list once you have checked the replacement.',
                );
                setForm(null);
                packs.reload();
                return;
              }
            }
            push(
              'success',
              form.mode === 'edit' ? 'Mapping replaced' : 'Mapping activated',
              `${openPack.pack_id} is now ${packVersion}. The next audit uses it — no restart.`,
            );
            setForm(null);
            packs.reload();
          }}
        />
      )}

      {pendingWithdraw && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-ink/30 p-4 animate-fade-in"
          role="dialog"
          aria-modal="true"
          aria-label="Withdraw this mapping"
          onClick={(event) => {
            if (event.target === event.currentTarget) setPendingWithdraw(null);
          }}
        >
          <div className="card w-full max-w-xl p-5">
            <h2 className="card-title">Withdraw this mapping?</h2>
            <p className="mt-2 text-ink-2">
              {openPack.pack_id} will be drafted at a new version without{' '}
              <span className="mono text-ink">{pendingWithdraw.id}</span>, validated and activated.
              Configurations of this platform stop being read for{' '}
              <span className="text-ink">{humanise(pendingWithdraw.field)}</span> by this pattern,
              and the field becomes UNKNOWN unless another pattern reads it.
            </p>
            <pre className="mono mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded border border-border bg-surface p-3 text-ink">
              {pendingWithdraw.pattern}
            </pre>
            <p className="mt-3 text-micro leading-relaxed text-muted">
              Version {openPack.pack_version} stays on disk and can be rolled back to. The
              confirmation that produced this pattern is not touched — a decision somebody made is
              an event that happened.
            </p>

            <label className="mt-4 block">
              <span className="label">Reason (recorded in the audit chain)</span>
              <input
                type="text"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                maxLength={500}
                placeholder="Optional — why this mapping is no longer trusted"
                className="mt-1 h-9 w-full rounded border border-border bg-paper px-2"
              />
            </label>

            <div className="mt-5 flex justify-end gap-2">
              <Button onClick={() => setPendingWithdraw(null)} disabled={withdraw.pending}>
                Cancel
              </Button>
              <Button variant="danger" onClick={confirmWithdraw} disabled={withdraw.pending}>
                {withdraw.pending ? 'Withdrawing…' : 'Withdraw mapping'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
