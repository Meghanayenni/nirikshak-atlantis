# ADR 0067 — A platform described from its own file

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D167 (the system derives a new platform's structure from one of
  its files and never proposes its name), D168 (a pack may declare its syntax
  mode), D169 (a bootstrap is a stub pack through the existing lifecycle, decided
  by a dry run before anything is written), D170 (discard removes every version,
  the activation entry and the platform's residue), D171 (the demo fixture is
  MikroTik RouterOS, written from its documentation)
- **Affects:** `api/train/bootstrap.py` (new), `api/ingest/redetect.py` (new),
  `api/models/pack.py`, `api/parse/service.py`, `api/train/activation.py`,
  `api/ingest/pack_activation.py`, `api/train/errors.py`, `api/config.py`,
  `api/routers/training.py`, `api/routers/ingest.py`, `api/routers/audits.py`,
  `ui/src/pages/Bootstrap.tsx` (new), `ui/src/components/device/DeviceWorkspace.tsx`,
  `corpus/mikrotik/dev/edge-mt-01.rsc` (new), `corpus/MANIFEST.yaml`

## Context

The problem statement asks for coverage that expands without code changes. The
training loop delivers that for a platform that already has a pack: an unknown
line becomes a pattern. It could not start for a platform with none. Four facts,
established before design:

1. **The syntax mode was keyed to the platform.** `SYNTAX_MODE_BY_OS` is a code
   map; ADR 0043 let JunOS choose between its two known surfaces by one regex,
   and nothing more. An unknown `os_family` silently became INDENT.
2. **The loop's gate.** `compile_confirmation` refuses when `find_pack` finds no
   active pack — and earlier still, residue reaches the queue only from an audit,
   which needs a detected platform.
3. **A minimal pack** needs `vendor`, `os_family`, a semver version and a status,
   and a checksum once ACTIVE; detection and patterns may be empty. `validate`
   self-checks patterns (trivially, for none) and `activate` writes ACTIVE into
   the trained root and pins it in the activation record.
4. **The dead end.** Upload never refused: it stored the file with
   `detected_vendor = NULL`. The 409 came from `POST /compliance/audits`.

## D167 — structure from the file, a name from a person

The system proposes only what it can derive from the file, and says so on the
page before anything else. It never proposes a vendor or platform name: nothing
in a configuration states whose it is in a form this code can verify, and a name
offered from a model's training data would be an assertion about the input made
from outside it. No model is used anywhere in this feature.

What is derived, each with its evidence and each editable:

| Derived | How | Correction path |
| --- | --- | --- |
| Syntax mode | XML parse (lxml); balanced braces; ≥ half the lines begin `set `; otherwise indentation. Reported as counts. | A dropdown, derived value pre-selected, evidence kept visible; unimplemented modes shown and disabled |
| Comment style | Lines counted per prefix (`#`, `!`, `//`, `;`) | A text field |
| Structure | Line, blank, comment, content and indented counts; depth and block headers from the parser | Facts; displayed as-is |
| Fingerprints | Stems (up to three leading keywords, stopping at the first value) of column-zero lines, excluding any stem an active pack's examples or detection signatures use; longer stems first, then frequency | Unticked checkboxes — not ticking is the rejection — and a pasted line of the administrator's own, which must be a column-zero line of the file |
| Vendor, platform | Never derived | Free text, lower case, refused on collision |

A fingerprint becomes an anchored literal (`^/ip service$`), escaping only regex
metacharacters so an administrator can read it (DEVELOPER_GUIDE.md §4). A stem is capped
at three words, so two lines can share one — `/system ntp client` and
`/system ntp client servers` count as two occurrences of a stem whose signature
matches only the first. The displayed regex is exactly what is written.

## D168 — a pack may declare its syntax mode

`VendorPack.syntax_mode`, optional. `syntax_mode_for` honours it first; every
existing pack omits it and behaves as before. Without it a bootstrapped brace or
`set` platform would have been parsed as flat text without a word.

## D169 — a stub pack, decided before it is written

`POST /training/bootstrap` writes `vendor`, `os_family`, version 1.0.0, the
chosen syntax mode and comment prefix, and one detection signature per chosen
fingerprint, **no patterns** — through `validate` then `activate`, the lifecycle
every compiled pack uses. Weights are equal and sum to 1.0, so the source file
scores 1.0 and another file must carry most fingerprints to reach 0.60. The 0.60
threshold and 0.25 margin are unchanged.

Before anything is written, a dry run with the proposed pack added:

- the source file must be DETECTED as the new platform — otherwise refused with
  the detection's own explanation;
- no stored file already identified as another platform may change — otherwise
  refused, naming each file and its before/after.

Then the pack is activated, the cache cleared, and the file re-detected by the
same function ingestion uses (`api/ingest/redetect.py`), written to the same
columns. The training loop then runs unchanged: an audit records every line as
residue, and confirm → compile → activate produces 1.0.1.

**On D51's two steps.** Compiled patterns are drafted and activated in separate
calls so the regex can be reviewed. Here the review happens on the page: the GET
returns the exact regex each fingerprint becomes, deterministically, before the
POST. The stub reads no field, and the dry run guarantees it moves no identified
file.

Refusals: an evaluation or held-out file (matched by sha256 against the manifest,
path in `settings.corpus_manifest`); the held-out vendor's name; a platform that
already has a pack, shipped or trained; an AMBIGUOUS file (two known packs
competing — a third does not resolve it); a mode the parser does not implement.
Conflicts answer 409, malformed requests 422. A deployment built without the
corpus has no manifest, and the page says the split check had nothing to compare
against rather than implying it passed.

The audit route's 409 for an unidentified file stays a 409 — nothing can be
audited — but now names the bootstrap route. The upload response carries it for
any file no pack claims, and the device workspace links an administrator to the
page.

## D170 — discard and start over

`DELETE /training/bootstrap/{vendor}/{os_family}` refuses a shipped platform. For
a bootstrapped one it removes the activation-record entry first, then every
version file (drafts and compiled versions included) and the empty directory —
restoring the record if a deletion fails — clears the platform's residue, and
re-detects its files, which return to undetected. Recorded decisions stay in the
audit chain; the discard is chained as `PACK_ROLLED_BACK` with
`discarded: true`, the versions removed and the file count, rather than a new
action the audit schema would need a migration to accept.

## D171 — the demo fixture

`corpus/mikrotik/dev/edge-mt-01.rsc`, registered synthetic, dev split. Huawei VRP
was the first choice and could not be sourced: support.huawei.com refused direct
requests and its guide pages render empty without a browser. MikroTik's RouterOS
documentation (help.mikrotik.com) was fetched and read: *Configuration
Management* for the `/export` shape, *First Time Configuration* for the bridge,
addressing, input filter and hardening commands, *Identity*, *NTP*. The PAN-OS
holdout was not touched.

**No inferred line.** The first version of the fixture wrote the `/ip service`
section as `set telnet disabled=yes` (and the same for ftp, www, api): the
export form of the documented `/ip service disable telnet,ftp,www,api`. No
MikroTik page read — including *Securing your router* — prints that form; it
changed a documented command's verb into one the documentation does not show,
which is unsourced vendor syntax. Removed at review. The section is now the
three full-path commands *First Time Configuration* prints verbatim:
`/ip service disable telnet,ftp,www,api`, `/ip service set ssh port=2200`,
`/ip service set winbox address=192.168.88.0/24`. The other sections keep the
export shape, which *Configuration Management* documents with its own example
(`set 0 protocol=gre` run under `/ip ipsec policy` exports as that path line
followed by the `set` line): the command is unchanged, only its path moves to
the line above.

## What the demo shows, and one limit it exposes

Uploaded, the file is `no_signature_matched`. The page derives **indent** with
"no line is indented: every statement is read at the top level", comment `#`
(19 lines), 31 content lines, and 14 column-zero lines beginning `/` (eleven
section paths and the three full-path `/ip service` commands). Eight
fingerprints are offered; one stem was set aside as used by a known platform.
Bootstrapped with three, it detects at 1.0; an audit puts all 31 content lines
in the queue.

**The demo path is chosen so the limit below never shows.** It confirms
`/ip service disable telnet,ftp,www,api` (line 35) as `telnet_enabled` = false.
That line names its own path, sits at the top level (empty block path), and is
alone in its shape in the queue, so reading it without a section loses
nothing. It compiles 1.0.1, and the re-audit PASSes NRK-TELNET-001 citing
line 35.

**The limit.** A RouterOS export scopes its lines by a preceding `/section` line,
not by indentation. No implemented mode expresses that, so every line is read at
the top level without its section: `add address=192.0.2.10` under
`/system ntp client servers` and an `add address=…` under `/ip address` are the
same unscoped shape to the parser. The page says so whenever it counts such
lines, without naming a vendor. A section-scoped syntax mode would close it; it
is a parser change and is not made here.
