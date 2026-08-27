# ADR 0014 — Semantic ACL analysis, findings persistence, and a protected API

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P7
- **Decisions:** D20 (ACL analysis), D21 (constructed fixtures only), D22
  (separate result contract), D23 (findings persistence), D24 (unresolved is
  UNKNOWN), D25 (authentication and roles)
- **Defects addressed:** DEF-5 (fixed), OBS-2 (accepted, unchanged), DEF-3
  (still deferred)

## Context

P7 fills `api/analyse/` with the analysis the Concept Report describes: *"access
lists evaluated as interval logic over source, destination, protocol and port to
detect shadowed, redundant and overly permissive rules. This is computation, not
pattern matching."*

It also does two things the pipeline needed before anything could be shown to a
human: it persists findings, and it puts an authenticated boundary in front of
them.

## D20 — the analyser is built; the extractor is not

**The corpus contains no access lists.** Verified again at HEAD: searching every
file in every split for `access-list`, `access-group`, `ip access`, `firewall`,
`filter`, `security-policy`, `policy-map` and `class-map` returns nothing.

The phase splits along the same line P6 did:

- **Interval containment is computation.** Whether entry 40's range sits inside
  entry 20's does not depend on which vendor wrote either line, so the analyser
  is built and tested exhaustively against constructed `ACL` objects.
- **ACL extraction is parsing**, governed by the P4 provenance rule that every
  pattern example must appear verbatim in a development file. With zero ACL lines
  in the corpus, a pattern could be authored only from general vendor knowledge.
  **No ACL patterns were added to any pack**, and no claim of ACL parsing coverage
  is made anywhere.

The consequence is that `CSM.acls` is empty on every real device, so
`analysed_nothing` is true for all of them. That is reported rather than rendered
as a clean result: *"no access lists were found"* and *"the access lists were
fine"* would otherwise look identical, and only one of them is reassuring.

### The three observations, and what is deliberately not among them

| Kind | Meaning |
| --- | --- |
| `shadowed` | Fully covered by an earlier entry with the **opposite** action, so it can never fire |
| `redundant` | Fully covered by an earlier entry with the **same** action |
| `overly_permissive` | A permit with an unbounded match set — the `permit ip any any` shape |
| `undetermined` | Could not be analysed, and says why (D24) |

**Correlated entries — partial overlaps with different actions — are not
implemented.** They are a real maintenance hazard, but the finding is hard to
explain and easy to over-report, and three well-understood observation types are
worth more than four where one is noisy.

### Coverage is pairwise, and that is a deliberate under-report

An entry is reported shadowed when a *single* earlier entry covers it, not when
the union of several earlier entries does. Union coverage is strictly more
complete and much harder to justify to a reader: *"line 40 can never fire because
of line 20"* is checkable by a human in seconds; *"because of lines 12, 20 and 31
taken together"* is not.

It also errs toward missing findings rather than inventing them. A missed
shadowing costs one finding; an invented one costs the operator's trust in every
other finding in the report.

### Three semantics that would each be quietly wrong if skipped

- **Protocol subsumption, not equality.** `tcp` is a subset of `ip`, so an
  earlier `deny ip` shadows a later `permit tcp`. Equality would miss the most
  common real case entirely.
- **`established` narrows but never shadows.** Such an entry matches only packets
  in an existing session — strictly less — so treating it as a shadower produces
  confident false positives on exactly the lists most likely to have been written
  carefully.
- **Disabled entries are excluded and *reported* as excluded.** Dropping them
  silently would leave a reader unable to tell whether the analysis saw them.

## D21 — constructed objects, not corpus files

Fixtures live in `tests/fixtures/acls.py` as `ACL` and `ACLEntry` instances. **No
corpus file was added**, which follows from D20: without a parser, an ACL-bearing
configuration file would exercise nothing, and adding one would imply parsing
coverage that does not exist.

Their evidence is labelled `synthetic-acl-fixture.cfg` so it cannot be mistaken
for a corpus path in a test failure or a report.

**What P9 may and may not say.** It may state that the analyser correctly
identifies shadowing, redundancy and over-permission on constructed cases. It
**may not** state a detection rate, precision or recall against real-world access
lists, because none have been seen. That sentence belongs in the evaluation
report, not only here.

## D22 — an observation is not a verdict

`CheckSpec` reads `CSM.fields[name]` and has no path to `CSM.acls`, so
representing an ACL result as a `Finding` would have meant widening the one object
the whole Rule 1 argument rests on. It was not widened.

Two rails, and they are separate by construction:

    CSM.fields  ──►  rules  ──►  findings         a verdict against a control
    CSM.acls    ──►  analyser ──►  observations   a fact about a list's own logic

A shadowed entry is a fact about an access list's internal logic. Whether it
breaches a control is a separate question needing a control to breach, and none
has been sourced (D16). `comply → analyse` is a forbidden import edge, so a
verdict cannot become influenceable by analysis performed outside the canonical
model.

## D23 — findings are persisted, in the operational database only

**The boundary, restated because it is the thing most at risk here:**

| | holds |
| --- | --- |
| operational database | configuration content, findings, users, ownership |
| audit database | identifiers, counts and hashes — nothing else |

Migration `0002` adds `audit_run`, `finding` and `finding_evidence` to the
**operational** store. The P2 chain is untouched: not re-keyed, not relaxed, not
referenced. It still records *that* a run happened, over which device, with which
rulepack, and how many findings of each verdict — never what any finding said.

Why persist at all: without it, P8 reporting would re-run the pipeline per
request. That is slow, and worse, it would describe a **fresh** audit that happens
to agree with the original. If a pack version changed in between, the report would
silently describe something else.

**Evidence is stored as pointers**, not copies. `(file_id, line_start, line_end)`
resolves through `config_line` and `line_cache` to the exact stored bytes, so a
citation quotes the operator's own file. A second copy of the line could drift
from the first, and evidence whose two copies disagree is worse than evidence with
one.

**Findings are rebuilt through the contract on read**, not returned as rows. A
stored row that lost its abstention reason raises at reconstruction rather than
being rendered into a report as a bare UNKNOWN. Rule 3 is additionally a `CHECK`
constraint in the schema, so a direct SQL writer cannot bypass it either.

## D24 — unresolved is UNKNOWN, never an empty interval

`AddrSpec(kind=OBJECT)` may legitimately carry no `resolved_cidrs` — the contract
requires them only for `HOST` and `CIDR`. Its address set is genuinely unknown.

Treating unknown as *empty* would make such an entry match nothing, so it could
neither shadow another entry nor be shadowed by one. It would drop silently out
of the analysis while the report looked complete: an entry the operator can see in
their own configuration would simply have no line in the output, with nothing
saying why. That is the Rule 3 substitution, in the one place a reader would never
think to check.

Containment is therefore **three-valued** — `True`, `False`, `None` — threaded
all the way through rather than collapsed at the edges. Two consequences, both
tested:

- an unresolved entry above another **never** produces a false shadowing claim
  about it;
- but that entry is **not declared clean** either. Something above could not be
  compared, so whether it is reachable was not established, and reporting nothing
  would imply it was.

A definite finding still wins over an unresolved neighbour: an unknown elsewhere
must not suppress a conclusion that was actually established.

## D25 — authentication, two roles, minimal

Before P7 there was **no authentication anywhere**. Every route was open,
including configuration upload. The Concept Report promises that *"access to raw
files is role-separated from access to findings"*; that promise is now
implemented rather than stated.

**Passwords use `hashlib.scrypt`** — RFC 7914, a memory-hard KDF from the standard
library, with a random per-password salt, parameters recorded inside the stored
hash, and `hmac.compare_digest` for verification. No cryptography is invented, and
no dependency is added to a project committed to running offline. A fast
general-purpose hash would be the wrong primitive, because being fast is precisely
what an attacker wants.

`User` carries **no credential field at all**, so a hash cannot leak into a log
line, an API response or an audit payload. The schema has no column a plaintext
could be written to, and a `CHECK` requires the stored value to carry its
algorithm tag — an unsalted bare digest is refused by the database.

Authorisation, in full:

| | |
| --- | --- |
| `user` | Only resources they own — their uploads, devices, audits, findings |
| `admin` | The fleet, plus account management |

- **An unowned resource is admin-only.** Rows predating ownership have no owner,
  and defaulting those to "everyone" would silently expose every earlier upload.
- **A resource the caller may not see answers 404, not 403.** 403 confirms the id
  exists, which lets someone walk the id space and learn how many audits another
  operator has run.
- **Every authentication failure is the same 401.** Missing header, unknown
  username, wrong password and disabled account are indistinguishable, and a
  missing account still costs a hash computation so timing does not separate them.
- **No public registration.** Accounts are created by an admin;
  `scripts/create_admin.py` makes the first one out-of-band, so there is no
  bootstrap endpoint to remember to disable. The password is prompted, never
  passed as an argument where it would reach shell history and the process table.
- **An admin cannot disable their own account** — locking out the last admin has
  no recovery short of the database.

## The API surface

Four compliance endpoints, mounted at `/compliance/audits`. The prefix matters:
P2 already owns `/audit/*` for the hash-chained log, which is read-only by design,
and `/audit/head` beside `/audits` would be two unrelated resources one character
apart. A test caught the collision, and the names were the thing worth fixing.

This is the surface P8's reporting layer will consume, and P8 is its first real
client. Nothing speculative was added: an endpoint nobody exercises is an endpoint
designed against a guess. **No frontend was built** — the architecture puts the UI
at P13 and nothing here changes that.

## DEF-5 — README corrected

`README.md` said *"Exposure-aware prioritisation is P7"*, written during the P6
documentation pass. Six P1 sources say P7 is ACL analysis and that prioritisation
is P12. Corrected.

## OBS-2 — accepted, unchanged

`ACLEntry.is_permit_any_any` checks protocol, source, destination and
*destination* port, but not source port, so `permit ip any eq 80 any` is reported
as permit-any-any. A source port is meaningless with `protocol: ip`, so the entry
is nonsense to begin with and no real generator would emit it. **Recorded and left
alone** rather than tightened speculatively.

## Consequences

`api/analyse/` may import `api.models` and nothing else from `api/` — a whitelist,
so layers P8 has not written yet are forbidden too. No ML library, no network
client, no vendor or OS-family literal, no canonical field name. Eight new
forbidden edges, of which `comply → analyse` is the one carrying weight.

**Not built at P7:**

- **ACL extraction** — corpus prerequisite, unchanged.
- **Correlated-entry analysis** — noisy, deferred.
- **Exposure-aware prioritisation and peer baselines** — P12. `exposure_score` and
  `priority_rank` stay `None`; exposure needs ACLs *and* interfaces, and
  `CSM.interfaces` is also empty.
- **Remediation** — P8. `snippets/` holds one empty schema directory.
- **The React/Tailwind UI** — P13.
- **Sessions, tokens, password reset, registration** — each is a real feature with
  its own failure modes, and none is needed to make the API safe to expose.

**DEF-3 remains deferred.** `device_id` is the ingested file's content hash, so
every finding and every audit run inherits an identity that changes when a
configuration is edited. Nothing may present it as a stable device identity until
the P12 identity work.
