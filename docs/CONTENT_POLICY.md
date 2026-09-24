# Repository content policy

**Applies to:** `rules/`, `packs/`, `snippets/`, `corpus/`, `docs/`
**Enforced by:** `tests/architecture/test_rule_content_policy.py`
**Decision:** ADR 0005

---

## What this document is

An engineering policy about what content this repository accumulates. It keeps
the repository to material we authored or can account for.

**It is not legal advice and makes no legal claim.** If the project needs a
licensing review, that is a separate exercise for the team and its institution.

---

## Compliance rules

Rule files in `rules/` **may** contain:

- Framework and control **identifiers** — for example a CIS recommendation
  number, a NIST SP 800-53 control ID, a STIG ID, an ISO/IEC 27001 Annex A
  control reference.
- The framework name, version, revision or benchmark edition the identifier
  belongs to.
- A **citation** naming the source document, so a reader can look the control up
  themselves.
- **Our own** `title`, `rationale`, `severity`, check logic and remediation
  reference, written by the project.

Rule files **must not** contain:

- Transcribed control text, benchmark prose, audit procedures or remediation
  narrative copied from a framework document.
- Fields whose purpose is to hold such text. The test rejects `control_text`,
  `benchmark_text`, `standard_text`, `annex_text`, and similar names.

### Why this costs nothing

The compliance engine matches on **identifiers**, never on prose. A control's
text is not an input to any verdict, so the policy removes nothing the system
needs. What the operator sees in a report is the identifier, our rationale, and
the evidence line from their own configuration.

Rationale is capped at 1200 characters — generous for explaining why a check
exists, tight enough to catch wholesale pasting.

---

## Framework source documents — held, or referenced

A framework index in `rules/frameworks/` records the sha256 and edition of the
document its identifiers were read from. Whether the **document itself** may sit
in this repository depends on that document's own terms, and the answer differs
by framework (ADR 0052):

| Source | In the repository? | Why |
| --- | --- | --- |
| NIST SP 800-53 Rev 5 (OSCAL) | No — fetched by `scripts/`, digest recorded | Left open for the team (ADR 0035) |
| DISA Cisco IOS XE Router NDM STIG (XCCDF) | **Yes** — `docs/sources/disa/`, byte for byte | A US Government work published for public download |
| CIS Cisco IOS XE 17.x Benchmark (PDF) | **Never** — read from an operator-supplied path outside the tree | Its own terms say it may not be hosted on a third-party site; this repository has a public remote |

For CIS that means, concretely: the recommendation **number** and our own
description of the check, and nothing else — no title, rationale, audit
procedure or remediation text, and no extract of the PDF in any format.
`.gitignore` guards against accident, and
`tests/architecture/test_cis_material_is_not_held.py` fails on any CIS-named
file, or any file whose bytes match the pinned digest, anywhere in the working
tree — ignored files included.

**This is not a legal claim** about any of those terms. They were read, and the
conservative reading was taken. Whether to ask CIS Legal for guidance on using
portions of its recommendations is a decision for the team.

A file under `docs/sources/` is held *because* it is content-addressed, so
`.gitattributes` marks it `-text`: git stores and checks out the published bytes
unaltered, and the recorded sha256 stays true of the file on disk.

## Sample configurations

`corpus/` holds sanitised sample device configurations.

- No real credentials, keys, certificates, community strings or password
  hashes — including hashed values, which remain crackable. A hash-shaped
  value is written `$N$SAMPLE$…`, and the gate treats any other salt as a
  credential. An SNMP community is `public` or `private`, and a configuration
  line mentioning `community` in a form the gate cannot read **fails** the
  suite rather than passing it (ADR 0055).
- No real public IP addressing, hostnames or topology belonging to an actual
  organisation.
- Each corpus file records its **provenance** — hand-written, adapted from
  public vendor documentation, or synthetic — so the evaluation report can
  state honestly what its results rest on.

## Remediation snippets

`snippets/` holds commands the project has vetted against vendor documentation.
Each snippet cites the document it was checked against. Commands are short
factual instructions; the surrounding `impact`, `preconditions` and `notes` are
our own words.

**Enforced from P8** by `tests/architecture/test_rule_content_policy.py`: every
file under `snippets/` must name a `vetted_by` and a `reference`, must carry no
field shaped to hold vendor prose, and must load through
`api/remediate/library.py` — which validates it against
`snippets/schema/snippet.schema.json` and then against the contract. A
`vetted_by` that looks automated is refused: the field exists to name the person
accountable for the commands.

The library holds twenty snippets across three platforms, each naming its vetter
and the vendor document it was checked against. See `snippets/README.md`.
*(Until P18 this sentence said the library was empty, which had been false
since the snippets shipped.)*

## Vendor packs

`packs/` holds parsing patterns. Pattern examples are configuration lines —
either from `corpus/` under the rules above, or supplied by an administrator
during training, in which case they are scrubbed of secrets before storage.

---

## If in doubt

Store the identifier and write the explanation yourself. That is always
sufficient for NIRIKSHAK to function, and it is the option that requires no
judgement call about someone else's material.
