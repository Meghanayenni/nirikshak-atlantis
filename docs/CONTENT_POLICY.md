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

## Sample configurations

`corpus/` holds sanitised sample device configurations.

- No real credentials, keys, certificates, community strings or password
  hashes — including hashed values, which remain crackable.
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

## Vendor packs

`packs/` holds parsing patterns. Pattern examples are configuration lines —
either from `corpus/` under the rules above, or supplied by an administrator
during training, in which case they are scrubbed of secrets before storage.

---

## If in doubt

Store the identifier and write the explanation yourself. That is always
sufficient for NIRIKSHAK to function, and it is the option that requires no
judgement call about someone else's material.
