# NIRIKSHAK — Project Instructions

Self-learning, vendor-agnostic network security compliance auditor.
Smart India Hackathon 2026 · PS 26155 · NTRO · Team Atlantis.

Specification: `docs/NIRIKSHAK_Concept_Report.pdf`. Read it before any major
architectural decision.

---

## 1. Core Product

NIRIKSHAK ingests network device configuration files, normalises vendor-specific
syntax into a vendor-neutral security schema, evaluates that schema against
compliance frameworks, and produces evidence-linked findings with vetted,
device-specific remediation.

`Ingest → Parse → Normalise → Comply → Prioritise → Remediate → Report`

The central differentiator is the administrator-driven learning loop for
previously unsupported vendor syntax.

---

## 2. Non-Negotiable Architecture Rules

These must not be relaxed for convenience.

**Rule 1 — AI never issues a compliance verdict.** A deterministic rule engine
reading the canonical model decides PASS, FAIL or UNKNOWN. AI may only suggest
mappings for unknown configuration lines and explain deterministic findings.

**Rule 2 — Evidence is mandatory.** Every security-relevant field carries
`value`, `confidence`, `evidence`. Evidence points to file, line number and raw
line. No evidence, no claim. Commented-out directives and literal block bodies
(banners, keys, certificates) must never produce a PRESENT field — a security
fact that is not in effect, carrying a citation, is the worst output this system
can generate.

**Rule 3 — Low confidence abstains.** Below threshold, produce UNKNOWN and route
to the training workflow. Never convert uncertainty into a guessed PASS or FAIL.
Confidence populations are not comparable and each is floored separately:
deterministic and admin-confirmed matches produce a field or nothing;
`platform_default` has its own floor and is always visibly marked as inferred
rather than observed; only calibrated similarity is compared against
`confidence_threshold`.

**Rule 4 — Remediation is never AI-generated.** Commands come only from the
vetted snippet library, keyed by vendor, OS family and rule ID.

**Rule 5 — Rules and vendor packs are data.** Primarily YAML. Adding a vendor,
framework or OS version must not require application code changes wherever the
architecture permits.

**Rule 6 — Offline-first.** CPU embeddings, FAISS, local LLM via Ollama where an
LLM is needed. Secrets scrubbed before inference, encryption at rest, complete
audit trail. Configuration data never needs to leave the operator network.
Target hardware: a standard 8 GB laptop, no GPU.

---

## 3. Canonical Security Model

All vendor syntax maps to a vendor-neutral model. Every security-relevant field
carries value, confidence and evidence.

Fields include: SSH version · Telnet enabled · HTTP server enabled · minimum
password length · idle timeout · logging enabled · logging host · NTP servers ·
SNMP v3 only · banner present · AAA enabled · weak ciphers.

ACLs use a structured vendor-neutral representation. Vendor-specific syntax must
never leak into the compliance rule engine.

Do not add a field to the schema until a pattern for it can be verified against
a real corpus file. A field that is present in the schema but never matches
looks supported while producing UNKNOWN forever.

---

## 4. Vendor Packs

Packs describe how one platform's syntax maps to the canonical model, and are
versioned.

```yaml
vendor: acme-os
version: 1
patterns:
  - field: ssh_version
    match: {type: regex, pattern: "^set ssh proto-version (\\d+)"}
    capture: {value: "$1", cast: int}
    source: admin-trained
    examples: ["set ssh proto-version 2"]
```

Generated patterns must be predictable and boring: tokenise the confirmed line,
replace the captured token with `(\S+)`, escape the rest, anchor with `^`, show
it to the administrator, allow editing before activation. Block scope selectors
are anchored regexes, defaulting to the literal-escaped header — numeric-range
generalisation is an explicit opt-in the administrator sees.

Do not generate clever regexes. A pattern an administrator cannot read is one
they cannot verify.

---

## 5. Adaptive Learning

On an unknown configuration line: do not guess. Cluster unknown lines, search
the shared labelled-example index, produce up to three candidate mappings, and
present them to the administrator. On confirmation or correction, compile the
mapping into the vendor pack, add the example to the similarity index, version
the pack, and allow re-evaluation.

The model is never the authority. Administrator confirmation creates the trusted
mapping. Vendor coverage expands through data changes, not backend code changes.

---

## 6. Compliance Engine

Deterministic decisions from declarative YAML rules. Frameworks: CIS, NIST
SP 800-53, DISA STIG, ISO/IEC 27001. One canonical check may map to multiple
framework control IDs. Output is PASS, FAIL or UNKNOWN with evidence and
severity.

---

## 7. Analysis Capabilities

**Absence-aware evaluation.** A missing directive is not automatically FAIL.
Consider whether the platform supports the control, its documented default, and
whether the absence is determinable at all. If support or default behaviour is
unknown, abstain.

**Peer-baseline outlier detection.** Compare devices against their own peer group
to surface unusual configuration states.

**Semantic ACL analysis.** Structural representation with deterministic interval
logic to detect shadowed, redundant and overly permissive rules. Not an LLM.

**Exposure-aware prioritisation.** Rank using the canonical model together with
ACL and exposure information. Severity alone must not determine remediation
order.

**Calibrated confidence.** Similarity scores are not confidence. Calibrate
against labelled ground truth before treating any score as a probability.

---

## 8. Remediation

Commands come from the vetted snippet library and include, where applicable:
exact command, vendor, OS family and version, rule ID, rollback command, impact
assessment, and dependency or ordering information.

Remediation is never applied automatically. The system recommends; a human
operator applies. Ordering must account for lockout risk — never sequence a
change that strands the operator outside their own device.

---

## 9. Security Restrictions

Do not implement: live device access · active network scanning · automatic
remediation · model-generated production CLI · configuration chatbot · model
fine-tuning · unnecessary cloud AI dependencies.

Configuration files are sensitive data. Scrub secrets and credential-adjacent
strings before any external inference. Maintain a hash-chained audit trail of AI
suggestions, administrator corrections, vendor pack changes and audit results.

---

## 10. Interface Principles

Applies to the web UI (`ui/`) and report templates (`api/report/templates/`).
Both share one visual vocabulary; neither invents its own. A static reference
implementation lives at `docs/ui-reference.html` — translate from it rather than
inventing component styling per screen.

**Structure.** Three levels of zoom, one question each: fleet (which devices need
attention) → device (what is wrong with this one) → finding (why do you claim
that, and what do I type). A screen shows what serves its own question and links
down for the rest. Build the finding detail view before any dashboard — it is
the atom of the product; everything else is composition.

**Palette.** Neutral base, restrained semantic colour.

```
ink       #17191C    primary text, solid fills
ink-2     #3D444D    secondary text, severity bars
muted     #6B7280    metadata, column headers
paper     #FFFFFF    cards, tables
surface   #F6F7F9    page background, hover
border    #E1E5EA    hairlines

pass      #1E6B4F  on #EDF5F1     fail    #9E2B2B  (solid, reversed text)
unknown   #4A5666  on #EFF2F5     inferred #7A5B12  on #FAF3E3
accent    #23527C    links, focus, evidence highlight
```

Semantic colour appears only on verdict chips, the inferred marker, evidence
highlight, and focus states. Never on table rows, never as a large fill. If a
screen is more than roughly a tenth colour, something is being decorated rather
than communicated.

**Colour accelerates recognition; it never carries meaning alone.** Reports print
in greyscale and a meaningful share of engineers have colour vision deficiency,
so every state pairs its colour with a text label and a distinct weight or
border treatment. FAIL is heaviest (solid fill, reversed) and draws the eye
first. PASS is lightest — a compliant control needs no attention. UNKNOWN is
dashed and neutral slate, deliberately **not** amber: abstention sits off the
severity axis, not at the bottom of it. If the interface makes abstention look
like a weaker failure, operators learn to filter it out and Rule 3 is defeated
at the presentation layer.

Severity uses ink weight, not colour. Two competing colour scales on one screen
produce a rainbow and destroy the verdict signal.

**Evidence is always one interaction away.** Any finding traces to its source
line without leaving context — show surrounding lines with the matched span
marked. Fields asserted from `platform_default` carry a visible INFERRED marker
that cannot be suppressed. An operator always knows the difference between
observed and inferred. Remediation displays with its rollback and its impact
note; never the command alone.

**Density.** The audience is network and security engineers; dense is correct,
cluttered is not. One separation mechanism per table — hairlines or banding or
spacing, not all three. Numerals are tabular so columns align. Restraint in
borders and shadows, not in information.

The training interface is the exception: it is a focused judgement task and
should be spacious, one line at a time. A cramped training screen produces
careless confirmations, and a careless confirmation enters a vendor pack
permanently. Similarity scores are labelled as rankings, not probabilities.

**Restraint.** No chart that a sentence or a sorted table would carry better. No
decorative visualisation of pass/fail ratios. Prioritisation is computed and
presented as an ordered list — do not offload ranking onto filters the operator
must drive themselves.

Spacing scales, type scales and component styling are implementation choices
living in the frontend as tokens. They may be revised without amending these
principles.

---

## 11. Technology Stack

Backend: Python 3.11, FastAPI, SQLite.
Parsing: TextFSM, ntc-templates, lxml for XML/JSON exports.
AI: sentence-transformers (`all-MiniLM-L6-v2`), FAISS, Ollama.
Rules: YAML. Frontend: React, Tailwind. Reporting: Jinja2, WeasyPrint.

Do not introduce a new major technology without explaining why it is necessary
and how it fits the architecture.

---

## 12. Repository Structure

```
corpus/<vendor>/ , corpus/labels/    packs/    rules/{cis,nist,stig,iso}/
snippets/    api/    ui/    eval/    docs/
```

Configuration data, rules, vendor packs and remediation snippets stay separate
from application logic.

---

## 13. Evaluation

Evaluation is part of the product, not an afterthought. The harness measures:
precision and recall per canonical field · correct-abstention rate ·
wrong-confident rate · held-out vendor generalisation · top-3 mapping accuracy.

Wrong-confident rate is the critical safety metric and must stay near zero. One
vendor is held out entirely for the generalisation experiment and its files are
never opened during development.

---

## 14. Development Rules and Workflow

Before coding: inspect the repository, read this file and the Concept Report, and
understand the current implementation state.

For major changes: Plan → Review → Implement → Test → Verify. Identify affected
components and risks in the plan. Implement incrementally. Never silently
replace an architectural decision.

Do not: delete working functionality unnecessarily · rewrite the project to solve
a small problem · add dependencies without justification · hard-code
vendor-specific logic into the rule engine · put compliance decisions inside AI
prompts · hide uncertainty · fake evaluation results.

A deferred capability must raise, never degrade. A mode that silently returns
empty output is indistinguishable from a clean result and is a mis-parse
arriving dressed as a fact.

If a requirement is ambiguous, identify the ambiguity rather than inventing a
convenient interpretation. Prefer boring, deterministic, testable solutions over
impressive but unverifiable ones.

---

## 15. Source of Truth

`docs/NIRIKSHAK_Concept_Report.pdf` is the specification; this file defines
implementation constraints. On conflict: identify it, explain it, do not silently
choose — ask for a decision when it affects architecture.

The repository must remain consistent with the NIRIKSHAK architecture and SIH
Problem Statement 26155.