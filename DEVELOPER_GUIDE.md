# NIRIKSHAK — Project Instructions

## Project Identity

NIRIKSHAK is a self-learning, vendor-agnostic network security
compliance auditor.

Smart India Hackathon 2026
Problem Statement: 26155
Organisation: National Technical Research Organisation (NTRO)
Team: Atlantis

The detailed product specification is available at:

docs/NIRIKSHAK_Concept_Report.pdf

Read and follow that document before making major architectural decisions.

---

# 1. Core Product

NIRIKSHAK ingests network device configuration files, normalises
vendor-specific syntax into a vendor-neutral security schema,
evaluates the schema against compliance frameworks, and produces
evidence-linked findings and vetted device-specific remediation.

The primary workflow is:

Ingest → Parse → Normalise → Comply → Prioritise → Remediate → Report

The central differentiator is the administrator-driven learning
loop for previously unsupported vendor/configuration syntax.

---

# 2. Non-Negotiable Architecture Rules

These rules MUST NOT be relaxed for convenience.

## Rule 1 — AI never issues a compliance verdict

A deterministic rule engine reading the canonical model decides
PASS, FAIL, or UNKNOWN.

AI may only:

- suggest mappings for unknown configuration lines
- provide explanations of deterministic findings

AI must never directly decide compliance.

---

## Rule 2 — Evidence is mandatory

Every parsed security-relevant field must contain:

- value
- confidence
- evidence

Evidence must point to the exact source:

- file
- line number
- raw configuration line

If the system cannot provide evidence, it must not make the
corresponding security claim.

---

## Rule 3 — Low confidence must abstain

If confidence is below the configured threshold:

UNKNOWN

must be produced.

Never convert uncertain information into a guessed PASS or FAIL.

Unknown fields should be routed to the administrator training workflow.

---

## Rule 4 — Remediation is never AI-generated

Remediation commands must come only from a vetted snippet library.

Snippets are keyed by:

- vendor
- OS family
- rule ID

Never generate production remediation CLI commands using an AI model.

---

## Rule 5 — Rules and vendor packs are DATA

Compliance rules and vendor parsing packs must be represented as
data, primarily YAML.

Adding:

- a vendor
- a framework
- an OS version

should not require modifying application code wherever the
architecture permits.

---

## Rule 6 — Offline-first

The system must be capable of operating without paid cloud APIs.

Preferred architecture:

- CPU-based local embeddings
- FAISS similarity search
- local LLM through Ollama where an LLM is required
- secrets scrubbed before model inference
- configuration data does not need to leave the operator network
- encryption at rest
- complete audit trail

Target hardware is a standard 8 GB laptop with no GPU.

---

# 3. Canonical Security Model

Vendor-specific configuration syntax must ultimately map to a
vendor-neutral canonical model.

Security-relevant fields should carry:

value
confidence
evidence

The canonical model includes fields such as:

- SSH version
- Telnet enabled
- HTTP server enabled
- minimum password length
- idle timeout
- logging enabled
- logging host
- NTP servers
- SNMP v3 only
- banner present
- AAA enabled
- weak ciphers

ACLs must use a structured vendor-neutral representation.

Do not allow vendor-specific syntax to leak into the compliance
rule engine.

---

# 4. Vendor Packs

Vendor packs describe how vendor-specific syntax maps to the
canonical model.

Example structure:

vendor: acme-os
version: 1

patterns:
  - field: ssh_version
    match:
      type: regex
      pattern: "^set ssh proto-version (\\d+)"
    capture:
      value: "$1"
      cast: int
    source: admin-trained
    examples:
      - "set ssh proto-version 2"

Vendor packs must be versioned.

Admin-trained patterns must be editable and deterministic.

Generated patterns should be predictable and boring:

1. Tokenise the confirmed line.
2. Replace the captured token with `(\S+)`.
3. Escape the remaining tokens.
4. Anchor the pattern with `^`.
5. Show the generated pattern to the administrator.
6. Allow the administrator to edit it before activation.

Do not generate unnecessarily clever regexes.

---

# 5. Adaptive Learning

When an unknown configuration line is encountered:

1. Do not guess.
2. Cluster unknown lines where appropriate.
3. Search the shared labelled-example similarity index.
4. Produce up to three candidate mappings.
5. Present them to the administrator.
6. Allow the administrator to confirm or correct the mapping.
7. Compile the confirmed mapping into the vendor pack.
8. Add the confirmed example to the similarity index.
9. Version the vendor pack.
10. Allow the configuration to be re-evaluated.

The AI/model does not become the authority.

Administrator confirmation creates the trusted mapping.

The goal is for vendor coverage to expand through data changes
rather than backend code changes.

---

# 6. Compliance Engine

Compliance decisions must be deterministic.

Rules should be declarative YAML.

Initial framework support:

- CIS
- NIST SP 800-53
- DISA STIG
- ISO/IEC 27001

One canonical security check may map to multiple framework
control IDs.

The compliance engine must produce:

- PASS
- FAIL
- UNKNOWN

with evidence and severity.

---

# 7. Important Analysis Features

Where feasible, preserve the following capabilities from the
project specification:

### Absence-aware evaluation

A missing configuration directive must not automatically mean
FAIL.

Consider:

- whether the platform supports the control
- documented platform defaults
- whether the absence is actually determinable

If support/default behaviour is unknown, abstain.

### Peer-baseline outlier detection

Compare devices against their own peer group to identify unusual
configuration states.

### Semantic ACL analysis

Represent ACLs structurally and detect:

- shadowed rules
- redundant rules
- overly permissive rules

Use deterministic interval/logic analysis rather than an LLM.

### Exposure-aware prioritisation

Prioritise findings using the canonical security model together
with ACL/exposure information.

Severity alone should not determine the remediation order.

### Calibrated confidence

Similarity scores must not automatically be treated as confidence.

Confidence should eventually be calibrated against labelled
ground truth.

---

# 8. Remediation

Remediation commands must come from the vetted snippet library.

Each remediation should include, where applicable:

- exact command
- vendor
- OS family/version
- rule ID
- rollback command
- impact assessment
- dependency/ordering information

Never automatically apply remediation to a live device.

The system only generates recommendations.

A human operator applies them.

---

# 9. Security Restrictions

DO NOT implement:

- live device access
- active network scanning
- automatic remediation
- model-generated production CLI
- configuration chatbot
- model fine-tuning
- unnecessary cloud AI dependencies

Configuration files may contain sensitive information.

Treat them as sensitive data.

Scrub secrets and credential-adjacent strings before external
inference.

Maintain an audit trail for:

- AI suggestions
- administrator corrections
- vendor pack changes
- audit results

Use hash chaining for audit integrity.

---

# 10. Technology Stack

Preferred stack:

Backend:
- Python 3.11
- FastAPI
- SQLite

Parsing:
- TextFSM
- ntc-templates
- Netmiko / NAPALM
- lxml for XML/JSON exports

AI:
- sentence-transformers
- all-MiniLM-L6-v2
- FAISS
- Ollama for local LLM functionality

Rules:
- YAML

Frontend:
- React
- Tailwind CSS

Reporting:
- Jinja2
- WeasyPrint

Do not introduce a new major technology without explaining why
it is necessary and how it fits the architecture.

---

# 11. Repository Structure

Target structure:

corpus/
  <vendor>/
  labels/

packs/

rules/
  cis/
  nist/
  stig/
  iso/

snippets/

api/

ui/

eval/

docs/

Keep configuration data, rules, vendor packs and remediation
snippets separate from application logic.

---

# 12. Evaluation

Evaluation is part of the product, not an afterthought.

The evaluation harness must measure:

- precision per canonical field
- recall per canonical field
- correct-abstention rate
- wrong-confident rate
- held-out vendor generalisation
- top-3 mapping accuracy

The wrong-confident rate should be treated as a critical safety
metric and kept near zero.

One vendor should be held out entirely for the generalisation
experiment.

---

# 13. Development Rules

Before implementing a large feature:

1. Understand the existing architecture.
2. Explain the implementation plan.
3. Identify affected components.
4. Identify risks.
5. Implement incrementally.
6. Test the implementation.
7. Do not silently replace architectural decisions.

Do not:

- delete working functionality unnecessarily
- rewrite the entire project to solve a small problem
- add dependencies without justification
- hard-code vendor-specific logic into the rule engine
- put compliance decisions inside AI prompts
- hide uncertainty
- fake evaluation results

If a requirement is ambiguous, identify the ambiguity rather than
inventing a convenient interpretation.

Prefer boring, deterministic, testable solutions over impressive
but unverifiable implementations.

---

# 14. Development Workflow

Before coding:

- inspect the repository
- read this file
- read docs/NIRIKSHAK_Concept_Report.pdf
- understand the current implementation state

For major changes:

Plan → Review → Implement → Test → Verify

Do not begin the full application implementation merely because
the project is empty.

Build the system incrementally from the core data contracts
outward.

---

# 15. Source of Truth

The project specification is:

docs/NIRIKSHAK_Concept_Report.pdf

These project instructions define implementation constraints.

When a conflict appears:

1. Identify the conflict.
2. Explain it.
3. Do not silently choose a solution.
4. Ask for a decision when it affects architecture.

The repository must remain consistent with the NIRIKSHAK
architecture and SIH Problem Statement 26155.