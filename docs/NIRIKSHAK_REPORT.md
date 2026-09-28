# NIRIKSHAK

Smart India Hackathon 2026 · Problem Statement 26155 · National Technical
Research Organisation (NTRO) · Team Atlantis

## What NIRIKSHAK does

NIRIKSHAK is a self-learning, vendor-agnostic network security compliance
auditor. It reads a network device's configuration file, normalises its
vendor-specific syntax into one vendor-neutral security schema, evaluates that
schema against compliance frameworks with a deterministic rule engine, and
produces evidence-linked findings paired with vetted, device-specific
remediation commands.

When it meets a configuration line it does not recognise, it does not guess.
It shows the line to an administrator, and their confirmed answer becomes a
permanent, deterministic pattern — so the platform is read correctly the next
time, without a code change or a restart.

## How it works

Every configuration passes through one pipeline:

```
Ingest → Parse → Normalise → Comply → Analyse → Prioritise → Report
```

- **Ingest** — a configuration file is uploaded and stored.
- **Parse** — the raw text is turned into a structural tree, and a vendor pack's
  patterns are applied to it.
- **Normalise** — the parsed values become a Canonical Security Model: one
  vendor-neutral representation with a value, a confidence level and a cited
  evidence line for every security field.
- **Comply** — a deterministic rule engine reads the canonical model and
  decides PASS, FAIL, UNKNOWN or NOT_APPLICABLE for every applicable rule.
- **Analyse** — a device's access lists are checked for shadowed rules,
  redundant entries and overly permissive matches.
- **Prioritise** — devices are grouped by platform and compared against their
  own peer cohort.
- **Report** — a persisted audit run renders as a self-contained, evidence-
  linked HTML document, or as a PDF.

**The learning loop.** A line no vendor pack recognises is clustered by shape
and shown to an administrator in the Needs-review queue, ranked by how many
devices share it. The administrator maps it to a security field, or marks it
not security relevant. That decision compiles into a new, versioned pattern in
the vendor pack:

```
residue → cluster → a human decides → compile → DRAFT → VALIDATED
        → activate → re-parse → the line is no longer unknown
```

The generated pattern is deliberately readable — `logging host 192.0.2.10`
becomes `^logging\s+host\s+(\S+)$` — so the administrator who is about to make
it permanent can verify it by eye, and may edit it before activating.
Activation takes effect immediately, with no restart. A field read by a
learned pattern is always marked `admin_confirmed`, distinct from a field a
shipped pack read on its own.

**A platform with no pack at all** can be started from the interface's
bootstrap page. It derives what it can from the uploaded file itself — its
syntax mode, its comment convention, and the lines no known platform's pack
recognises — and never guesses a vendor name: the administrator supplies the
name, the file supplies the structure. The result is a new, versioned pack,
which the ordinary training loop then fills in one confirmed line at a time.

## Security frameworks supported

Three frameworks are sourced, each pinned to a specific published edition:

- **NIST SP 800-53 Rev 5**, edition 5.2.0 — the OSCAL catalog, 1,014 controls.
- **DISA Cisco IOS XE Router NDM STIG**, V3R7 — 42 requirements, held in the
  repository and re-verified against its own document on every check.
- **CIS Cisco IOS XE 17.x Benchmark**, v2.2.1 — 84 recommendations.

An audit can be scoped to one or more of these benchmarks
(`POST /compliance/audits?file_id=…&framework=nist`), and a finding shows every
framework control it maps to, with the exact edition it was validated against.

## Vendor support

Four platforms are read today, each by its own vendor pack:

| Vendor / platform | Canonical security fields read |
| --- | --- |
| Cisco IOS | 11 — SSH version, telnet, HTTP/HTTPS server, idle timeout, password minimum, logging hosts, NTP servers, banner, SSH ciphers, SSH MACs |
| Cisco NX-OS | 9 — telnet, HTTP server, idle timeout, AAA, logging hosts, NTP servers, banner, SSH ciphers, SSH MACs |
| Juniper Junos | 4 — telnet, banner, logging hosts, SSH version |
| Arista EOS | 3 — telnet, idle timeout, banner |

A vendor pack is versioned YAML data, not application code: adding a platform,
a new pattern, or a new framework mapping is a data change, verified against a
checksum at load and activated without redeploying the service.

## Compliance scoring

A device is scored against a framework only once its configuration has been
fully reviewed: every line the vendor pack could not recognise must carry an
administrator's decision, and the audit run used for scoring must be newer
than every one of those decisions. Until then, the system states which of
those two conditions is unmet rather than showing a number.

Once a device is ready to be scored, each framework control is rolled up from
the rules mapped to it:

- **violated** — at least one mapped rule failed.
- **fully satisfied** — every mapped rule passed, and at least one of those
  rules tests the control in full.
- **no violation found** — every mapped rule passed, but each only tests part
  of the control, so nothing failing was found without the whole control being
  verified.
- **undetermined** — anything else, including a rule that could not reach a
  verdict.

The headline figure is a fraction of controls **fully satisfied** out of
controls assessed — for example, "1 of 10 assessed controls fully
satisfied" — never a percentage, alongside how many of the framework's total
published controls were assessed at all. A framework whose edition does not
describe the device in question (for example, a platform benchmark applied to
a different vendor) is marked not applicable rather than scored as zero.

## Findings and evidence

Every finding carries a verdict (PASS, FAIL, UNKNOWN or NOT_APPLICABLE), the
severity of the underlying rule, and the evidence it rests on: the exact file,
line number and raw configuration text. A field NIRIKSHAK could not determine
carries the reason it abstained rather than a guessed answer, and a value
inferred from a documented platform default — rather than read directly from
the file — is always marked as inferred, never presented as observed.

The interface is a pure consumer of this data: it computes no verdict, no
score and no severity of its own. Everything it shows was returned by the API.

## Remediation

A failing finding is resolved against a library of vetted commands, keyed by
vendor, OS family and rule ID. Twenty vetted snippets ship today, across
Cisco IOS, Juniper Junos and Arista EOS. Every snippet names the person who
checked it, the vendor document it was checked against, its rollback command,
and any precondition for applying it safely.

Remediation is returned as a plan in application order, with a command that
carries a lockout risk sorted last — so a change is never sequenced in a way
that would strand the operator outside the device they are fixing. Nothing is
ever applied automatically: NIRIKSHAK recommends a command, and a human
operator types it.

## Audit trail

Every administrator decision, every vendor-pack change, and every audit run is
recorded in a hash-chained, append-only log, separate from the operational
data it attests to. Each record's hash binds to the hash of the record before
it (SHA-256 over the record's canonical payload), so any retroactive edit to
one record breaks verification for every record after it. The chain can be
independently verified without running the API that produced it.

## Technical stack

- **Backend:** Python 3.11, FastAPI, SQLite.
- **Parsing:** a purpose-built hierarchical block parser for indented,
  brace-nested and flat configuration syntax.
- **Similarity suggestions:** `sentence-transformers` (`all-MiniLM-L6-v2`),
  running locally on CPU — no suggestion is ever treated as a decision; only
  an administrator's confirmation is.
- **Rules and vendor packs:** YAML, checksum-verified at load.
- **Frontend:** React, TypeScript, Tailwind CSS.
- **Reporting:** self-contained HTML, and PDF via WeasyPrint.
- **Deployment:** offline-first — inference runs locally, secrets are scrubbed
  before any model call, and configuration data never needs to leave the
  operator's network.
