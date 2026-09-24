# ADR 0035 — Framework mappings against a content-addressed catalog

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D91 (validate identifiers against an official catalog, indexed
  by its own sha256), D92 (**every** mapping is `project_asserted` — a catalog
  publishes controls, not mappings), D93 (the catalog is not redistributed; the
  index is)
- **Affects:** `api/comply/frameworks.py` (new),
  `scripts/fetch_framework_catalog.py` (new), `rules/frameworks/` (new),
  `rules/canonical/*.yaml`, `tests/unit/test_rulepack_loading.py`
- **Replaces:** `test_no_framework_mappings_are_claimed`, deleted here

## Context

`SOURCING_BACKLOG` gap 4 is the most visible gap against Problem Statement
26155, which names CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001 explicitly.
Every rule shipped `frameworks: []`, and a test asserted that empty state —
written to be deleted by whoever sourced the first mapping.

The rule that made it a *gap* rather than an afternoon's typing is that a
control identifier written from memory is indistinguishable, in a report, from
one that was checked. Both look like `AC-17(02)`.

## What could be obtained, and what could not

| Framework | Outcome |
| --- | --- |
| **NIST SP 800-53 Rev 5** | **Obtained.** Published by NIST as OSCAL JSON, free and machine readable. Edition 5.2.0, 10,442,037 bytes, sha256 `01f37cf9…`. 1,014 live controls and 182 withdrawn. |
| DISA STIG | **Not obtained.** The DoD Cyber Exchange download index at `public.cyber.mil/stigs/downloads/` is rendered client-side; the served HTML carries fifteen links and no file URLs. Five plausible direct paths under `dl.dod.cyber.mil` were probed and every one answered 404. |
| CIS Benchmarks | **Not attempted past the first step.** Distribution is behind registration and terms acceptance; there is no free machine-readable edition to ingest. |
| ISO/IEC 27001 | **Not obtained.** A purchased standard. |

**One of four.** That is the honest result, and it is stated as a result rather
than smoothed over: three frameworks the problem statement names are still
unmapped, and the reason differs for each.

Guessing a STIG filename was considered for about as long as it takes to write
this sentence. It is the same failure as guessing a control identifier, in URL
form.

## D91 — validate every identifier against the catalog, and content-address the catalog

`scripts/fetch_framework_catalog.py` reads an official catalog and derives an
**index** into `rules/frameworks/`: the framework, the document, its edition as
the document itself declares it, the source URL, the catalog's **sha256**, and
every control identifier — live and withdrawn, kept apart.

The sha256 is the point. A citation reading "NIST SP 800-53 Rev 5" is a label
two people can hold while holding different files; a citation carrying the
digest of the bytes the identifiers were read from is a document. It costs
nothing and it is the difference between a claim that can be verified and one
that must be trusted.

**Withdrawn controls are named, not omitted**, and this turned out to be the
most useful thing in the index. Two of the identifiers a person would most
plausibly write from memory for NIRIKSHAK's own checks are withdrawn in Rev 5:

| Identifier | Title | Would have been written for | Status |
| --- | --- | --- | --- |
| `AC-17(08)` | Disable Nonsecure Network Protocols | the telnet check | **withdrawn** |
| `AU-08(01)` | Synchronization with Authoritative Time Source | the NTP check | **withdrawn** |

Both look entirely correct. Both would have shipped. An index that merely
omitted them would report "no such control", which reads like a typo; naming
them says *this identifier is real and you may not map to it*.

A third thing the catalog corrected: its labels are **zero-padded**. The control
is `AC-17(02)`, not `AC-17(2)`, and `CM-07`, not `CM-7`. A test asserts the
unpadded form does **not** validate, because that is the form a person types.

### The mappings

Seven rules, all mapped, each against a live control whose identifier is in the
index:

| Rule | NIST SP 800-53 Rev 5 |
| --- | --- |
| `NRK-SSH-001` | `AC-17(02)` |
| `NRK-TELNET-001` | `CM-07`, `AC-17(02)` |
| `NRK-HTTP-001` | `CM-07`, `AC-17(02)` |
| `NRK-TIMEOUT-001` | `AC-12`, `SC-10` |
| `NRK-LOGGING-001` | `AU-04(01)`, `AU-09(02)` |
| `NRK-NTP-001` | `SC-45(01)` |
| `NRK-BANNER-001` | `AC-08` |

The principle applied throughout: **map a rule to a control when the control's
own statement is what the check tests for.** `NRK-TIMEOUT-001` gets both `AC-12`
("automatically terminate a user session after…") and `SC-10` ("terminate the
network connection … after … of inactivity") because `exec-timeout` on a vty
line does both. `NRK-TELNET-001` gets `CM-07` (an insecure protocol that should
be restricted is in use) and `AC-17(02)` (a remote access path exists that is
not cryptographically protected). Where no control's statement clearly covered
the check, nothing was mapped rather than something adjacent.

## D92 — every mapping is `project_asserted`, and this contradicts the brief

The work was briefed to mark a mapping `OFFICIAL` "where it comes from a
published catalog". **That distinction does not hold, and the reason is worth
more than the mapping table.**

A catalog publishes **controls**. It says `AC-17(02)` exists, what it is called,
what it requires and where it sits in the document. It says nothing whatever
about whether NIRIKSHAK's `NRK-SSH-001` satisfies it. That judgement is this
project's, made by reading the control statements and deciding — and `OFFICIAL`
would claim somebody else made it.

`MappingProvenance.OFFICIAL` means *this mapping follows a published crosswalk*.
No crosswalk this project has obtained names our checks, so every mapping here
is `project_asserted`, and `test_no_mapping_is_marked_official` asserts it stays
that way until one is.

> **Narrowed at P18 (ADR 0045).** This section originally said such a crosswalk
> *"does not exist and is not going to"*. That was too strong and the reasoning
> did not support it: what a control catalog cannot do is publish mappings, and
> crosswalks are a different artefact that does exist — CIS publishes mappings
> from its Benchmarks to NIST SP 800-53, and NIST publishes crosswalk material
> between SP 800-53 and ISO/IEC 27001. `OFFICIAL` is unreachable **from a
> control catalog**, which is the accurate claim and a narrower one.

What the catalog buys is therefore precisely this much, and it is worth having:

- the identifier **exists**, in the edition named;
- it is **not withdrawn**;
- it is spelled the way the document spells it;
- the edition is pinned to a **sha256**, so a reviewer can obtain the same file.

That is a materially stronger claim than `frameworks: []` and a materially
weaker one than "NIRIKSHAK is NIST 800-53 compliant". Both halves are stated
everywhere the mappings surface.

## D93 — the catalog is not redistributed; the index is

The OSCAL catalog is **not committed**. `rules/frameworks/` holds the derived
index — identifiers, edition, digest — which is 14 KB against the catalog's
10 MB, and which contains no control text, no titles and no assessment
procedures, per `docs/CONTENT_POLICY.md`. The existing content-policy suite
scans `rules/` recursively, so the index is governed by that policy already
rather than by a new exemption.

**Whether this repository may redistribute the catalog itself is recorded as an
open question for the team, not answered here.** ADR 0005 set the precedent:
this project makes engineering decisions about what it accumulates and no legal
claims. An operator who wants to re-derive the index runs the script, or points
it at a file they obtained themselves — which is also what an airgapped
deployment does, and why the fetcher lives in `scripts/` rather than under
`api/`. Rule 6 is intact: nothing in the running system fetches anything, and no
audit depends on the script ever having been run.

### The gap this leaves in verification, stated plainly

Because the catalog is not in the repository, the test suite validates
identifiers against the **index**, and the index is derived from the catalog.
Re-deriving it is a one-command check against a file whose digest is recorded,
and until somebody runs that command the index is trusted rather than verified.
That is a real limit. It is the same limit any content-addressed reference has,
and it is smaller than the alternative, which was no reference at all.

## What replaces the deleted test

`test_no_framework_mappings_are_claimed` asserted zero identifiers ship. It was
deleted in this commit, by the change that earned it. The gate it enforced has
moved rather than relaxed — `tests/unit/test_framework_mappings.py` asserts:

- every rule is mapped, and every mapping carries a **citation** and a
  **catalog version**;
- every control identifier **exists in its catalog**;
- no mapping points at a **withdrawn** control;
- the version on every mapping **matches the catalog's own edition**;
- **no mapping is marked `OFFICIAL`**;
- the index records a 64-character digest and an `https` source;
- a framework with no catalog is **absent** from `sourced_frameworks()`, never
  present and empty — an empty result reads as "your fleet is compliant", and
  "we have never read this benchmark" is a different statement.

`test_no_framework_identifier_is_written` in the architecture-document suite was
rewritten rather than deleted: it now keys off `sourced_frameworks()`, so it
still refuses a CIS, STIG or ISO identifier anywhere in the document and permits
a NIST one. It re-tightens by itself if a catalog is withdrawn.
