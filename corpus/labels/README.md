# Ground-truth labels

**A label is authored from the configuration, never from parser output.**
(ADR 0010, preserved by decision D31.)

These files record what a person read in an evaluation configuration. They are
the reference the P9 harness scores the system against, so everything about how
they are produced matters more than the code that consumes them.

---

## What was read, and what was not

Every label in this directory was written by opening the raw configuration file
and reading it. **No NIRIKSHAK output was consulted** — not the parser, not the
normaliser, not the compliance engine, not a report. In particular,
determinability was never inferred from whether the parser managed to extract a
value; that inference is the exact circularity the rule exists to prevent.

The label contract has no field a prediction could be written into. There is no
`predicted_value`, no `confidence`, no `state` copied from a parsed `Field`.

## The doctrine, so a reviewer can disagree with it

A field is **determinable** when a competent network engineer reading *only this
file* can state its value.

**Absence counts as determinable for exactly one class of field:** those that
exist by being configured. If the file contains no `banner` directive then the
device has no banner; if it contains no logging host then no remote logging
destination is configured. These are readable off the page.

**Absence is not determinable for everything else.** An unset SSH version, an
unmentioned HTTPS listener, a missing password policy, absent AAA — each is a
question about what the platform does by default, which is documented vendor
behaviour and not a property of this file. NIRIKSHAK has sourced no such
documentation, so neither the system nor the labeller can answer them, and both
correctly abstain.

**No inference chains.** A configured logging host does not get labelled as
proof that the logging subsystem is enabled. A label states what the file says,
not what the file implies.

### Consequence worth stating plainly

Under this doctrine most abstentions on Arista and Juniper are **correct**, and a
handful are **misses** — cases a human reads easily and the system cannot,
because no parsing pack exists for those platforms. That asymmetry is real and
the report separates it by vendor rather than averaging it away (decision D34).

## Verdict labels

Each verdict label is derived by taking the labelled field value and applying the
rule's condition **as written in the rule file** — never by running the engine,
and never from the rule's rationale prose.

Where a rule's condition and its own rationale disagree, that is a rule defect
and belongs in a decision record, not in this metric. Folding it in here would
report a rule-authoring mistake as an engine error. One such defect is recorded
as DEF-8 in ADR 0016.

## Provenance and the authorship conflict

Every file records `labelled_by`, `labelled_at`, `authored_from` and a
`review_status`.

**All labels here are `unreviewed`,** and the Cisco files additionally carry
`pattern_author_conflict: true`. The Cisco parsing patterns and these Cisco
labels share an author, so correlated error between them is invisible: a field
misunderstood while writing the pattern would be misunderstood the same way while
writing the label, and the measurement would come out clean without proving
anything.

The flag does not fix that. It makes it loud rather than silent, which is what
decision D35 asked for. The harness reports labels carrying the flag separately,
and **no report may describe an unreviewed label as independent ground truth**.

Arista and Juniper carry no conflict: no parsing pattern has ever been written
for either platform, so there is nothing for the label author to have been
influenced by.

### Clearing the flag

A reviewer reads the configuration, checks each label against it, and sets
`review_status: reviewed` with `reviewed_by` and `reviewed_at`. That is a data
change and needs no code. Once a label is reviewed **by someone other than its
author**, `LabelProvenance.is_independent` becomes true and the harness reports
it in the independent population.

## Binding to the file

`file_sha256` pins the labels to the exact bytes they were written against, and
the loader refuses to score a file whose content has changed. Each label citing a
line also records that line's verbatim text, checked against the file at load
time — so a citation that has drifted fails loudly instead of scoring something.

## Which files are labelled

| File | Split | Labels |
| --- | --- | --- |
| `cisco/eval/rtr-edge-09.cfg` | eval | 13 fields, 7 verdicts |
| `cisco/eval/sw-dist-11.cfg` | eval | 13 fields, 7 verdicts |
| `arista/eval/sw-leaf-07.cfg` | eval | 13 fields, 7 verdicts |
| `juniper/eval/srx-dc-02.conf` | eval | 13 fields, 7 verdicts |

**The PAN-OS holdout is not labelled and must not be.** Labelling requires
reading, and nothing may read the held-out vendor until the generalisation
experiment at P10. Its manifest entries carry `labelled: false`.

**No development file is labelled.** Ground truth next to the files patterns are
authored from is an invitation to author patterns from the ground truth. The
contract refuses any label whose split is not `eval`.
