# ADR 0050 — The analyser was right again

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D128 (rename the term rather than write vendor syntax nobody
  can source), D129 (a sanitisation pattern must not be vendor-shaped)
- **Affects:** `corpus/juniper/dev/core-rtr-01.conf`, `corpus/MANIFEST.yaml`,
  `tests/integration/test_corpus_policy.py`,
  `tests/unit/test_junos_filter_extraction.py`

## Twice now

ADR 0028 recorded the first: `edge-rtr-01.cfg` carried a remark saying *"this
deny is unreachable: the catch-all permit below already matches it"*, and the
analyser declined to flag that entry. It was right — an ACL evaluates top-down,
so a rule *below* cannot shadow a rule above.

This is the second. `core-rtr-01.conf` contained
`term allow-established { from { protocol tcp; } then accept; }`, and the
analyser reported the two management permits beneath it as **redundant**. That
is only true of a term matching *all* TCP — which is exactly what the
configuration says, and exactly what the name denies.

**The pattern is worth stating plainly.** The corpus was written by somebody who
believed each file was correct, carefully enough to name terms after their
intent and to annotate the tricky ones. Twice the tool has disagreed with that
belief, on evidence, and twice the tool was right. Both times the disagreement
surfaced not as an error but as an *observation the author did not expect* —
which is the only way this kind of mistake ever surfaces, and the reason an
analyser that reports what it computed rather than what it was told is worth
having.

Neither was a parser bug. Both were the analyser reading the file more
carefully than its author.

## D128 — rename the term; do not write the keyword

The obvious fix is to make the configuration match the name: add the JunOS
construct that matches established sessions, so `allow-established` allows
established sessions.

**Not taken, and the reason matters more than the fix.** Writing that keyword
would be vendor syntax drawn from general knowledge, with no document in this
repository behind it — precisely what DEVELOPER_GUIDE.md forbids and what `! model
ISR4331` cost ten phases ago (ADR 0044). The brief for this work observed that
*"IOS-style `established` has no Junos equivalent in that position"*, which is
true and is also the observation that the equivalent, wherever it lives, is
something this repository cannot currently cite.

There would also have been a second cost: the dialect does not read a valueless
`from` condition, so adding one would have dropped the whole filter and removed
the corpus's only non-Cisco shadowing fixture — trading a naming error for a
silent loss of coverage.

So the **name** was the error and the name is what changed:
`allow-established` → `allow-all-tcp`. The configuration was always what it
appears to be, and the analyser's reading of it was correct throughout. Every
observation is unchanged, which is the point: nothing about the device moved,
only the description of it.

The file's header records what happened, the old name, and why the alternative
fix was refused — so the next reader finds the correction rather than
rediscovering the term.

## D129 — a sanitisation gate must not be vendor-shaped

Found while re-hashing the same file, and the sharper of the two findings.

Decision D66 established that **a non-default SNMP community string is a
credential**, whatever it was invented for, and rewrote the two corpus files
carrying one to `public`. It missed a third. `core-rtr-01.conf` has carried
`community NIRIKSHAK-SAMPLE-RO-COMMUNITY` ever since.

The detector is:

```python
re.compile(r"snmp-server community\s+(?!public\b|private\b)\S+")
```

which is IOS syntax. JunOS nests `community NAME { … }` inside an `snmp` block
and never writes `snmp-server` at all, so the gate **reported clean on the one
file it could not read**.

That is the worst place for a blind spot. A parser that cannot read a vendor
produces UNKNOWN and says so; a *sanitisation* check that cannot read a vendor
produces a pass. The failure mode is silent and points the safe way, which is
why it survived a decision specifically about this class of secret.

Fixed in both directions: the JunOS form is added to `CREDENTIAL_PATTERNS`, and
the community is rewritten to `public` per D66. Verified by order — the pattern
was added first and the file failed, then the file was corrected and it passed.

Nothing measured moves. No pack declares an SNMP pattern (D73), so
`snmp_v3_only` reads UNKNOWN on this device either way; the property the
fixture exists for is untouched.

## A third, smaller one, in a test written this week

`test_the_brace_terms_leave_the_training_queue` asserted
`not remaining & set(range(127, 160))`, with a comment naming the lines the
filter occupied. Adding fourteen header lines to the fixture moved the filter
down and broke it.

A line range **declared beside** the file it describes — written during the
same session that made a rule of not doing that (ADR 0048), which is a fair
measure of how easily the habit reasserts itself. It derives the range from the
file now.

## Consequences

`corpus/MANIFEST.yaml` records the new `sha256` for the file, twice over: once
after the rename and once after the community rewrite. The manifest hash is what
makes "this is the file that was scored" checkable, and leaving it stale would
have been the same class of error as everything above.

The evaluation report is unchanged. `core-rtr-01.conf` is a development file, so
nothing it contains is scored.
