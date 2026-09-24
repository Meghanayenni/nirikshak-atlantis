"""The DEF-16 guard, run against a trained pack the training loop produced.

DEF-16 is the defect that actually bit this project. An administrator uploaded a
configuration, worked the Needs-review queue and confirmed what two lines meant.
Both lines came from `corpus/cisco/eval/edge-rtr-11.cfg` — a file whose entire
purpose is to be a regression fixture nobody authors from — and the patterns
compiled from them went into the active Cisco pack, teaching the parser answers
from the split it is measured on. **Nobody misused the interface**; the loop did
exactly what it is built to do.

`test_no_trained_pack_quotes_an_evaluation_or_holdout_line` exists to catch
that. It scans `packs/trained/`, which is gitignored deployment state (D45) and
therefore **empty on every checkout and on CI** — so it has skipped every time
it has ever executed, and the contamination was found by tracing pack examples
back to files by hand.

ADR 0042 gave the *detection function* constructed input. This gives the
**guard** a populated directory, and builds what it scans through
`compile_pattern` → `draft_with_pattern` → `validate` → `activate` rather than
by hand-writing YAML — because the question is whether the guard catches what
the loop produces, and a hand-written pack only proves it catches what a test
author writes.

**This does not close DEF-16.** The loop still has no notion of a corpus split
and an administrator can still do exactly what they did. What changes is that
the detector is no longer unexercised: it is shown catching the real line, on a
pack the real loop wrote. See ADR 0051.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from api.ingest.packs import PACKS_ROOT, load_pack
from api.models.enums import CastType, TrainingOutcome
from api.models.training import TrainingExample
from api.train.activation import activate, draft_with_pattern, validate
from api.train.compile import CompileRequest, compile_pattern
from tests.architecture.test_train_boundaries import contaminated_examples

CONTAMINATED_LINE = "ip ssh server algorithm encryption aes128-cbc"
"""The real thing, from `corpus/cisco/eval/edge-rtr-11.cfg`.

Compiled into `cisco/ios` 1.1.4 through 1.1.6 as `p-weak-ciphers-admin-002`, and
recoverable today only because ADR 0031 committed the deleted trained packs to
`packs/archive/`. It appears in that evaluation file and in no development file,
which is precisely what makes it contamination rather than an ordinary example.
"""

CLEAN_LINE = "ip ssh version 2"
"""From `corpus/cisco/dev/rtr-core-01.cfg` — where an example is meant to come from."""


def confirmation(line: str, field: str) -> TrainingExample:
    """What an administrator's decision looks like by the time it reaches compile."""
    return TrainingExample(
        example_id="trn-contamination-probe",
        vendor="cisco",
        os_family="ios",
        raw_line_scrubbed=line,
        field=field,
        # CORRECTED, not ACCEPTED_RANK_n: the contract refuses an accepted rank
        # unless a suggestion was shown at it, and no model was running when
        # DEF-16 happened. The administrator supplied the field themselves,
        # which is exactly this outcome.
        outcome=TrainingOutcome.CORRECTED,
        confirmed_by="alice",
        audit_seq=7,
    )


def trained_pack_from(line: str, field: str, token: int, trained_root: Path) -> Path:
    """Drive the real loop and return the pack file it wrote.

    Deliberately not a hand-written YAML fixture. The guard's job is to catch
    what an administrator's confirmation turns into, and only the loop can
    produce that — the pattern id, the retained example, the provenance and the
    version bump are all its doing.
    """
    base = load_pack(PACKS_ROOT / "cisco_ios" / "1.4.0.yaml")
    pattern = compile_pattern(
        confirmation(line, field), CompileRequest(value_token=token, cast=CastType.LIST)
    )
    draft = validate(draft_with_pattern(base, pattern))
    result = activate(draft, trained_root=trained_root)
    return Path(result.path)


# ---------------------------------------------------------------------------


@pytest.fixture
def contaminated(tmp_path: Path) -> Path:
    return trained_pack_from(CONTAMINATED_LINE, "weak_ciphers", 5, tmp_path)


@pytest.fixture
def clean(tmp_path: Path) -> Path:
    return trained_pack_from(CLEAN_LINE, "ssh_version", 3, tmp_path)


def test_the_loop_writes_a_pack_that_retains_the_confirmed_line(contaminated: Path) -> None:
    """The precondition, checked so a later assertion cannot pass vacuously.

    If the loop stopped retaining the example — which D44 requires, so a mapping
    can be traced to the person who confirmed it — the guard would find nothing
    to object to and report clean for the wrong reason.
    """
    raw = yaml.safe_load(contaminated.read_text(encoding="utf-8"))
    examples = [ex for p in raw["patterns"] for ex in (p.get("examples") or [])]

    assert CONTAMINATED_LINE in examples


def test_the_guard_detects_a_pack_trained_on_an_evaluation_line(contaminated: Path) -> None:
    """The populated run this guard has never had.

    Not the detection helper against a constructed file — the directory scan,
    over a pack the loop wrote, carrying the exact line that caused the P15
    reset.
    """
    offenders = contaminated_examples([contaminated])

    assert len(offenders) == 1
    assert "aes128-cbc" in offenders[0]
    assert contaminated.name in offenders[0]


def test_the_guard_passes_a_pack_trained_on_a_development_line(clean: Path) -> None:
    """The negative case, or the test above proves only that it flags everything.

    `ip ssh version 2` is in the development split, which is where a confirmed
    example is supposed to come from. A guard that cannot tell this from the
    line above would have to be ignored to get any work done.
    """
    assert contaminated_examples([clean]) == []


def test_the_guard_scans_a_directory_rather_than_one_file(
    contaminated: Path, tmp_path: Path
) -> None:
    """The real scan takes every pack under `packs/trained/`, not the newest.

    A deployment accumulates versions, and the contamination that bit this
    project was in three of them. Checking only the active version would have
    reported clean on a directory holding the answer three times over.
    """
    clean_pack = trained_pack_from(CLEAN_LINE, "ssh_version", 3, tmp_path / "second")
    offenders = contaminated_examples(sorted([contaminated, clean_pack]))

    assert len(offenders) == 1, "the scan must find the one bad pack among several"


def test_the_repository_itself_is_still_clean() -> None:
    """The live directory, whatever it holds on this machine.

    Empty on a checkout, and not empty on a machine somebody has trained. The
    assertion is the same either way, and unlike the architecture-suite scan it
    does not skip: an empty directory is a pass with nothing in it, which is
    true and worth stating rather than absent.
    """
    trained = Path("packs/trained")
    packs = [p for p in trained.rglob("*.yaml") if not p.name.startswith("activation")]

    assert contaminated_examples(packs) == [], (
        "a trained pack on this machine quotes an evaluation line. This is DEF-16 "
        "recurring: reset the trained packs and re-confirm from development files."
    )
