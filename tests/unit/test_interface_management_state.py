"""Interface management status is three-valued, not two (DEF-2).

`Interface.is_management` is `bool | None`, where `None` means undocumented.
`management_interfaces()` used a truthiness test, and `None` is falsy — so an
interface whose management status we did **not know** was silently returned as
confirmed non-management.

That is the exact substitution Rule 3 forbids, sitting in the one accessor P12's
exposure-aware prioritisation depends on. A management interface we failed to
classify would have been quietly de-prioritised rather than surfaced as
undetermined, and nothing anywhere would have recorded that a question went
unanswered.

Fixed by asking `is True` / `is False` / `is None` explicitly, and by giving the
indeterminate case its own accessor so a caller has to decide what to do about
it rather than receiving it folded into an answer.
"""

from __future__ import annotations

import pytest

from api.models.csm import CanonicalSecurityModel, DeviceIdentity, Interface


def csm_with(*states: bool | None) -> CanonicalSecurityModel:
    return CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"),
        interfaces=tuple(
            Interface(name=f"Gi0/{n}", is_management=state) for n, state in enumerate(states)
        ),
    )


# ---------------------------------------------------------------------------
# The three states, one test each
# ---------------------------------------------------------------------------


def test_is_management_true_is_included() -> None:
    csm = csm_with(True)

    assert [i.name for i in csm.management_interfaces()] == ["Gi0/0"]
    assert csm.non_management_interfaces() == ()
    assert csm.indeterminate_interfaces() == ()


def test_is_management_false_is_confirmed_non_management() -> None:
    csm = csm_with(False)

    assert csm.management_interfaces() == ()
    assert [i.name for i in csm.non_management_interfaces()] == ["Gi0/0"]
    assert csm.indeterminate_interfaces() == ()


def test_is_management_none_is_undetermined_not_false() -> None:
    """The regression. `None` must not be answered as if it were `False`."""
    csm = csm_with(None)

    assert csm.management_interfaces() == ()
    assert csm.non_management_interfaces() == (), (
        "an undocumented interface was reported as CONFIRMED non-management, "
        "which converts ignorance into an answer (Rule 3)"
    )
    assert [i.name for i in csm.indeterminate_interfaces()] == ["Gi0/0"]


# ---------------------------------------------------------------------------
# Together
# ---------------------------------------------------------------------------


def test_the_three_accessors_partition_the_interfaces() -> None:
    """Every interface appears in exactly one bucket, and none is lost."""
    csm = csm_with(True, False, None, True, None)

    buckets = (
        csm.management_interfaces(),
        csm.non_management_interfaces(),
        csm.indeterminate_interfaces(),
    )
    names = [i.name for bucket in buckets for i in bucket]

    assert len(names) == len(csm.interfaces)
    assert set(names) == {i.name for i in csm.interfaces}
    assert len(set(names)) == len(names), "an interface appeared in two buckets"


def test_undetermined_interfaces_are_countable() -> None:
    """P12 needs to know how much it could not classify, not just what it could."""
    csm = csm_with(True, None, None)

    assert len(csm.management_interfaces()) == 1
    assert len(csm.indeterminate_interfaces()) == 2


@pytest.mark.parametrize("state", [True, False, None])
def test_the_model_still_accepts_all_three_states(state: bool | None) -> None:
    """The fix is in the accessor. The model was never wrong and is not weakened."""
    assert Interface(name="Gi0/0", is_management=state).is_management is state


def test_no_interfaces_is_not_an_error() -> None:
    csm = CanonicalSecurityModel(device=DeviceIdentity(device_id="d1"))

    assert csm.management_interfaces() == ()
    assert csm.indeterminate_interfaces() == ()
