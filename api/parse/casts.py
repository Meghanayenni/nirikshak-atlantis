"""Converting captured text to typed values.

Every cast either succeeds exactly or raises. There is no fallback, no partial
parse, no "close enough": a malformed value produces no fact, which is the only
honest outcome when the configuration does not say what we thought it said.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from api.models.enums import CastType
from api.parse.errors import CastError

TRUE_TOKENS = frozenset({"true", "yes", "on", "enable", "enabled", "1"})
FALSE_TOKENS = frozenset({"false", "no", "off", "disable", "disabled", "0"})


def cast_int(raw: str) -> int:
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise CastError(raw, "int") from exc


def cast_bool(raw: str) -> bool:
    token = raw.strip().lower()
    if token in TRUE_TOKENS:
        return True
    if token in FALSE_TOKENS:
        return False
    raise CastError(raw, "bool", "expected a yes/no token")


def cast_str(raw: str) -> str:
    return raw.strip()


def cast_cidr(raw: str) -> str:
    try:
        return str(ipaddress.ip_network(raw.strip(), strict=False))
    except ValueError as exc:
        raise CastError(raw, "cidr", str(exc)) from exc


def cast_duration(raw: str) -> int:
    """Normalise a duration to whole seconds.

    Two accepted forms, both common in device configuration:

        "600"       -> 600      seconds
        "10 0"      -> 600      minutes and seconds, as Cisco writes exec-timeout

    A platform expressing durations some third way needs a new cast rather than
    a looser one here. That is a code change, and decision R14 already commits us
    to saying so plainly rather than pretending every platform is data-only.
    """
    parts = raw.strip().split()
    try:
        if len(parts) == 1:
            seconds = int(parts[0])
        elif len(parts) == 2:
            seconds = int(parts[0]) * 60 + int(parts[1])
        else:
            raise CastError(raw, "duration", "expected '<seconds>' or '<minutes> <seconds>'")
    except ValueError as exc:
        raise CastError(raw, "duration", "non-numeric component") from exc

    if seconds < 0:
        raise CastError(raw, "duration", "negative duration")
    return seconds


_SCALAR_CASTS = {
    CastType.INT: cast_int,
    CastType.BOOL: cast_bool,
    CastType.STR: cast_str,
    CastType.CIDR: cast_cidr,
    CastType.DURATION: cast_duration,
}


def cast_value(raw: str, cast: CastType) -> Any:
    """Convert one captured string. `LIST` casts its element as a string.

    A list-typed field accumulates across matches rather than parsing a
    delimited value, so at the level of a single capture it behaves as `str`.
    """
    if cast is CastType.LIST:
        return cast_str(raw)
    handler = _SCALAR_CASTS.get(cast)
    if handler is None:  # pragma: no cover - CastType is closed
        raise CastError(raw, str(cast), "no handler for this cast type")
    return handler(raw)


def is_multi_valued(cast: CastType) -> bool:
    """Whether repeated matches accumulate rather than conflict.

    `ntp server` appearing twice is two servers; `ip ssh version` appearing twice
    with different numbers is a contradiction. The cast is what distinguishes
    them, so the pack author states it once rather than the engine guessing.
    """
    return cast is CastType.LIST
