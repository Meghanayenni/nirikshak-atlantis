"""Facts an input type cannot carry, however good the parser is.

`DeviceIdentity.serial` has been `None` on every device NIRIKSHAK has ever read,
and until P18 the repository described that as a gap in its parsing — a pattern
nobody had authored yet, sitting in `SOURCING_BACKLOG` beside the rest.

**It is not a parsing gap.** A serial number is inventory data. It appears in
`show version` and `show inventory` output and not in a configuration export, so
no pattern over a running-config can extract one. Authoring a `serial` pattern
would put a regex in a pack that no input could ever satisfy — the failure
DEVELOPER_GUIDE.md §3 names: *"a field that is present in the schema but never matches
looks supported while producing UNKNOWN forever."*

## Why this is not `PlatformCapability`

That contract says whether **a platform** can express a control, and
`supported: false` resolves to `ABSENT_UNSUPPORTED`, a determinable state a
compliance rule may act on. Neither fits.

NX-OS *can* express a serial. Every platform here can. What cannot carry it is
the **input type** — and a claim scoped to the input is provable from this
project's own contract, while a claim scoped to the platform would need vendor
documentation this repository does not have (`SOURCING_BACKLOG` gap 2). Recording
it as a platform limitation would be both unsourced and wrong.

So this is a product-level statement about what NIRIKSHAK ingests, it lives
beside the contracts rather than inside a vendor pack, and it requires no
citation because it is not a claim about anybody else's equipment.

## The clean way to close it

Accept `show version` / `show inventory` output as a **second input type**
alongside configuration exports, and let a pack declare identity patterns
scoped to it. `SourceType` already distinguishes artefacts and `Evidence`
already records which one a citation came from, so the contracts are in place.

That is not built, and this module is not a plan to build it. It is the
statement of what would be needed, recorded where the absence is, so the next
reader finds the answer rather than the gap. See ADR 0044.
"""

from __future__ import annotations

from api.models.enums import SourceType

NOT_DETERMINABLE: dict[SourceType, dict[str, str]] = {
    SourceType.CLI: {
        "serial": (
            "A serial number is inventory data. It appears in `show version` and "
            "`show inventory` output, not in a configuration export, so no pattern "
            "over this input can extract one. Reading it needs a second input type, "
            "not a better parser."
        ),
    },
}
"""Per input type, the identity fields that input cannot carry, and why.

Deliberately small. An entry here is a statement that **no pack will ever read
this field from this input**, which is a stronger claim than "nobody has written
the pattern yet" and must not be used for the second thing. A field that is
merely unparsed today belongs in `SOURCING_BACKLOG`, where somebody can close
it by writing a pattern.
"""


def not_determinable(field: str, source_type: SourceType = SourceType.CLI) -> str | None:
    """The reason this input cannot carry the field, or None if it can.

    `None` means only that this module makes no claim — the field may still be
    absent, unparsed or UNKNOWN for any of the ordinary reasons. Absence of a
    limit is not a promise of a value.
    """
    return NOT_DETERMINABLE.get(source_type, {}).get(field)


def limited_fields(source_type: SourceType = SourceType.CLI) -> frozenset[str]:
    return frozenset(NOT_DETERMINABLE.get(source_type, {}))
