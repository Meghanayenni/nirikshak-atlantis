"""Ingestion's per-field identity becomes the canonical model's flat identity.

Two types, deliberately different shapes:

  `DetectedDeviceIdentity`  ingestion-side — each attribute is a `Field[str]`
                            carrying its own evidence and abstaining separately
  `DeviceIdentity`          CSM-side — resolved strings, plus a `device_id`

The conversion collapses the first into the second, and the only rule that
matters is that **an abstaining field becomes `None`, never a guess**. A device
whose serial could not be read has no serial, not an empty string and not a
value borrowed from somewhere else.

Both types were named `DeviceIdentity` before P5 (DEF-1). This module is the
reason the ingestion one was renamed: it is the one place that holds both at
once, and an ambiguous import here would have silently produced the wrong class.
"""

from __future__ import annotations

from api.models.csm import DeviceIdentity
from api.models.ingestion import DetectedDeviceIdentity


def to_canonical_identity(
    detected: DetectedDeviceIdentity,
    *,
    device_id: str,
    vendor: str | None,
    os_family: str | None,
) -> DeviceIdentity:
    """Flatten a detected identity into the canonical one.

    `device_id` is supplied by the caller rather than derived here. At P5 it is
    the ingested file's content hash, which identifies *this configuration* and
    not the physical device over time — DEF-3, deferred. Keeping the value an
    argument means the later fix is a change at the call site rather than in the
    canonical model.

    `role`, `site` and `peer_group` stay `None`. They are operator metadata with
    no source in a configuration file, and inventing them would be exactly the
    kind of plausible-looking fabrication the rest of the system refuses.
    """
    known = detected.known_fields()

    return DeviceIdentity(
        device_id=device_id,
        hostname=known.get("hostname"),
        vendor=vendor,
        os_family=os_family,
        os_version=known.get("os_version"),
        model=known.get("model"),
        serial=known.get("serial"),
    )
