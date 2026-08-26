"""Format detection — CLI text, XML or JSON.

Prefix sniff, then a real parse. A file whose first non-space character is `<`
claims to be XML; if it then fails to parse it is **malformed XML**, not CLI
text. Silently downgrading it would mean parsing a broken PAN-OS export as if it
were Cisco commands, which produces confident nonsense rather than an honest
refusal.
"""

from __future__ import annotations

import json

from api.ingest.validate import ValidationError
from api.models.ingestion import FileFormat, RejectionReason


def sniff(text: str) -> FileFormat:
    """Guess the format from the first meaningful character, without parsing."""
    stripped = text.lstrip()
    if not stripped:
        return FileFormat.CLI
    if stripped.startswith("<"):
        return FileFormat.XML
    if stripped[0] in "{[":
        return FileFormat.JSON
    return FileFormat.CLI


def detect(text: str) -> FileFormat:
    """Determine the format, confirming the sniff with an actual parse."""
    claimed = sniff(text)

    if claimed is FileFormat.XML:
        from lxml import etree

        try:
            parser = etree.XMLParser(resolve_entities=False, no_network=True)
            etree.fromstring(text.encode("utf-8"), parser=parser)
        except etree.XMLSyntaxError as exc:
            raise ValidationError(
                RejectionReason.MALFORMED_XML,
                f"the file begins as XML but does not parse: {exc}",
            ) from exc
        return FileFormat.XML

    if claimed is FileFormat.JSON:
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                RejectionReason.MALFORMED_JSON,
                f"the file begins as JSON but does not parse: {exc}",
            ) from exc
        return FileFormat.JSON

    return FileFormat.CLI
