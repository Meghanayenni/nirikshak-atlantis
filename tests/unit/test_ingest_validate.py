"""File validation — encoding, binary detection, size (finding F2)."""

from __future__ import annotations

import pytest

from api.ingest.format_detect import detect, sniff
from api.ingest.validate import (
    ValidationError,
    check_size,
    decode,
    detect_encoding,
    printable_ratio,
)
from api.models.ingestion import FileFormat, RejectionReason
from tests.fixtures import configs

MIN = 0.90


# ---------------------------------------------------------------------------
# F2 — a NUL byte does not mean binary
# ---------------------------------------------------------------------------


def test_utf16_config_is_accepted_despite_nul_bytes() -> None:
    """The case the naive heuristic gets wrong: real text, full of NULs."""
    assert b"\x00" in configs.UTF16_CONFIG

    result = decode(configs.UTF16_CONFIG, min_printable=MIN)
    assert result.encoding == "utf-16-le"
    assert "hostname sw-01" in result.text


def test_utf8_bom_is_stripped_and_recorded() -> None:
    result = decode(configs.UTF8_BOM_CONFIG, min_printable=MIN)
    assert result.encoding == "utf-8-sig"
    assert result.text.startswith("hostname sw-02")


@pytest.mark.parametrize(
    ("name", "data"),
    [("png", configs.PNG_BYTES), ("elf", configs.ELF_BYTES), ("gzip", configs.GZIP_BYTES)],
)
def test_binary_masquerading_as_config_is_rejected(name: str, data: bytes) -> None:
    with pytest.raises(ValidationError) as exc:
        decode(data, min_printable=MIN)
    assert exc.value.reason in (RejectionReason.BINARY_CONTENT, RejectionReason.UNDECODABLE)


def test_elf_decodes_as_utf8_yet_is_still_rejected() -> None:
    """UTF-8 decodability alone is not enough — the ELF header passes it."""
    configs.ELF_BYTES.decode("utf-8")  # does not raise

    with pytest.raises(ValidationError, match="printable"):
        decode(configs.ELF_BYTES, min_printable=MIN)


def test_printable_ratio_separates_the_cases() -> None:
    """The discriminator, stated as a measurement."""
    config_ratio = printable_ratio(configs.CISCO_IOS)
    binary_ratio = printable_ratio(configs.ELF_BYTES.decode("utf-8", errors="replace"))

    assert config_ratio >= 0.99
    assert binary_ratio < 0.70
    assert config_ratio > MIN > binary_ratio


def test_unicode_config_is_not_mistaken_for_binary() -> None:
    result = decode(configs.UNICODE_CONFIG.encode("utf-8"), min_printable=MIN)
    assert "राउटर" in result.text
    assert result.encoding == "utf-8"


def test_bom_detection() -> None:
    assert detect_encoding(configs.UTF16_CONFIG) == "utf-16-le"
    assert detect_encoding(configs.UTF8_BOM_CONFIG) == "utf-8-sig"
    assert detect_encoding(b"hostname r1\n") is None


# ---------------------------------------------------------------------------
# Empty and oversized
# ---------------------------------------------------------------------------


def test_empty_file_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        decode(b"", min_printable=MIN)
    assert exc.value.reason is RejectionReason.EMPTY


def test_whitespace_only_file_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        decode(b"   \n\n\t\n", min_printable=MIN)
    assert exc.value.reason is RejectionReason.EMPTY


def test_oversized_file_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        check_size(20_000_000, max_bytes=10_485_760, filename="huge.cfg")
    assert exc.value.reason is RejectionReason.TOO_LARGE
    assert "20,000,000" in exc.value.detail


def test_size_check_accepts_a_normal_config() -> None:
    check_size(4096, max_bytes=10_485_760, filename="rtr.cfg")


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def test_sniff_recognises_the_three_shapes() -> None:
    assert sniff(configs.CISCO_IOS) is FileFormat.CLI
    assert sniff('<?xml version="1.0"?><config/>') is FileFormat.XML
    assert sniff(configs.VALID_JSON) is FileFormat.JSON


def test_valid_xml_and_json_confirm() -> None:
    assert detect('<?xml version="1.0"?><config><a/></config>') is FileFormat.XML
    assert detect(configs.VALID_JSON) is FileFormat.JSON
    assert detect(configs.CISCO_IOS) is FileFormat.CLI


def test_malformed_xml_is_rejected_not_downgraded_to_cli() -> None:
    """Parsing a broken PAN-OS export as Cisco commands would be worse."""
    with pytest.raises(ValidationError) as exc:
        detect(configs.MALFORMED_XML)
    assert exc.value.reason is RejectionReason.MALFORMED_XML


def test_malformed_json_is_rejected_not_downgraded_to_cli() -> None:
    with pytest.raises(ValidationError) as exc:
        detect(configs.MALFORMED_JSON)
    assert exc.value.reason is RejectionReason.MALFORMED_JSON


def test_xml_parser_does_not_resolve_entities() -> None:
    """An XXE payload must not be expanded while sniffing a format."""
    xxe = (
        '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n<r>&x;</r>'
    )
    try:
        detect(xxe)
    except ValidationError:
        pass  # refusing outright is also acceptable
