from isms_pii_toolkit.redactor import decrypt_tokens, detect_pii, redact_text


SAMPLE_TEXT = "홍길동 900101-1234568, 010-1234-5678, hong@example.com"


def test_detect_pii_returns_supported_types() -> None:
    matches = detect_pii(SAMPLE_TEXT)
    assert [match.pii_type for match in matches] == ["rrn", "phone", "email"]
    assert [match.validation_method for match in matches] == [
        "rrn_checksum",
        "regex_pattern",
        "regex_pattern",
    ]


def test_redact_text_masks_by_default() -> None:
    redacted, processed = redact_text(SAMPLE_TEXT)
    assert "900101-1******" in redacted
    assert "010-****-5678" in redacted
    assert "h***@example.com" in redacted
    assert {item.strategy for item in processed} == {"mask"}


def test_redact_text_encrypts_requested_types() -> None:
    redacted, processed = redact_text(SAMPLE_TEXT, encrypt_types=["rrn"], encryption_key="a" * 64)
    assert "ENC::rrn::" in redacted
    assert processed[0].strategy == "encrypt"
    assert processed[0].validation_method == "rrn_checksum"
    assert processed[0].start == 4
    assert processed[0].end == 18
    assert decrypt_tokens(redacted, "a" * 64).startswith("홍길동 900101-1234568")
