from isms_pii_toolkit.validators import validate_rrn


def test_validate_rrn_accepts_valid_number() -> None:
    assert validate_rrn("900101-1234568")


def test_validate_rrn_rejects_invalid_checksum() -> None:
    assert not validate_rrn("900101-1234567")
