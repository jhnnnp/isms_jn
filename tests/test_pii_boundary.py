"""오탐·미탐이 나기 쉬운 경계 문자열(한계를 테스트로 고정)."""

from __future__ import annotations

from isms_pii_toolkit.redactor import detect_pii


def test_invalid_rrn_checksum_not_detected() -> None:
    """형식은 비슷하나 체크섬이 틀린 번호는 주민번호로 보지 않는다."""
    text = "번호 900101-1234567 입니다"
    assert detect_pii(text) == []


def test_legacy_area_code_not_detected_as_mobile() -> None:
    """01[016789] 외 접두(예: 012)는 휴대전화 패턴에서 제외한다."""
    text = "연락처 012-1234-5678"
    types = [m.pii_type for m in detect_pii(text)]
    assert "phone" not in types


def test_plain_korean_without_identifiers_is_empty() -> None:
    """숫자·이메일 형식이 없으면 탐지 결과가 없다."""
    assert detect_pii("안녕하세요 오늘 날씨가 좋네요") == []


def test_rrn_like_sequence_fails_validation() -> None:
    """13자리처럼 보이나 검증을 통과하지 못하는 경우."""
    text = "id=123456-1234567"
    assert detect_pii(text) == []
