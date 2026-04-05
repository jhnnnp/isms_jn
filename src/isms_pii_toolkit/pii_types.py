"""Supported PII scope and explicit non-goals (README and API stay in sync with this module)."""

from __future__ import annotations

from enum import StrEnum


class PiiType(StrEnum):
    """탐지·비식별화 대상으로 구현된 유형(단일 소스)."""

    RRN = "rrn"
    PHONE = "phone"
    EMAIL = "email"


SUPPORTED_PII_TYPES: tuple[PiiType, ...] = tuple(PiiType)

NON_GOALS_PII_CATEGORIES: tuple[str, ...] = (
    "이름·실명(문맥 기반 식별)",
    "주소·상세 위치",
    "계좌·카드번호",
    "IP 주소·쿠키 등 온라인 식별자(별도 규격 없음)",
    "기타 주민등록번호·휴대전화·이메일 형식이 아닌 개인정보",
)
