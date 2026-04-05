from __future__ import annotations

import re
from typing import Callable, Literal

from .pii_types import PiiType
from .validators import validate_rrn


PatternValidator = Callable[[str], bool]

ValidationMethod = Literal["rrn_checksum", "regex_pattern"]

PII_VALIDATION_METHOD: dict[PiiType, ValidationMethod] = {
    PiiType.RRN: "rrn_checksum",
    PiiType.PHONE: "regex_pattern",
    PiiType.EMAIL: "regex_pattern",
}


def _always_valid(_: str) -> bool:
    return True


PII_PATTERNS: dict[PiiType, tuple[re.Pattern[str], PatternValidator]] = {
    PiiType.RRN: (
        re.compile(r"(?<!\d)(\d{6})[- ]?([1-8]\d{6})(?!\d)"),
        validate_rrn,
    ),
    PiiType.PHONE: (
        re.compile(r"(?<!\d)(01[016789])[- ]?(\d{3,4})[- ]?(\d{4})(?!\d)"),
        _always_valid,
    ),
    PiiType.EMAIL: (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        _always_valid,
    ),
}
