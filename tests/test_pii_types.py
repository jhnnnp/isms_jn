from __future__ import annotations

from isms_pii_toolkit.patterns import PII_PATTERNS, PII_VALIDATION_METHOD
from isms_pii_toolkit.pii_types import NON_GOALS_PII_CATEGORIES, PiiType, SUPPORTED_PII_TYPES


def test_supported_types_match_pattern_registry() -> None:
    assert set(PiiType) == set(PII_PATTERNS.keys()) == set(PII_VALIDATION_METHOD.keys())
    assert tuple(PiiType) == tuple(SUPPORTED_PII_TYPES)


def test_non_goals_list_is_documented_scope() -> None:
    assert len(NON_GOALS_PII_CATEGORIES) >= 3
    assert all(isinstance(item, str) and item.strip() for item in NON_GOALS_PII_CATEGORIES)
