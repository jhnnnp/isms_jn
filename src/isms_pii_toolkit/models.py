from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectedMatch:
    pii_type: str
    value: str
    start: int
    end: int
    validation_method: str


@dataclass(frozen=True, slots=True)
class ProcessedMatch:
    pii_type: str
    original: str
    transformed: str
    strategy: str
    validation_method: str
    start: int
    end: int
