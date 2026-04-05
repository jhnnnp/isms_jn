from __future__ import annotations

import re
from collections.abc import Iterable

from .crypto import decrypt_text, encrypt_text
from .models import DetectedMatch, ProcessedMatch
from .patterns import PII_PATTERNS, PII_VALIDATION_METHOD
from .pii_types import PiiType


ENCRYPTED_TOKEN_PATTERN = re.compile(r"ENC::(?P<pii_type>[a-z_]+)::(?P<payload>[A-Za-z0-9_\-=]+)")


def detect_pii(text: str) -> list[DetectedMatch]:
    matches: list[DetectedMatch] = []
    occupied_ranges: list[tuple[int, int]] = []

    for pii_type, (pattern, validator) in PII_PATTERNS.items():
        for result in pattern.finditer(text):
            value = result.group(0)
            start, end = result.span()
            if any(not (end <= left or start >= right) for left, right in occupied_ranges):
                continue
            if validator(value):
                matches.append(
                    DetectedMatch(
                        pii_type=pii_type.value,
                        value=value,
                        start=start,
                        end=end,
                        validation_method=PII_VALIDATION_METHOD[pii_type],
                    )
                )
                occupied_ranges.append((start, end))

    return sorted(matches, key=lambda item: item.start)


def mask_value(pii_type: str, value: str) -> str:
    if pii_type == "rrn":
        digits = "".join(character for character in value if character.isdigit())
        return f"{digits[:6]}-{digits[6]}******"
    if pii_type == "phone":
        digits = "".join(character for character in value if character.isdigit())
        middle_length = len(digits) - 7
        return f"{digits[:3]}-{'*' * middle_length}-{digits[-4:]}"
    if pii_type == "email":
        local, domain = value.split("@", maxsplit=1)
        visible = local[:1]
        return f"{visible}{'*' * max(len(local) - 1, 1)}@{domain}"
    return "*" * len(value)


def redact_text(
    text: str,
    encrypt_types: Iterable[str | PiiType] | None = None,
    encryption_key: str | None = None,
) -> tuple[str, list[ProcessedMatch]]:
    encrypted = {str(item) for item in (encrypt_types or [])}
    processed_matches: list[ProcessedMatch] = []
    parts: list[str] = []
    cursor = 0

    for match in detect_pii(text):
        parts.append(text[cursor:match.start])
        strategy = "encrypt" if str(match.pii_type) in encrypted else "mask"
        if strategy == "encrypt":
            if not encryption_key:
                raise ValueError("Encryption key is required when encryption is enabled.")
            transformed = f"ENC::{match.pii_type}::{encrypt_text(match.value, encryption_key)}"
        else:
            transformed = mask_value(match.pii_type, match.value)

        parts.append(transformed)
        processed_matches.append(
            ProcessedMatch(
                pii_type=match.pii_type,
                original=match.value,
                transformed=transformed,
                strategy=strategy,
                validation_method=match.validation_method,
                start=match.start,
                end=match.end,
            )
        )
        cursor = match.end

    parts.append(text[cursor:])
    return "".join(parts), processed_matches


def decrypt_tokens(text: str, encryption_key: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return decrypt_text(match.group("payload"), encryption_key)

    return ENCRYPTED_TOKEN_PATTERN.sub(replace, text)
