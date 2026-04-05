from __future__ import annotations

from datetime import date


def digits_only(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def validate_rrn(value: str) -> bool:
    digits = digits_only(value)
    if len(digits) != 13:
        return False

    birth = digits[:6]
    serial = digits[6:]
    century_code = serial[0]

    if century_code not in "12345678":
        return False

    century = 1900 if century_code in "1256" else 2000
    try:
        date(century + int(birth[:2]), int(birth[2:4]), int(birth[4:6]))
    except ValueError:
        return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    checksum = sum(int(number) * weight for number, weight in zip(digits[:12], weights))
    verifier = (11 - (checksum % 11)) % 10
    return verifier == int(digits[-1])
