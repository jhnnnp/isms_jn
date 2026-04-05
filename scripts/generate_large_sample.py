#!/usr/bin/env python3
"""Generate examples/large_sample.txt with many PII test rows (no filler).

Each line is one record: name + valid RRN (checksum) + phone + email.
Stays under isms_pii_toolkit.api.MAX_UPLOAD_BYTES (256 KiB).
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from isms_pii_toolkit.validators import validate_rrn  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "examples" / "large_sample.txt"
LINE_COUNT = 120
MAX_BYTES = 256 * 1024


def _rrn_string(birth6: str, century: int, serial5: int) -> str:
    first12 = f"{birth6}{century}{serial5:05d}"
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    checksum = sum(int(first12[i]) * weights[i] for i in range(12))
    check = (11 - (checksum % 11)) % 10
    full = first12 + str(check)
    return f"{full[:6]}-{full[6:]}"


def _phone(i: int) -> str:
    prefix = ("010", "011", "016", "017", "018", "019")[i % 6]
    if prefix in ("011", "017"):
        mid = 200 + (i % 799)
        last = 1000 + (i * 7) % 9000
        return f"{prefix}-{mid:03d}-{last:04d}"
    mid = 1000 + (i * 13) % 9000
    last = 1000 + (i * 17) % 9000
    return f"{prefix}-{mid:04d}-{last:04d}"


def main() -> None:
    lines: list[str] = [
        "# ISMS-P PII Toolkit - 파일 스캔 테스트 (인위적 예시, 실제 개인정보 아님)\n",
        "# 각 행: 이름, 주민등록번호(체크섬 유효), 휴대전화, 이메일\n",
        "# ---------------------------------------------------------------------------\n",
    ]
    start = date(1990, 1, 1)
    for i in range(LINE_COUNT):
        d = start + timedelta(days=i * 3)
        yy = d.year % 100
        birth6 = f"{yy:02d}{d.month:02d}{d.day:02d}"
        if d.year < 2000:
            century = (1, 2, 5, 6)[i % 4]
        else:
            century = (3, 4, 7, 8)[i % 4]
        serial5 = (i * 97 + 13) % 100000
        rrn = _rrn_string(birth6, century, serial5)
        if not validate_rrn(rrn):
            raise SystemExit(f"Invalid RRN at i={i}: {rrn}")
        phone = _phone(i)
        email = f"large-sample-{i + 1:03d}@example.com"
        lines.append(f"샘플{i + 1:03d} {rrn}, {phone}, {email}\n")

    text = "".join(lines)
    raw = text.encode("utf-8")
    if len(raw) > MAX_BYTES:
        print(f"Output too large: {len(raw)} bytes (max {MAX_BYTES})", file=sys.stderr)
        raise SystemExit(1)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(
        f"Wrote {OUT} ({len(raw)} bytes, {LINE_COUNT} data lines + header)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
