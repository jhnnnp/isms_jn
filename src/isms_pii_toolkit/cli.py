from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .pii_types import PiiType
from .redactor import decrypt_tokens, detect_pii, redact_text


def _read_input(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8")
    return sys.stdin.read()


def _write_output(path: str | None, content: str) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
        return
    sys.stdout.write(content)


def _resolve_key(cli_key: str | None) -> str | None:
    return cli_key or os.getenv("PII_TOOLKIT_AES_KEY")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isms-pii",
        description="ISMS-P 관점의 개인정보 탐지 및 비식별화 CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="개인정보 패턴을 탐지합니다.")
    scan_parser.add_argument("input", nargs="?", help="분석할 텍스트 파일 경로")

    redact_parser = subparsers.add_parser("redact", help="개인정보를 마스킹 또는 암호화합니다.")
    redact_parser.add_argument("input", nargs="?", help="처리할 텍스트 파일 경로")
    redact_parser.add_argument("-o", "--output", help="출력 파일 경로")
    redact_parser.add_argument(
        "--encrypt-type",
        dest="encrypt_types",
        action="append",
        choices=[member.value for member in PiiType],
        default=[],
        help="암호화 대상으로 지정할 개인정보 유형",
    )
    redact_parser.add_argument("--key", help="AES-256 암호화에 사용할 키")

    decrypt_parser = subparsers.add_parser("decrypt", help="암호화 토큰을 복호화합니다.")
    decrypt_parser.add_argument("input", nargs="?", help="복호화할 텍스트 파일 경로")
    decrypt_parser.add_argument("-o", "--output", help="출력 파일 경로")
    decrypt_parser.add_argument("--key", help="AES-256 복호화에 사용할 키")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        text = _read_input(args.input)
        matches = detect_pii(text)
        counts = Counter(match.pii_type for match in matches)
        payload = {
            "total_matches": len(matches),
            "counts": dict(counts),
            "matches": [asdict(match) for match in matches],
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return 0

    if args.command == "redact":
        text = _read_input(args.input)
        key = _resolve_key(args.key)
        redacted_text, processed = redact_text(
            text,
            encrypt_types=args.encrypt_types,
            encryption_key=key,
        )
        _write_output(args.output, redacted_text)
        if not args.output and not redacted_text.endswith("\n"):
            sys.stdout.write("\n")
        sys.stderr.write(
            json.dumps(
                {
                    "processed": len(processed),
                    "encrypted_types": args.encrypt_types,
                },
                ensure_ascii=False,
            )
        )
        sys.stderr.write("\n")
        return 0

    if args.command == "decrypt":
        text = _read_input(args.input)
        key = _resolve_key(args.key)
        if not key:
            parser.error("decrypt 명령은 --key 또는 PII_TOOLKIT_AES_KEY 환경 변수가 필요합니다.")
        decrypted = decrypt_tokens(text, key)
        _write_output(args.output, decrypted)
        if not args.output and not decrypted.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    return 1
