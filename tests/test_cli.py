from __future__ import annotations

import json

import pytest

from isms_pii_toolkit.cli import main


def test_scan_command_emits_json(monkeypatch, capsys, tmp_path) -> None:
    sample_file = tmp_path / "sample.log"
    sample_file.write_text("홍길동 900101-1234568 hong@example.com", encoding="utf-8")

    monkeypatch.setattr("sys.argv", ["isms-pii", "scan", str(sample_file)])
    exit_code = main()

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["total_matches"] == 2
    assert payload["counts"] == {"rrn": 1, "email": 1}
    assert payload["matches"][0]["validation_method"] == "rrn_checksum"


def test_redact_command_writes_stdout_and_stderr(monkeypatch, capsys, tmp_path) -> None:
    sample_file = tmp_path / "in.log"
    sample_file.write_text("hong@example.com", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["isms-pii", "redact", str(sample_file)])
    exit_code = main()
    assert exit_code == 0
    out = capsys.readouterr()
    assert "h***@example.com" in out.out
    meta = json.loads(out.err.strip())
    assert meta["processed"] == 1


def test_decrypt_command_requires_key(monkeypatch, capsys, tmp_path) -> None:
    sample_file = tmp_path / "enc.log"
    sample_file.write_text("ENC::rrn::abc", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["isms-pii", "decrypt", str(sample_file)])
    monkeypatch.delenv("PII_TOOLKIT_AES_KEY", raising=False)
    with pytest.raises(SystemExit):
        main()
