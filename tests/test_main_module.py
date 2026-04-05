from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_python_m_module_runs_scan(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hong@example.com", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "isms_pii_toolkit", "scan", str(sample)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "total_matches" in result.stdout
    assert "email" in result.stdout
