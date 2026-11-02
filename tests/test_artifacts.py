from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "marker", ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
)
def test_public_evidence_rejects_private_material(tmp_path: Path, marker: str) -> None:
    script = Path("scripts/check-artifacts.py").resolve()
    output = tmp_path / "artifacts/output.json"
    output.parent.mkdir()
    output.write_text('{"synthetic": true}')
    assert (
        subprocess.run([sys.executable, str(script)], cwd=tmp_path, capture_output=True).returncode
        == 0
    )
    output.write_text(
        json.dumps({"sample": "-----BEGIN " + marker + "-----\nsynthetic-rejection-fixture"})
    )
    assert (
        subprocess.run([sys.executable, str(script)], cwd=tmp_path, capture_output=True).returncode
        != 0
    )

    output.write_text(
        json.dumps({"sample": "-----BEGIN " + marker + "-----"}).replace("-", "\\u002d")
    )
    assert (
        subprocess.run([sys.executable, str(script)], cwd=tmp_path, capture_output=True).returncode
        != 0
    )
