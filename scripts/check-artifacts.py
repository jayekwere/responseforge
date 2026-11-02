from __future__ import annotations

import json
import re
from pathlib import Path

# Keep the publish set explicit so temporary databases and CA keys cannot enter it.
PUBLIC = [
    "coverage.xml",
    "docs/workbench.png",
    "samples/output.json",
    "artifacts/output.json",
    "artifacts/container-demo.json",
    "artifacts/python-dependency-audit.json",
    "artifacts/recovery-output.json",
]
for item in PUBLIC:
    file = Path(item)
    if not file.exists():
        continue
    if file.is_symlink() or file.stat().st_size > 8 * 1024 * 1024:
        raise SystemExit("Public evidence file boundary rejected")
    if file.suffix != ".png":
        data = file.read_bytes()
        candidates = [data]
        if file.suffix == ".json":
            pending = [json.loads(data)]
            inspected = 0
            while pending:
                inspected += 1
                if inspected > 100000:
                    raise SystemExit("Public JSON evidence exceeds the bounded item count")
                value = pending.pop()
                if isinstance(value, str):
                    candidates.append(value.encode())
                elif isinstance(value, dict):
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
        if any(re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", item) for item in candidates):
            raise SystemExit("Private key material cannot enter public evidence")
print("Explicit public evidence set contains no private key material")
