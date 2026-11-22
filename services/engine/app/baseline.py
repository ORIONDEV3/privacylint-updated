from __future__ import annotations

import json
from pathlib import Path


def finding_key(finding: dict) -> str:
    return str(finding.get("id", ""))


def read_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("finding_keys"), list):
        raise ValueError("Baseline file must have version 1 and a finding_keys list")
    if any(not isinstance(item, str) for item in data["finding_keys"]):
        raise ValueError("Baseline finding keys must be strings")
    return set(data["finding_keys"])


def write_baseline(path: Path, scan: dict) -> None:
    data = {
        "version": 1,
        "scan_hash": scan.get("scan_hash"),
        "finding_keys": sorted({finding_key(item) for item in scan.get("findings", [])}),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
