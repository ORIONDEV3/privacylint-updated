from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml


def _project_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "rules" / "dpdp.yaml").is_file():
            return parent
    return Path(__file__).resolve().parents[1]


ROOT = _project_root()
RULES_PATH = ROOT / "rules" / "dpdp.yaml"
REQUIRED_FIELDS = {
    "id", "name", "languages", "sources", "sinks", "sanitizers", "gates",
    "detector", "severity", "dpdp_mapping", "remediation", "patch_template_id",
}
SEVERITIES = {"critical", "high", "medium", "low"}
DPDP_SECTIONS = {"§5", "§8(5)", "§8(6)", "§9"}


@lru_cache(maxsize=1)
def load_rules() -> tuple[dict, ...]:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("rules"), list):
        raise ValueError("Invalid DPDP rules document")
    rules = []
    seen = set()
    for rule in raw["rules"]:
        if not isinstance(rule, dict) or REQUIRED_FIELDS - set(rule):
            raise ValueError("DPDP rule is missing required fields")
        if rule["id"] in seen or rule["severity"] not in SEVERITIES or rule["dpdp_mapping"] not in DPDP_SECTIONS:
            raise ValueError(f"Invalid rule metadata: {rule.get('id', 'unknown')}")
        if not all(isinstance(rule[field], list) for field in ("languages", "sources", "sinks", "sanitizers", "gates")):
            raise ValueError(f"Invalid rule lists: {rule['id']}")
        seen.add(rule["id"])
        rules.append(rule)
    return tuple(rules)


def rules_by_detector() -> dict[str, dict]:
    return {rule["detector"]: rule for rule in load_rules()}
