from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

from .detectors import SENSITIVITY

SEVERITY_WEIGHT = {"critical": Decimal("25"), "high": Decimal("15"), "medium": Decimal("8"), "low": Decimal("3")}


def grade_for(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    return "F"


def calculate_score(findings: list[dict], verified_fix_bonus: int = 0) -> dict:
    bonus = max(0, min(10, int(verified_fix_bonus)))
    deductions: list[Decimal] = []
    for finding in findings:
        severity = finding.get("severity", "low")
        category = finding.get("pii_category", "other")
        exploitability = Decimal("1.2") if finding.get("unauthenticated") or finding.get("rule_id") == "PL004" else Decimal("1.0")
        sensitivity = Decimal(str(SENSITIVITY.get(category, SENSITIVITY["other"])))
        deductions.append(SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT["low"]) * sensitivity * exploitability)
    total_deduction = sum(deductions, Decimal(0))
    score = max(Decimal(0), min(Decimal(100), Decimal(100) - total_deduction + Decimal(bonus)))
    score = score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return {
        "score": float(score),
        "grade": grade_for(float(score)),
        "deduction": float(total_deduction),
        "verified_fix_bonus": bonus,
        "formula": "max(0, min(100, 100 - sum(severity_weight × sensitivity × exploitability) + verified_fix_bonus))",
        "weights": {"critical": 25, "high": 15, "medium": 8, "low": 3},
        "sensitivity": {key: float(value) for key, value in SENSITIVITY.items()},
    }
