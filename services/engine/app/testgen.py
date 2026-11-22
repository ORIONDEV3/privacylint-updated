from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .rules import ROOT


SINKS = {
    "log": r"(?:console\s*\.\s*(?:log|info|warn|error|debug)|logger\s*\.|\bprint\s*\(|\bprintf\s*\(|System\s*\.\s*out)",
    "response": r"(?:\b(?:res|response)\s*\.\s*(?:json|send|write)\s*\(|\bjsonify\s*\()",
    "database": r"(?:\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\.(?:insert|create|save|update|execute|query)\s*\()",
    "unauthenticated_route": r"\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete)\s*\(",
    "weak_hash": r"\b(?:md5|sha1)\s*\(",
    "third_party": r"\b(?:fetch|axios\s*\.|requests\s*\.|httpx\s*\.|analytics|track)\b",
    "client_storage": r"\b(?:localStorage|sessionStorage|indexedDB)\s*\.",
    "children_data": r"\b(?:child|children|minor|guardian|parental|dob|date_of_birth)\b",
    "http_transport": r"https?://",
    "error": r"\b(?:throw\s+new\s+Error|raise\s+\w*Error|new\s+Error)",
    "hardcoded_secret": r"\b(?:api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b\s*[:=]",
}
SAFE_PATTERNS = {
    "PL001": r"\b(?:mask|redact|sanitize|tokenize|hash_fields|to_safe_dto)\w*\s*\(",
    "PL002": r"\b(?:dto|project|select|omit|redact|mask|to_safe_dto)\w*\s*\(",
    "PL003": r"\b(?:encrypt|cipher|tokeniz|seal)\w*\s*\(",
    "PL004": r"\b(?:auth|authenticate|requireauth|require_role|requireRole|protect|authorize|isAuthenticated|verify_token)\w*\b",
    "PL005": r"\b(?:bcrypt|argon2|scrypt|pbkdf2)\w*\s*\(",
    "PL006": r"\b(?:minimize|redact|sanitize|consent|allowlisted)\w*\s*\(",
    "PL007": r"\b(?:encrypt|tokenize|remove|clear)\w*\s*\(",
    "PL008": r"\b(?:process\.env|os\.environ|environment|getenv|secretmanager|keyvault)\b",
    "PL009": r"\b(?:parental|guardian|verified_consent|consent_required)\w*\b",
    "PL010": r"\b(?:delete|erase|erasure|anonymi[sz]e|retention|purge)\b",
    "PL011": r"https://",
    "PL012": r"\b(?:generic|redact|sanitize|error_id|request_id)\w*\b",
}
PII_PATTERNS = {
    "aadhaar": r"aadhaar|aadhar|uidai|uid_number", "pan": r"pan|tax_id", "phone": r"phone|mobile|telephone",
    "email": r"email", "financial": r"card|account_number|upi|bank|ifsc", "health": r"health|medical|patient|biometric|diagnosis",
    "children": r"child|minor|guardian|parental|date_of_birth|\bdob\b", "location": r"location|gps|latitude|longitude|address|pincode",
    "contact": r"name|contact|user_id|device_id", "credential": r"password|secret|token|api_key|private_key", "ip": r"ip_address",
    "other": r"personal_data|pii|sensitive_data",
}
TEMPLATE_BY_FRAMEWORK = {"node:test": "node.test.j2", "jest": "jest.test.j2", "mocha": "mocha.test.j2", "pytest": "pytest.test.j2", "junit5": "junit5.test.j2"}
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
environment = Environment(loader=FileSystemLoader(ROOT / "templates" / "tests"), undefined=StrictUndefined, autoescape=False, trim_blocks=True, lstrip_blocks=True)


def detect_framework(files: dict[str, bytes]) -> tuple[str, str | None]:
    names = {name.lower() for name in files}
    package_file = next((content for name, content in files.items() if name.lower().endswith("package.json")), None)
    if package_file:
        try:
            package = json.loads(package_file)
            dependencies = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
            if "jest" in dependencies:
                return "jest", None
            if "mocha" in dependencies:
                return "mocha", None
        except (ValueError, AttributeError):
            pass
        return "node:test", None
    if any(name.endswith((".py", "requirements.txt")) for name in names):
        has_pytest = any("pytest" in content.decode("utf-8", errors="ignore").lower() for name, content in files.items() if "requirements" in name.lower() or name.lower().endswith("pyproject.toml"))
        return "pytest", None if has_pytest else "pytest>=8.3,<9\n"
    if any(name.endswith(("pom.xml", ".java")) for name in names):
        has_junit = any(b"junit-jupiter" in content for name, content in files.items() if name.lower().endswith("pom.xml"))
        config = None if has_junit else "<dependency>\n  <groupId>org.junit.jupiter</groupId>\n  <artifactId>junit-jupiter</artifactId>\n  <version>5.11.4</version>\n  <scope>test</scope>\n</dependency>\n"
        return "junit5", config
    return "pytest", "pytest>=8.3,<9\n"


def generate_regression_test(finding: dict, scan_metadata: dict) -> dict:
    rule_id = finding.get("rule_id", "")
    if rule_id not in SAFE_PATTERNS or finding.get("sink_type") not in SINKS:
        return {"supported": False, "guidance": finding.get("remediation", "Review the finding and add a regression test."), "dpdp_section": finding.get("dpdp_section")}
    source_path = str(PurePosixPath(finding.get("file", "")).as_posix())
    pure = PurePosixPath(source_path)
    if not source_path or pure.is_absolute() or ".." in pure.parts:
        raise ValueError("Finding has an unsafe source path")
    category = finding.get("pii_category", "other")
    framework = scan_metadata.get("test_framework", "node:test" if pure.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"} else "pytest")
    if framework not in TEMPLATE_BY_FRAMEWORK:
        framework = "pytest"
    setup = scan_metadata.get("test_setup_config")
    test_name = f"privacylint_{rule_id}_{re.sub(r'[^a-z0-9]+', '_', category.lower()).strip('_')}"
    if framework == "pytest":
        test_path = f"tests/privacy/test_{test_name}.py"
    elif framework == "junit5":
        test_path = f"src/test/java/PrivacyLint{rule_id}RegressionTest.java"
    else:
        extension = ".test.js" if framework in {"jest", "mocha"} else ".test.cjs"
        test_path = f"tests/privacy/{test_name}{extension}"
    source_relative = PurePosixPath("..", "..", *pure.parts).as_posix()
    template_name = TEMPLATE_BY_FRAMEWORK[framework]
    title = f"{rule_id} {SEVERITY_LABEL.get(finding.get('severity'), 'Privacy')} flow is protected"
    context = {
        "rule_id": rule_id, "title": title, "method_name": f"{test_name}_is_protected",
        "source_relative_path": source_relative, "source_repo_path": source_path,
        "sink_pattern": SINKS[finding["sink_type"]],
        "pii_pattern": PII_PATTERNS.get(category, PII_PATTERNS["other"]), "safe_pattern": SAFE_PATTERNS[rule_id],
    }
    if rule_id == "PL004" and finding.get("route"):
        route_path = str(finding["route"]).split()[-1]
        context["pii_pattern"] = re.escape(route_path)
    template = environment.get_template(template_name)
    content = template.render(**context).rstrip() + "\n"
    run = {"node:test": f"node --test {test_path}", "jest": f"npx jest {test_path}", "mocha": f"npx mocha {test_path}", "pytest": f"pytest {test_path}", "junit5": "mvn test"}[framework]
    ci_snippet = f"- name: PrivacyLint regression tests\n  run: {run}"
    setup_file = "requirements-privacylint.txt" if framework == "pytest" else "pom.xml" if framework == "junit5" else None
    return {
        "supported": True, "framework": framework, "path": test_path, "content": content,
        "ci_snippet": ci_snippet,
        "setup_config": {"path": setup_file, "content": setup} if setup and setup_file else None,
        "dpdp_section": finding.get("dpdp_section"),
        "assertions_hash": hashlib_sha256(content),
    }


def hashlib_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
