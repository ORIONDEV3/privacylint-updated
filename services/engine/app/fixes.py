from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .detectors import redact_sensitive
from .rules import ROOT
from .scanner import scan_files, _parse_file


PATCH_ENV = Environment(loader=FileSystemLoader(ROOT / "templates" / "patches"), undefined=StrictUndefined, autoescape=False, trim_blocks=True, lstrip_blocks=True)
LOG_LINE = re.compile(r"^(\s*)(console|logger|log)\s*\.\s*(log|info|warn|error|debug)\s*\(.*\)\s*(;?)\s*$", re.IGNORECASE)
RESPONSE_LINE = re.compile(r"^(\s*)(res|response)\s*\.\s*(json|send|write)\s*\(.*\)\s*(;?)\s*$", re.IGNORECASE)
ROUTE_LINE = re.compile(r"^(\s*)(app|router|server)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['\"`][^'\"`]+['\"`])\s*,\s*(.+?)\s*\)\s*(;?)\s*$", re.IGNORECASE)
HASH_CALL = re.compile(r"\b(?:md5|sha1)\s*\(([^()]*)\)", re.IGNORECASE)
DB_CALL = re.compile(r"(\b(?:\w+\s*\.\s*)?(?:insert|create|save|update|execute|query)\s*\()(.*)(\)\s*;?)", re.IGNORECASE)
SECRET_ASSIGN = re.compile(r"^(\s*(?:(?:const|let|var)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(['\"])[^'\"]*\3(\s*;?\s*)$")
HTTP_LITERAL = re.compile(r"http://", re.IGNORECASE)
SECRET_LITERAL = re.compile(r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b\s*[:=]\s*(['\"])[^'\"]{8,}\1")
PYTHON_SECRET_VALUE = re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b(\s*=\s*)(['\"])([^'\"\r\n]{8,})\3")
JS_SECRET_VALUE = re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b(\s*[:=]\s*)(['\"`])([^'\"`\r\n]{8,})\3")


def _render(name: str, **context) -> str:
    return PATCH_ENV.get_template(name).render(**context).rstrip("\r\n")


def _secret_environment_name(path: str, field: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", field).strip("_").upper()
    lower_path = path.lower()
    scope = "BARCHART" if "barchart" in lower_path else "DB" if any(part in {"db", "database"} for part in PurePosixPath(path).parts[:-1]) else "SERVICE"
    return normalized if normalized.startswith(f"{scope}_") else f"{scope}_{normalized}"


def _safe_secret_plan_candidate(path: str, before: str, after: str, line_index: int, original_line: str, env_name: str) -> dict:
    preview = redact_sensitive(make_unified_diff(path, before, after))
    plan = json.dumps({
        "environment_variable": env_name,
        "file": path,
        "kind": "privacylint.secret-env.v1",
        "line": line_index + 1,
        "source_line_sha256": hashlib.sha256(original_line.encode("utf-8")).hexdigest(),
    }, sort_keys=True, separators=(",", ":"))
    return {
        "file": path, "before": before, "after": after, "patch": plan, "patch_preview": preview,
        "template_id": "move_secret_to_env", "assumptions": [f"Set {env_name} in the runtime secret manager before starting this client."],
        "tier": "Template",
    }


def _python_secret_candidate(finding: dict, path: str, before: str, environment_variable: str | None = None) -> dict | None:
    lines = before.splitlines(keepends=True)
    line_index = int(finding.get("line", 0)) - 1
    if line_index < 0 or line_index >= len(lines):
        return None
    original = lines[line_index]
    line = original.rstrip("\r\n")
    ending = original[len(line):]
    match = PYTHON_SECRET_VALUE.search(line)
    if not match:
        return None
    try:
        module = ast.parse(before)
    except SyntaxError:
        return None

    field = re.sub(r"[^A-Za-z0-9]+", "_", match.group(1)).strip("_").upper()
    env_name = environment_variable or _secret_environment_name(path, field)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", env_name):
        return None
    binding = None
    for statement in module.body:
        if statement.lineno >= line_index + 1:
            continue
        if isinstance(statement, ast.Import):
            binding = next((alias.asname or "os" for alias in statement.names if alias.name == "os"), None)
        if binding:
            break

    import_at = None
    if not binding:
        names = set(re.findall(r"\b[A-Za-z_]\w*\b", before))
        binding = "_privacylint_os"
        suffix = 2
        while binding in names:
            binding = f"_privacylint_os_{suffix}"
            suffix += 1
        import_at = 0
        body_index = 0
        if module.body and isinstance(module.body[0], ast.Expr) and isinstance(getattr(module.body[0], "value", None), ast.Constant) and isinstance(module.body[0].value.value, str):
            import_at = module.body[0].end_lineno or module.body[0].lineno
            body_index = 1
        while body_index < len(module.body):
            statement = module.body[body_index]
            if isinstance(statement, ast.ImportFrom) and statement.module == "__future__":
                import_at = statement.end_lineno or statement.lineno
                body_index += 1
                continue
            break
        if import_at == 0:
            for index, source_line in enumerate(lines):
                if not source_line.strip() or source_line.lstrip().startswith("#"):
                    import_at = index + 1
                else:
                    break
        import_at = min(import_at, line_index)

    replacement = line[:match.start(3)] + f'{binding}.environ["{env_name}"]' + line[match.end(4) + 1:]
    patched_lines = list(lines)
    patched_lines[line_index] = replacement + ending
    if import_at is not None:
        newline = "\r\n" if "\r\n" in before else "\n"
        patched_lines.insert(import_at, f"import os as {binding}{newline}")
    after = "".join(patched_lines)
    return _safe_secret_plan_candidate(path, before, after, line_index, line, env_name)


def _javascript_secret_candidate(finding: dict, path: str, before: str, environment_variable: str | None = None) -> dict | None:
    lines = before.splitlines(keepends=True)
    line_index = int(finding.get("line", 0)) - 1
    if line_index < 0 or line_index >= len(lines):
        return None
    original = lines[line_index]
    line = original.rstrip("\r\n")
    match = JS_SECRET_VALUE.search(line)
    if not match:
        return None
    env_name = environment_variable or _secret_environment_name(path, match.group(1))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", env_name):
        return None
    expression = f"process.env.{env_name}"
    replacement = line[:match.start(3)] + expression + line[match.end(4) + 1:]
    after = "".join(lines[:line_index] + [replacement + original[len(line):]] + lines[line_index + 1:])
    return _safe_secret_plan_candidate(path, before, after, line_index, line, env_name)


def _tier0_replacement(finding: dict, content: str) -> tuple[str, str, list[str]] | None:
    lines = content.splitlines(keepends=True)
    line_index = int(finding.get("line", 0)) - 1
    if line_index < 0 or line_index >= len(lines):
        return None
    original = lines[line_index]
    line = original.rstrip("\r\n")
    ending = original[len(line):]
    rule_id = finding.get("rule_id")

    if rule_id == "PL001":
        match = LOG_LINE.match(line)
        if not match:
            return None
        replacement = _render("mask_log.j2", indent=match.group(1), target=match.group(2), method=match.group(3), semicolon=match.group(4))
        return "mask_log_value", replacement + ending, ["The full log statement is replaced so it cannot emit personal data."]

    if rule_id == "PL002":
        match = RESPONSE_LINE.match(line)
        if not match:
            return None
        replacement = _render("response_projection.j2", indent=match.group(1), target=match.group(2), method=match.group(3), empty_body="{}", semicolon=match.group(4))
        return "response_projection", replacement + ending, ["The response body is empty; add only reviewed, necessary fields before shipping."]

    if rule_id in {"PL004", "PL009"}:
        match = ROUTE_LINE.match(line)
        if not match:
            return None
        middleware_pattern = r"\b(?:verifyParentalConsent|requireParentalConsent|guardianConsent)\b" if rule_id == "PL009" else r"\b(?:requireAuth|authMiddleware|authenticate|protect|authorize|isAuthenticated)\b"
        middleware = next((item for item in re.findall(middleware_pattern, content, re.IGNORECASE) if item.lower() not in match.group(5).lower()), None)
        if not middleware:
            return None
        replacement = _render("route_auth.j2", indent=match.group(1), target=match.group(2), method=match.group(3), route=match.group(4), middleware=middleware, handler=match.group(5), semicolon=match.group(6))
        return ("require_parental_consent" if rule_id == "PL009" else "add_auth_middleware"), replacement + ending, ["An existing middleware is inserted before the route handler."]

    if rule_id == "PL003" and re.search(r"\bfunction\s+encryptPII\b|\b(?:const|let|var)\s+encryptPII\s*=", content):
        match = DB_CALL.search(line)
        if not match:
            return None
        replacement = _render("encrypt_store.j2", indent="", prefix=match.group(1), expression=match.group(2), suffix=match.group(3))
        return "encrypt_store_value", replacement + ending, ["An existing encryptPII helper wraps the database payload."]

    if rule_id == "PL005" and re.search(r"\bfunction\s+hashPassword\b|\b(?:const|let|var)\s+hashPassword\s*=", content):
        match = HASH_CALL.search(line)
        if not match:
            return None
        replacement = _render("upgrade_password_hash.j2", line_prefix=line[:match.start()], password_expression=match.group(1), line_suffix=line[match.end():])
        return "upgrade_password_hash", replacement + ending, ["An existing adaptive hash helper replaces the weak hash call."]

    if rule_id == "PL006":
        if re.match(r"^\s*(?:analytics\s*\.\s*(?:track|identify)|(?:fetch|axios\.post|requests\.post)\s*\().*\b(?:email|aadhaar|aadhar|phone|pan)\b.*\)?\s*;?\s*$", line, re.IGNORECASE):
            indent = line[:len(line) - len(line.lstrip())]
            return "minimize_third_party_payload", f"{indent}// PrivacyLint: personal-data transfer omitted{ending}", ["The full third-party transfer statement is removed pending purpose and consent review."]

    if rule_id == "PL007" and re.match(r"^\s*(?:window\.)?(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(.*\)\s*;?\s*$", line, re.IGNORECASE):
        indent = line[:len(line) - len(line.lstrip())]
        return "remove_client_pii", f"{indent}// PrivacyLint: client-side personal-data persistence omitted{ending}", ["The personal-data browser-storage statement is removed."]

    if rule_id == "PL008":
        match = SECRET_ASSIGN.match(line)
        if not match:
            return None
        name = match.group(2)
        replacement = f"{match.group(1)}process.env.{name}{match.group(4)}"
        return "move_secret_to_env", replacement + ending, [f"The literal is replaced with the {name} environment variable."]

    if rule_id == "PL011":
        replacement, count = HTTP_LITERAL.subn("https://", line)
        if count:
            return "enforce_https", replacement + ending, ["The cleartext URL is changed to HTTPS."]

    if rule_id == "PL012":
        if re.match(r"^\s*throw\s+new\s+Error\s*\(.*\)\s*;?\s*$", line, re.IGNORECASE):
            indent = line[:len(line) - len(line.lstrip())]
            return "generic_error_message", f'{indent}throw new Error("Request failed");{ending}', ["The exception message no longer contains personal data."]
        if re.match(r"^\s*raise\s+\w*Error\s*\(.*\)\s*$", line, re.IGNORECASE):
            indent = line[:len(line) - len(line.lstrip())]
            return "generic_error_message", f'{indent}raise ValueError("Request failed"){ending}', ["The exception message no longer contains personal data."]
    return None


def make_unified_diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=f"a/{path}", tofile=f"b/{path}"))


def tier0_candidate(finding: dict, files: dict[str, bytes], environment_variable: str | None = None) -> dict | None:
    path = str(finding.get("file", ""))
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path not in files:
        return None
    before = files[path].decode("utf-8", errors="replace")
    if finding.get("rule_id") == "PL008":
        if path.lower().endswith(".py"):
            return _python_secret_candidate(finding, path, before, environment_variable)
        if path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            return _javascript_secret_candidate(finding, path, before, environment_variable)
    replacement = _tier0_replacement(finding, before)
    if replacement is None:
        return None
    template_id, target_line, assumptions = replacement
    lines = before.splitlines(keepends=True)
    index = int(finding.get("line", 0)) - 1
    after = "".join(lines[:index] + [target_line] + lines[index + 1:])
    patch = make_unified_diff(path, before, after)
    if not patch or len([line for line in patch.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]) > 80:
        return None
    if redact_sensitive(patch) != patch or SECRET_LITERAL.search(patch):
        return None
    return {"file": path, "before": before, "after": after, "patch": patch, "template_id": template_id, "assumptions": assumptions, "tier": "Template"}


def regenerate_secret_candidate(files: dict[str, bytes], finding: dict, safe_plan: str) -> dict | None:
    if finding.get("rule_id") != "PL008":
        return None
    try:
        plan = json.loads(safe_plan)
    except (TypeError, ValueError):
        return None
    if not isinstance(plan, dict) or plan.get("kind") != "privacylint.secret-env.v1":
        return None
    candidate = tier0_candidate(finding, files, plan.get("environment_variable"))
    return candidate if candidate and candidate.get("patch") == safe_plan else None


def apply_unified_diff(files: dict[str, bytes], patch: str) -> dict[str, bytes]:
    if len(patch.splitlines()) > 200:
        raise ValueError("Patch is too large")
    lines = patch.splitlines(keepends=True)
    if len(lines) < 4 or not lines[0].startswith("--- a/") or not lines[1].startswith("+++ b/"):
        raise ValueError("Patch must contain one unified-diff file")
    old_path = lines[0][6:].strip()
    new_path = lines[1][6:].strip()
    if old_path != new_path or old_path not in files or PurePosixPath(old_path).is_absolute() or ".." in PurePosixPath(old_path).parts:
        raise ValueError("Patch target is not an existing safe source file")
    if sum(1 for line in lines if line.startswith("--- ")) != 1 or sum(1 for line in lines if line.startswith("+++ ")) != 1:
        raise ValueError("Patch must change exactly one file")
    if sum(1 for line in lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))) > 80:
        raise ValueError("Patch exceeds the 80-line change limit")
    original = files[old_path].decode("utf-8", errors="strict").splitlines(keepends=True)
    result: list[str] = []
    cursor = 0
    index = 2
    hunk = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    while index < len(lines):
        match = hunk.match(lines[index])
        if not match:
            index += 1
            continue
        old_start = int(match.group(1))
        target = max(0, old_start - 1)
        if target < cursor or target > len(original):
            raise ValueError("Patch hunk overlaps or is outside the original file")
        result.extend(original[cursor:target])
        cursor = target
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            patch_line = lines[index]
            if patch_line.startswith(("\\", "--- ", "+++ ")):
                index += 1
                continue
            if not patch_line:
                raise ValueError("Malformed patch line")
            marker, text = patch_line[0], patch_line[1:]
            if marker in {" ", "-"}:
                if cursor >= len(original) or original[cursor].rstrip("\r\n") != text.rstrip("\r\n"):
                    raise ValueError("Patch context does not match the uploaded source")
                if marker == " ":
                    result.append(original[cursor])
                cursor += 1
            elif marker == "+":
                result.append(text if text.endswith(("\n", "\r")) else text + "\n")
            else:
                raise ValueError("Malformed patch line")
            index += 1
    result.extend(original[cursor:])
    updated = dict(files)
    updated[old_path] = "".join(result).encode("utf-8")
    return updated


def verify_candidate(files: dict[str, bytes], finding: dict, candidate: dict) -> dict:
    try:
        patched_files = dict(files)
        patched_files[candidate["file"]] = candidate["after"].encode("utf-8")
        parsed = _parse_file(candidate["file"], patched_files[candidate["file"]])
        if parsed.parse_error:
            return {"verified": False, "reason": "Patched file has a Tree-sitter parse error."}
        with tempfile.TemporaryDirectory(prefix="privacylint-sandbox-") as sandbox:
            root = Path(sandbox).resolve()
            for name, content in patched_files.items():
                path = PurePosixPath(str(name).replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts:
                    return {"verified": False, "reason": "Source archive contains an unsafe path."}
                target = root.joinpath(*path.parts).resolve()
                if root not in target.parents:
                    return {"verified": False, "reason": "Source path escaped the sandbox."}
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            scan = scan_files(patched_files)
        same_finding = any(item["rule_id"] == finding["rule_id"] and item["file"] == finding["file"] and item["pii_category"] == finding["pii_category"] and item["sink_type"] == finding["sink_type"] for item in scan["findings"])
        if same_finding:
            return {"verified": False, "reason": "The deterministic rescan still reports this finding."}
        original_high = Counter((item["rule_id"], item["file"], item["pii_category"], item["sink_type"]) for item in scan_files(files)["findings"] if item["severity"] in {"critical", "high"})
        patched_high = Counter((item["rule_id"], item["file"], item["pii_category"], item["sink_type"]) for item in scan["findings"] if item["severity"] in {"critical", "high"})
        if any(count > original_high[key] for key, count in patched_high.items()):
            return {"verified": False, "reason": "The rescan introduced a new critical or high finding."}
        return {"verified": True, "reason": "The target finding cleared, the patched file parses, and no new critical/high findings appeared.", "files_scanned": scan["files_scanned"], "findings": scan["findings"], "patched_files": patched_files}
    except (UnicodeDecodeError, OSError, ValueError) as error:
        return {"verified": False, "reason": str(error)}


def guidance_for(finding: dict) -> dict:
    return {"status": "guidance", "verified": False, "tier": None, "dpdp_section": finding.get("dpdp_section"), "guidance": finding.get("remediation", "Review the data path and add a privacy-safe regression test."), "assumptions": ["No automatic patch passed the deterministic sandbox rescan."]}
