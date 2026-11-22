from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Iterator

from tree_sitter_language_pack import PackConfig, configure, get_parser

from .detectors import categories_from_names, detect_literals, redact_sensitive
from .rules import ROOT, load_rules, rules_by_detector


# Recent language-pack releases download parsers into a cache. Keep that cache
# in the writable project data directory (or an explicit operator override),
# rather than the Windows user cache, which can be inaccessible in managed
# desktop environments.
_PARSER_CACHE = Path(os.environ.get("TREE_SITTER_CACHE_DIR", ROOT / ".local-db" / "tree-sitter"))
_PARSER_CACHE.mkdir(parents=True, exist_ok=True)
configure(PackConfig(cache_dir=str(_PARSER_CACHE)))


LANGUAGE_BY_EXTENSION = {
    ".js": "javascript", ".cjs": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".py": "python", ".java": "java",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".sql": "sql",
}
SKIP_PARTS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "coverage", "__pycache__"}
MAX_SOURCE_BYTES = 1_000_000
IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
SOURCE_RE = re.compile(r"(?i)\b(req|request|ctx\.request|httprequest)\s*\.\s*(body|query|params|form|json|headers|cookies)\b|\brequest\.(get_json|form|args)\b")
LOG_RE = re.compile(r"(?i)\b(console\s*\.\s*(log|info|warn|error|debug)|logger\s*\.\s*(log|info|warn|error|debug)|log\s*\.\s*(info|warn|error)|print\s*\(|printf\s*\(|System\s*\.\s*out\s*\.)")
RESPONSE_RE = re.compile(r"(?i)\b(res|response)\s*\.\s*(json|send|end|write)\s*\(|\b(jsonify|ResponseEntity)\s*\(")
DB_WRITE_RE = re.compile(r"(?i)\b(insert\s+into|update\s+\w+\s+set|\.\s*(insert|create|save|update|execute|query)\s*\()")
ROUTE_RE = re.compile(r"(?i)\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['\"`])([^'\"`]+)\2\s*,(.*)")
HTTP_RE = re.compile(r"(?i)https?://")
THIRD_PARTY_RE = re.compile(r"(?i)\b(fetch|axios\s*\.|requests\s*\.|httpx\s*\.|got\s*\(|undici|sendgrid|twilio|segment|mixpanel|amplitude|analytics)\b")
CLIENT_STORE_RE = re.compile(r"(?i)\b(localStorage|sessionStorage|indexedDB)\s*\.|\bsetItem\s*\(")
WEAK_HASH_RE = re.compile(r"(?i)\b(md5|sha1)\s*\(")
ERROR_RE = re.compile(r"(?i)\b(throw\s+new\s+Error|raise\s+\w*Error|new\s+Error|\.message\s*=|error\s*:\s*)")
SECRET_RE = re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|private[_-]?key|password)\b\s*[:=]\s*(['\"])([^'\"]{8,})\2")
SANITIZER_RE = re.compile(r"(?i)\b(mask|redact|sanitize|encrypt|tokenize|hash_fields|to_safe_dto)\w*\s*\(")
ERASURE_RE = re.compile(r"(?i)\b(delete|erase|erasure|anonymi[sz]e|retention|purge)\b")
AUTH_RE = re.compile(r"(?i)\b(auth|authenticate|requireauth|require_role|requireRole|protect|authorize|isAuthenticated|is_authenticated|verify_token)\w*\b")
CHILD_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:child|children|minor|guardian|age|date_of_birth|dob)(?![A-Za-z0-9])")
CONSENT_RE = re.compile(r"(?i)\b(?:parental_consent|guardian_consent|verifyParentalConsent|requireParentalConsent|guardianConsent|consent_required|verifyConsent)\b")


@lru_cache(maxsize=16)
def _parser(language: str):
    return get_parser(language)


def _walk(node) -> Iterator:
    yield node
    for child in node.children:
        yield from _walk(child)


def _mask_comments(source: bytes, root) -> bytes:
    masked = bytearray(source)
    for node in _walk(root):
        if "comment" not in node.type:
            continue
        for index in range(node.start_byte, node.end_byte):
            if masked[index] not in (10, 13):
                masked[index] = 32
    return bytes(masked)


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


@dataclass
class ParsedFile:
    path: str
    language: str
    source: str
    code_lines: list[str]
    raw_lines: list[str]
    tree: object | None
    parse_error: bool
    functions: dict[str, dict]


def _extract_functions(root, code_lines: list[str]) -> dict[str, dict]:
    functions: dict[str, dict] = {}
    if root is None:
        return functions
    function_types = {"function_declaration", "function_definition", "method_declaration", "function_item"}
    for node in _walk(root):
        name = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
        if node.type in function_types and name is not None:
            start = node.start_point.row
            end = node.end_point.row + 1
            functions[_text(name)] = {"start": start, "end": end, "text": "\n".join(code_lines[start:end])}
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            target = node.child_by_field_name("name")
            if value is not None and value.type in {"arrow_function", "function_expression"} and target is not None:
                start = node.start_point.row
                end = node.end_point.row + 1
                functions[_text(target)] = {"start": start, "end": end, "text": "\n".join(code_lines[start:end])}
    return functions


def _parse_file(path: str, content: bytes) -> ParsedFile:
    extension = PurePosixPath(path).suffix.lower()
    language = LANGUAGE_BY_EXTENSION[extension]
    source = content.decode("utf-8", errors="replace")
    encoded = source.encode("utf-8")
    tree = None
    parse_error = False
    try:
        tree = _parser(language).parse(encoded)
        parse_error = bool(tree.root_node.has_error)
        code = _mask_comments(encoded, tree.root_node).decode("utf-8", errors="replace")
    except Exception:
        code = source
        parse_error = True
    code_lines = code.splitlines()
    raw_lines = source.splitlines()
    functions = _extract_functions(tree.root_node, code_lines) if tree else {}
    return ParsedFile(path, language, source, code_lines, raw_lines, tree, parse_error, functions)


def _assignment_parts(line: str) -> tuple[list[str], str] | None:
    match = re.match(r"\s*(?:(?:const|let|var|final|val)\s+)?(.+?)\s*=\s*(.+)$", line)
    if not match or any(operator in match.group(0) for operator in ("==", ">=", "<=", "=>")):
        return None
    left = [name for name in IDENTIFIER_RE.findall(match.group(1)) if name not in {"const", "let", "var", "final", "val"}]
    return (left, match.group(2)) if left else None


def _analyze_line_data(parsed: ParsedFile) -> tuple[list[set[str]], list[set[str]], list[int | None]]:
    tainted: dict[str, set[str]] = {}
    taint_sources: dict[str, int] = {}
    categories_by_line: list[set[str]] = []
    sources_by_line: list[set[str]] = []
    source_line_by_line: list[int | None] = []
    for row, code_line in enumerate(parsed.code_lines):
        raw_line = parsed.raw_lines[row] if row < len(parsed.raw_lines) else code_line
        line_categories = categories_from_names(code_line)
        literals = detect_literals(raw_line)
        line_categories.update(match.category for match in literals)
        identifiers = set(IDENTIFIER_RE.findall(code_line))
        for identifier in identifiers:
            line_categories.update(tainted.get(identifier, set()))
        is_source = bool(SOURCE_RE.search(code_line)) or bool(literals)
        direct_sources = set(match.category for match in literals)
        if is_source:
            direct_sources.update(categories_from_names(code_line))
            if not direct_sources:
                direct_sources.add("other")
        inherited_sources = [taint_sources[name] for name in identifiers if name in taint_sources]
        source_line = row if is_source else (min(inherited_sources) if inherited_sources else None)
        assignment = _assignment_parts(code_line)
        if assignment:
            left_names, right_side = assignment
            right_categories = categories_from_names(right_side)
            right_identifiers = set(IDENTIFIER_RE.findall(right_side))
            for identifier in right_identifiers:
                right_categories.update(tainted.get(identifier, set()))
            right_categories.update(match.category for match in detect_literals(right_side))
            if is_source:
                right_categories.update(direct_sources)
            if right_categories:
                for name in left_names:
                    tainted.setdefault(name, set()).update(right_categories)
                    taint_sources[name] = row if is_source else min(
                        (taint_sources[name_part] for name_part in right_identifiers if name_part in taint_sources),
                        default=row,
                    )
        elif is_source and identifiers:
            # Destructured request bodies are common; propagate the PII field identifier.
            for identifier in identifiers:
                if categories_from_names(identifier):
                    tainted.setdefault(identifier, set()).update(categories_from_names(identifier))
        categories_by_line.append(line_categories)
        sources_by_line.append(direct_sources)
        source_line_by_line.append(source_line)
    return categories_by_line, sources_by_line, source_line_by_line


def _primary_category(categories: set[str]) -> str:
    if not categories:
        return "other"
    priority = {"aadhaar": 0, "children": 1, "financial": 2, "health": 3, "pan": 4, "credential": 5}
    return sorted(categories, key=lambda category: (priority.get(category, 10), category))[0]


def _finding(rule: dict, parsed: ParsedFile, row: int, category: str, sink_type: str, *, route: str | None = None, db_column: str | None = None, source_row: int | None = None, unauthenticated: bool = False) -> dict:
    raw_line = parsed.raw_lines[row] if row < len(parsed.raw_lines) else ""
    snippet = redact_sensitive(raw_line.strip())[:240]
    one_based = row + 1
    stable_key = f"{rule['id']}\0{parsed.path}\0{one_based}\0{sink_type}\0{category}"
    identifier = "pl_" + hashlib.sha256(stable_key.encode()).hexdigest()[:16]
    path = []
    if route:
        path.append({"kind": "route", "file": parsed.path, "line": one_based, "value": route})
    path.append({"kind": "source", "file": parsed.path, "line": (source_row + 1) if source_row is not None else one_based, "category": category})
    path.append({"kind": "sink", "file": parsed.path, "line": one_based, "type": sink_type})
    return {
        "id": identifier,
        "rule_id": rule["id"],
        "title": rule["name"],
        "severity": rule["severity"],
        "file": parsed.path,
        "line": one_based,
        "snippet": snippet,
        "sink_type": sink_type,
        "pii_category": category,
        "route": route,
        "db_column": db_column,
        "dpdp_section": rule["dpdp_mapping"],
        "remediation": rule["remediation"],
        "taint_path": path,
        "unauthenticated": unauthenticated,
        "verified": False,
    }


def _db_column(line: str) -> str | None:
    sql = re.search(r"(?i)\b(?:insert\s+into\s+\w+\s*\(|update\s+\w+\s+set\s+)([^)]+)", line)
    if sql:
        identifiers = [value.strip(' `\"') for value in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sql.group(1))]
        return next((value for value in identifiers if categories_from_names(value)), None)
    obj = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:", line)
    if obj and categories_from_names(obj.group(1)):
        return obj.group(1)
    return next(iter(sorted(categories_from_names(line))), None)


def _route_records(parsed_files: list[ParsedFile], file_categories: dict[str, set[str]]) -> tuple[list[dict], dict[str, list[dict]]]:
    functions: dict[str, list[dict]] = {}
    for parsed in parsed_files:
        for name, info in parsed.functions.items():
            functions.setdefault(name, []).append({"file": parsed.path, **info})
    records = []
    handlers: dict[str, list[dict]] = {}
    for parsed in parsed_files:
        for row, line in enumerate(parsed.code_lines):
            match = ROUTE_RE.search(line)
            if not match:
                continue
            method, route_path, tail = match.group(1).upper(), match.group(3), match.group(4)
            refs = [name for name in IDENTIFIER_RE.findall(tail) if name.lower() not in {"async", "req", "request", "res", "response", "next", "await", "true", "false"}]
            handler = refs[-1] if refs else None
            handler_candidates = functions.get(handler, []) if handler else []
            handler_info = next((item for item in handler_candidates if item["file"] == parsed.path), handler_candidates[0] if handler_candidates else None)
            body = handler_info["text"] if handler_info else ""
            categories = categories_from_names(route_path + " " + body)
            categories.update(file_categories.get(parsed.path, set()) if not body else set())
            if not categories:
                continue
            has_gate = bool(AUTH_RE.search(line) or AUTH_RE.search(body))
            record = {
                "file": parsed.path, "line": row, "method": method, "path": route_path,
                "handler": handler, "handler_file": handler_info["file"] if handler_info else parsed.path,
                "handler_start": handler_info["start"] if handler_info else row,
                "handler_end": handler_info["end"] if handler_info else row + 1,
                "categories": categories, "authenticated": has_gate,
            }
            records.append(record)
            if handler:
                handlers.setdefault(handler, []).append(record)
    return records, handlers


def scan_files(files: dict[str, bytes], enabled_rule_ids: set[str] | None = None) -> dict:
    rules = [rule for rule in load_rules() if enabled_rule_ids is None or rule["id"] in enabled_rule_ids]
    rule_map = {rule["detector"]: rule for rule in rules}
    parsed_files: list[ParsedFile] = []
    ignored_files = 0
    parse_errors = 0
    for filename, content in sorted(files.items()):
        relative = PurePosixPath(str(filename).replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts or any(part in SKIP_PARTS for part in relative.parts):
            ignored_files += 1
            continue
        extension = relative.suffix.lower()
        if extension not in LANGUAGE_BY_EXTENSION or len(content) > MAX_SOURCE_BYTES or b"\x00" in content:
            ignored_files += 1
            continue
        parsed = _parse_file(relative.as_posix(), content)
        parsed_files.append(parsed)
        parse_errors += int(parsed.parse_error)

    analyses: dict[str, tuple[list[set[str]], list[set[str]], list[int | None]]] = {}
    file_categories: dict[str, set[str]] = {}
    for parsed in parsed_files:
        data = _analyze_line_data(parsed)
        analyses[parsed.path] = data
        file_categories[parsed.path] = set().union(*data[0]) if data[0] else set()
    routes, handlers = _route_records(parsed_files, file_categories)
    findings: dict[tuple, dict] = {}

    for parsed in parsed_files:
        categories_by_line, sources_by_line, source_line_by_line = analyses[parsed.path]
        for row, line in enumerate(parsed.code_lines):
            categories = categories_by_line[row]
            if not categories:
                continue
            literals = detect_literals(line)
            source_row = source_line_by_line[row]
            matching_routes = [
                route for route in routes
                if route["handler_file"] == parsed.path
                and route["handler_start"] <= row < route["handler_end"]
            ]
            if not matching_routes:
                matching_routes = [route for route in routes if route["file"] == parsed.path and route["line"] == row]
            route = matching_routes[0] if matching_routes else None
            route_label = f"{route['method']} {route['path']}" if route else None
            common = {"route": route_label, "source_row": source_row}
            sanitized = bool(SANITIZER_RE.search(line))

            def add(detector: str, sink_type: str, *, category_set: set[str] = categories, db_column: str | None = None, is_unauthenticated: bool = False) -> None:
                rule = rule_map.get(detector)
                if not rule or not category_set:
                    return
                category = _primary_category(category_set)
                finding = _finding(rule, parsed, row, category, sink_type, route=common["route"], db_column=db_column, source_row=common["source_row"], unauthenticated=is_unauthenticated)
                findings[(finding["rule_id"], finding["file"], finding["line"], finding["pii_category"])] = finding

            if LOG_RE.search(line) and not sanitized:
                add("pii_log", "log")
            if RESPONSE_RE.search(line) and not sanitized:
                add("pii_response", "response")
            if DB_WRITE_RE.search(line) and not sanitized:
                add("plaintext_storage", "database", db_column=_db_column(line))
                if not ERASURE_RE.search(parsed.source):
                    add("missing_erasure", "database", db_column=_db_column(line))
            if THIRD_PARTY_RE.search(line) and not sanitized:
                add("third_party_pii", "third_party")
            if CLIENT_STORE_RE.search(line) and not sanitized:
                add("client_storage_pii", "client_storage")
            if HTTP_RE.search(line) and re.search(r"(?i)http://", line):
                add("pii_http", "http_transport")
            if ERROR_RE.search(line) and not sanitized:
                add("pii_error", "error")

            if WEAK_HASH_RE.search(line) and ("password" in line.lower() or "password" in parsed.source.lower()):
                add("weak_hash", "weak_hash", category_set={"credential"})

            if SECRET_RE.search(line):
                secret_rule = rule_map.get("hardcoded_secret")
                if secret_rule:
                    finding = _finding(secret_rule, parsed, row, "credential", "hardcoded_secret", route=route_label)
                    findings[(finding["rule_id"], finding["file"], finding["line"], finding["pii_category"])] = finding

            if CHILD_RE.search(line) and not any(CONSENT_RE.search(candidate) for candidate in parsed.code_lines) and categories & {"children", "health", "contact", "aadhaar", "pan", "phone", "email"}:
                add("child_consent", "children_data", category_set={"children"})

        for route_record in routes:
            if route_record["file"] != parsed.path or route_record["authenticated"] or not route_record["categories"]:
                continue
            rule = rule_map.get("missing_auth_gate")
            if not rule:
                continue
            route_category = _primary_category(route_record["categories"])
            finding = _finding(rule, parsed, route_record["line"], route_category, "unauthenticated_route", route=f"{route_record['method']} {route_record['path']}", source_row=route_record["line"], unauthenticated=True)
            finding["taint_path"].insert(1, {"kind": "controller", "file": route_record.get("handler_file", parsed.path), "value": route_record.get("handler") or "inline handler"})
            findings[(finding["rule_id"], finding["file"], finding["line"], finding["pii_category"])] = finding

    ordered = sorted(findings.values(), key=lambda finding: (finding["file"], finding["line"], finding["rule_id"], finding["pii_category"]))
    supported = sorted({parsed.language for parsed in parsed_files})
    return {"findings": ordered, "parse_errors": parse_errors, "ignored_files": ignored_files, "files_scanned": len(parsed_files), "languages": supported}
