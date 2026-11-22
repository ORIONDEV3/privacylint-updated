from __future__ import annotations

import json
import os
import re

import httpx

from .detectors import redact_sensitive
from .fixes import apply_unified_diff, make_unified_diff, tier0_candidate, verify_candidate


TOOLS = [
    {"type": "function", "name": "get_finding", "description": "Read sanitized metadata for the current deterministic finding.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"type": "function", "name": "read_code_window", "description": "Read at most 61 redacted source lines around the finding.", "parameters": {"type": "object", "properties": {"file": {"type": "string"}, "line": {"type": "integer"}, "radius": {"type": "integer"}}, "required": ["file", "line", "radius"]}},
    {"type": "function", "name": "get_dpdp_section", "description": "Read a short DPDP topic summary for a supported section.", "parameters": {"type": "object", "properties": {"section": {"type": "string", "enum": ["§5", "§8(5)", "§8(6)", "§9"]}}, "required": ["section"]}},
    {"type": "function", "name": "get_taint_path", "description": "Read the deterministic source-to-sink path for the current finding.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"type": "function", "name": "list_allowed_patch_patterns", "description": "List bounded patch patterns allowed for this finding.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"type": "function", "name": "propose_patch", "description": "Propose one unified diff for one file. The patch will be sandbox-checked before use.", "parameters": {"type": "object", "properties": {"patch": {"type": "string"}, "explanation": {"type": "string"}, "assumptions": {"type": "array", "items": {"type": "string"}}}, "required": ["patch", "explanation", "assumptions"]}},
    {"type": "function", "name": "propose_secret_fix", "description": "For PL008 only, choose a safe uppercase runtime environment variable name. The engine replaces the literal locally and returns only a secret-free plan and redacted preview; never request, repeat, or include the credential.", "parameters": {"type": "object", "properties": {"environment_variable": {"type": "string"}, "explanation": {"type": "string"}, "assumptions": {"type": "array", "items": {"type": "string"}}}, "required": ["environment_variable", "explanation", "assumptions"]}},
    {"type": "function", "name": "run_sandbox_rescan", "description": "Apply the proposed patch in an isolated temporary directory and run deterministic checks.", "parameters": {"type": "object", "properties": {}, "required": []}},
]

DPDP_SUMMARIES = {
    "§5": "Purpose limitation and consent: use a lawful, specific purpose and valid consent where required.",
    "§8(5)": "Reasonable security safeguards: protect personal data with appropriate technical and organizational measures.",
    "§8(6)": "Breach notification: notify the Board and affected Data Principals as prescribed when a personal data breach occurs.",
    "§9": "Children: apply verifiable parental consent and the applicable restrictions for children's data.",
}
PATTERN_GUIDANCE = {
    "PL001": ["remove the PII argument", "mask or redact the PII value before logging"],
    "PL002": ["return an explicit allowlisted DTO", "omit personal fields not required by the caller"],
    "PL003": ["use an existing managed encryption or tokenization helper"],
    "PL004": ["insert an existing authorization middleware before the route handler"],
    "PL005": ["use an existing scrypt, bcrypt, or Argon2id helper"],
    "PL008": ["remove the embedded literal and read its replacement from a runtime environment variable"],
    "PL011": ["replace cleartext transport with HTTPS"],
    "PL012": ["replace personal-data error text with a generic error identifier"],
}


def _safe_finding(finding: dict) -> dict:
    keys = ("id", "rule_id", "title", "severity", "file", "line", "sink_type", "pii_category", "route", "dpdp_section", "remediation")
    result = {key: finding.get(key) for key in keys}
    return {key: redact_sensitive(value) if isinstance(value, str) else value for key, value in result.items()}


async def run_gemini_agent(files: dict[str, bytes], finding: dict, scan: dict) -> dict | None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
    current = {"candidate": None, "verification": None, "patched_files": None, "tool_calls": 0}

    def find_finding(identifier: str) -> dict | None:
        return finding if identifier == finding.get("id") else None

    def execute(name: str, arguments: dict) -> dict:
        current["tool_calls"] += 1
        if name == "get_finding":
            item = find_finding(str(arguments.get("finding_id", "")))
            return {"finding": _safe_finding(item)} if item else {"error": "Finding is unavailable."}
        if name == "read_code_window":
            path = str(arguments.get("file", ""))
            if path != finding.get("file") or path not in files:
                return {"error": "Only the current finding file is available."}
            radius = max(0, min(30, int(arguments.get("radius", 30))))
            line = max(1, min(len(files[path].splitlines()), int(arguments.get("line", finding.get("line", 1)))))
            source_lines = files[path].decode("utf-8", errors="replace").splitlines()
            start, end = max(0, line - 1 - radius), min(len(source_lines), line + radius)
            return {"file": redact_sensitive(path), "start_line": start + 1, "lines": "\n".join(redact_sensitive(value) for value in source_lines[start:end])}
        if name == "get_dpdp_section":
            section = str(arguments.get("section", ""))
            return {"section": section, "summary": DPDP_SUMMARIES.get(section, "Unsupported DPDP section.")}
        if name == "get_taint_path":
            if arguments.get("finding_id") != finding.get("id"):
                return {"error": "Finding is unavailable."}
            return {"taint_path": [{key: redact_sensitive(value) if isinstance(value, str) else value for key, value in step.items()} for step in finding.get("taint_path", [])]}
        if name == "list_allowed_patch_patterns":
            if arguments.get("finding_id") != finding.get("id"):
                return {"error": "Finding is unavailable."}
            return {"patterns": PATTERN_GUIDANCE.get(finding.get("rule_id"), [finding.get("remediation", "Provide remediation guidance only.")])}
        if name == "propose_patch":
            patch = arguments.get("patch")
            if not isinstance(patch, str) or not patch or len(patch.splitlines()) > 200:
                return {"accepted": False, "error": "Patch is empty or exceeds the bounded diff size."}
            if redact_sensitive(patch) != patch or re.search(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}", patch):
                return {"accepted": False, "error": "Patch contains sensitive literal content and was discarded."}
            try:
                updated = apply_unified_diff(files, patch)
            except (ValueError, UnicodeDecodeError):
                return {"accepted": False, "error": "Patch does not apply cleanly to one source file."}
            target_files = [path for path in updated if updated[path] != files[path]]
            if target_files != [finding.get("file")]:
                return {"accepted": False, "error": "Patch must change only the finding's file."}
            after = updated[finding["file"]].decode("utf-8", errors="replace")
            exact_diff = make_unified_diff(finding["file"], files[finding["file"]].decode("utf-8", errors="replace"), after)
            if redact_sensitive(exact_diff) != exact_diff:
                return {"accepted": False, "error": "Patch would expose sensitive source text and was discarded."}
            current["candidate"] = {"file": finding["file"], "before": files[finding["file"]].decode("utf-8", errors="replace"), "after": after, "patch": exact_diff, "tier": "Gemini", "explanation": redact_sensitive(str(arguments.get("explanation", "")))[:1200], "assumptions": [redact_sensitive(str(item))[:300] for item in arguments.get("assumptions", [])[:8]]}
            return {"accepted": True, "status": "Pending deterministic sandbox rescan."}
        if name == "propose_secret_fix":
            if finding.get("rule_id") != "PL008":
                return {"accepted": False, "error": "Secret remediation is only available for a PL008 finding."}
            env_name = str(arguments.get("environment_variable", "")).strip()
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", env_name):
                return {"accepted": False, "error": "Choose a valid uppercase environment-variable name."}
            candidate = tier0_candidate(finding, files, env_name)
            if not candidate or redact_sensitive(candidate["patch"]) != candidate["patch"]:
                return {"accepted": False, "error": "The engine could not create a secret-free remediation plan for this line."}
            candidate["tier"] = "Gemini"
            candidate["explanation"] = redact_sensitive(str(arguments.get("explanation", "")))[:1200]
            candidate["assumptions"] = [redact_sensitive(str(item))[:300] for item in arguments.get("assumptions", [])[:8]] or candidate.get("assumptions", [])
            current["candidate"] = candidate
            return {"accepted": True, "status": "Safe plan ready; run the deterministic sandbox rescan."}
        if name == "run_sandbox_rescan":
            if not current["candidate"]:
                return {"verified": False, "reason": "No patch has been proposed."}
            result = verify_candidate(files, finding, current["candidate"])
            current["verification"] = {key: value for key, value in result.items() if key != "patched_files"}
            current["patched_files"] = result.get("patched_files") if result.get("verified") else None
            return current["verification"]
        return {"error": "Unknown tool."}

    prompt = (
        "You are a bounded privacy remediation assistant. Deterministic scanner results decide whether a finding exists; never challenge or alter that result. "
        "Use only the declared tools. Read no more than 60 lines at a time, propose at most one file patch per iteration, and stop after a passing sandbox rescan. "
        "If no safe, minimal patch is possible, give a concise explanation and do not invent a successful fix. For PL008, use propose_secret_fix with a suitable environment variable; never use propose_patch for a secret because the original literal must not be returned. Return patch/explanation/DPDP section/assumptions through the tools only. "
        f"Current sanitized finding: {json.dumps(_safe_finding(finding), ensure_ascii=False)}"
    )
    history = [{"type": "user_input", "content": [{"type": "text", "text": prompt}]}]
    timeout = httpx.Timeout(20, connect=8)
    iterations = 0
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            for _ in range(4):
                iterations += 1
                response = await client.post(
                    "https://generativelanguage.googleapis.com/v1beta/interactions",
                    headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                    json={"model": model, "store": False, "input": history, "tools": TOOLS},
                )
                if not response.is_success:
                    message = "Gemini quota is temporarily exhausted; fallback will be used." if response.status_code == 429 else "Gemini request failed; fallback will be used."
                    return {"candidate": None, "iterations": iterations, "tool_calls": current["tool_calls"], "model": model, "error": message}
                payload = response.json()
                steps = payload.get("steps", [])
                if not steps:
                    break
                history.extend(steps)
                results = []
                for step in steps:
                    if step.get("type") != "function_call":
                        continue
                    name = step.get("name", "")
                    arguments = step.get("arguments", {})
                    if isinstance(arguments, str):
                        try:
                            arguments = json.loads(arguments)
                        except ValueError:
                            arguments = {}
                    result = execute(name, arguments if isinstance(arguments, dict) else {})
                    results.append({"type": "function_result", "name": name, "call_id": step.get("id", ""), "result": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]})
                    if name == "run_sandbox_rescan" and current.get("verification", {}).get("verified"):
                        return {"candidate": current["candidate"], "patched_files": current["patched_files"], "verification": current["verification"], "iterations": iterations, "tool_calls": current["tool_calls"], "model": model}
                if not results:
                    break
                history.extend(results)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return {"candidate": None, "iterations": iterations, "tool_calls": current["tool_calls"], "model": model, "error": "Gemini request failed; fallback will be used."}
    return {"candidate": None, "iterations": iterations, "tool_calls": current["tool_calls"], "model": model, "error": "Gemini did not return a verified patch; fallback will be used."}
