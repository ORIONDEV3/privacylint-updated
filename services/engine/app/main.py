from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from contextlib import asynccontextmanager
from urllib.parse import quote
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .archive import ArchiveError, MAX_FILES, MAX_FILE_BYTES, MAX_UNPACKED_BYTES, read_zip
from .auth import REQUIRE_AUTH, current_user
from .inventory import extract_inventory
from .lineage import LineageStore, build_lineage, to_graphml, to_png, to_svg
from .fixes import apply_unified_diff, guidance_for, regenerate_secret_candidate, tier0_candidate, verify_candidate
from .gemini_agent import run_gemini_agent
from .rules import load_rules
from .sarif import to_sarif
from .scanner import LANGUAGE_BY_EXTENSION, scan_files
from .scoring import calculate_score
from .store import ScanStore
from .testgen import detect_framework, generate_regression_test


store = ScanStore()
lineage_store = LineageStore()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if REQUIRE_AUTH and (len(os.getenv("SESSION_SECRET", "")) < 32 or len(os.getenv("CSRF_SECRET", "")) < 32):
        raise RuntimeError("SESSION_SECRET and CSRF_SECRET must be configured when REQUIRE_AUTH=true")
    await store.connect()
    _app.state.scan_store = store
    _app.state.lineage_store = lineage_store
    yield
    await store.close()
    lineage_store.close()


app = FastAPI(title="PrivacyLint Analysis Engine", version="0.2.0", lifespan=lifespan)
_origins = [item.strip() for item in os.getenv("WEB_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=None if os.getenv("NODE_ENV") == "production" else r"https?://(localhost|127\.0\.0\.1):517[3-9]",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
    # Pydantic's default response may echo invalid request values, including a PAT.
    return JSONResponse(status_code=422, content={"detail": "Invalid request data."})


class GitHubScanRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    repo: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    ref: str | None = Field(default=None, max_length=200)
    token: str | None = Field(default=None, max_length=500)
    rule_ids: list[str] | None = Field(default=None, max_length=200)


class TestGenerationRequest(BaseModel):
    finding_ids: list[str] | None = Field(default=None, max_length=200)


class PullRequestFix(BaseModel):
    finding_id: str = Field(min_length=1, max_length=200)
    patch: str = Field(min_length=1, max_length=20_000)


class PullRequestRequest(BaseModel):
    github_token: str = Field(min_length=20, max_length=500)
    fixes: list[PullRequestFix] = Field(min_length=1, max_length=20)


def _scan_hash(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    hashable = {}
    manifests = {"package.json", "requirements.txt", "pom.xml"}
    for name, content in files.items():
        normalized = name.replace("\\", "/")
        path_parts = normalized.split("/")
        if any(part in {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "coverage"} for part in path_parts):
            continue
        if len(content) > MAX_FILE_BYTES:
            continue
        if normalized.lower().endswith(tuple(LANGUAGE_BY_EXTENSION)) or normalized.rsplit("/", 1)[-1].lower() in manifests or normalized.rsplit("/", 1)[-1].lower().endswith(".requirements.txt"):
            hashable[normalized] = content
    for name, content in sorted(hashable.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _normalize_github_archive_root(files: dict[str, bytes]) -> dict[str, bytes]:
    """Remove the single enclosing directory used by downloaded GitHub ZIPs."""
    if not files or any("/" not in name for name in files):
        return files
    roots = {name.split("/", 1)[0] for name in files}
    if len(roots) != 1:
        return files
    root = next(iter(roots))
    normalized: dict[str, bytes] = {}
    for name, content in files.items():
        relative = name[len(root) + 1:]
        if not relative or relative in normalized:
            return files
        normalized[relative] = content
    return normalized


async def _save_scan(files: dict[str, bytes], *, repo: str, owner: str | None, source: str, user_id: str | None, enabled_rule_ids: set[str] | None = None, verified_fix_bonus: int = 0, ref: str | None = None, git_commit: str | None = None) -> dict:
    if not files:
        raise HTTPException(422, "No readable source files were found in this repository.")
    result = await run_in_threadpool(scan_files, files, enabled_rule_ids)
    score_details = calculate_score(result["findings"], verified_fix_bonus)
    inventory = extract_inventory(files, result["findings"])
    test_framework, test_setup_config = detect_framework(files)
    scan = {
        "id": str(uuid4()), "user_id": user_id, "owner": owner, "repo": repo[:200], "source": source,
        "ref": ref, "git_commit": git_commit,
        "scan_hash": _scan_hash(files), "score": score_details["score"], "grade": score_details["grade"],
        "score_details": score_details, "files_scanned": result["files_scanned"],
        "parse_errors": result["parse_errors"], "ignored_files": result["ignored_files"],
        "languages": result["languages"], "findings": result["findings"],
        "sdk_inventory": inventory["sdk_inventory"], "outbound_hosts": inventory["outbound_hosts"],
        "erasure_coverage": inventory["erasure_coverage"],
        "test_framework": test_framework, "test_setup_config": test_setup_config,
    }
    await store.save(scan)
    return scan


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "analysis-engine", "mode": "postgres" if store.pool else "local-sqlite"}


@app.get("/api/v1/capabilities")
async def capabilities(user: dict = Depends(current_user)) -> dict:
    del user
    configured = bool(os.getenv("GEMINI_API_KEY", "").strip())
    return {
        "ai": {"provider": "Gemini", "configured": configured, "model": os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()},
        "analysis": {"offline_scanning": True, "sandbox_verified_fixes": True, "regression_tests_require_verified_fix": True},
        "lineage": {"backend": "neo4j" if os.getenv("NEO4J_URI") else "networkx"},
    }


@app.get("/api/v1/rules")
async def rules() -> dict:
    return {"version": 1, "rules": list(load_rules())}


@app.post("/api/v1/scans/upload", status_code=201)
async def upload_zip(file: UploadFile = File(...), rules: str | None = Form(default=None), user: dict = Depends(current_user)) -> dict:
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    if not filename.lower().endswith(".zip"):
        raise HTTPException(415, "Upload a ZIP archive.")
    payload = await file.read(50 * 1024 * 1024 + 1)
    await file.close()
    try:
        files = read_zip(payload)
    except ArchiveError as error:
        raise HTTPException(422, str(error)) from error
    selected = {item.strip() for item in rules.split(",") if item.strip()} if rules else None
    if selected is not None:
        valid = {rule["id"] for rule in load_rules()}
        if not selected or selected - valid:
            raise HTTPException(422, "One or more selected rule IDs are invalid.")
    repo = filename[:-4] or "uploaded-project"
    return await _save_scan(files, repo=repo, owner=None, source="zip", user_id=user["id"], enabled_rule_ids=selected)


async def _github_json(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> dict:
    response = await client.get(url, headers=headers)
    if response.status_code == 404:
        raise HTTPException(404, "Repository or branch was not found, or is not accessible.")
    if response.status_code in {401, 403}:
        raise HTTPException(403, "GitHub denied access. Check the repository token and permissions.")
    if response.status_code == 429:
        raise HTTPException(429, "GitHub rate limit reached. Try again later.")
    if response.status_code >= 400:
        raise HTTPException(502, "GitHub could not provide the repository source.")
    return response.json()


async def _github_write(client: httpx.AsyncClient, method: str, url: str, headers: dict[str, str], payload: dict) -> dict:
    response = await client.request(method, url, headers=headers, json=payload)
    if response.status_code in {401, 403}:
        raise HTTPException(403, "GitHub denied this write. The token needs repository contents and pull-request write access.")
    if response.status_code == 404:
        raise HTTPException(404, "GitHub could not find the repository, branch, or pull request target.")
    if response.status_code == 422:
        raise HTTPException(409, "GitHub rejected the branch or pull request request. Check for an existing branch or open pull request.")
    if response.status_code >= 400:
        raise HTTPException(502, "GitHub could not complete the pull request workflow.")
    return response.json() if response.content else {}


async def _github_source_files(client: httpx.AsyncClient, root: str, commit_sha: str, headers: dict[str, str]) -> dict[str, bytes]:
    tree = await _github_json(client, f"{root}/git/trees/{quote(commit_sha, safe='')}?recursive=1", headers)
    if tree.get("truncated"):
        raise HTTPException(422, "This repository is too large to scan in one request.")
    entries = [item for item in tree.get("tree", []) if item.get("type") == "blob" and item.get("size", 0) <= MAX_FILE_BYTES and "." in item.get("path", "")]
    manifests = {"package.json", "requirements.txt", "pom.xml"}
    entries = [item for item in entries if any(item["path"].lower().endswith(ext) for ext in LANGUAGE_BY_EXTENSION) or item["path"].rsplit("/", 1)[-1].lower() in manifests or item["path"].rsplit("/", 1)[-1].lower().endswith(".requirements.txt")]
    if len(entries) > min(MAX_FILES, 300):
        raise HTTPException(422, "Repository has too many supported source files for one scan.")
    if sum(item.get("size", 0) for item in entries) > MAX_UNPACKED_BYTES:
        raise HTTPException(422, "Repository source exceeds the 200 MB scan limit.")
    semaphore = asyncio.Semaphore(8)

    async def load_blob(item: dict) -> tuple[str, bytes] | None:
        async with semaphore:
            blob = await _github_json(client, f"{root}/git/blobs/{item['sha']}", headers)
            if blob.get("encoding") != "base64":
                return None
            content = base64.b64decode(blob.get("content", ""), validate=False)
            if len(content) != item.get("size"):
                return None
            return item["path"], content

    blobs = await asyncio.gather(*(load_blob(item) for item in entries))
    files = {path: content for item in blobs if item is not None for path, content in [item]}
    if not files:
        raise HTTPException(422, "No supported source files were found in the repository.")
    return files


@app.post("/api/v1/scans/github", status_code=201)
async def scan_github(request: GitHubScanRequest, user: dict = Depends(current_user)) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PrivacyLint/0.2"}
    if request.token:
        headers["Authorization"] = f"Bearer {request.token}"
    root = f"https://api.github.com/repos/{request.owner}/{request.repo}"
    timeout = httpx.Timeout(20, connect=8)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            repository = await _github_json(client, root, headers)
            ref = request.ref or repository.get("default_branch") or "main"
            branch = await _github_json(client, f"{root}/branches/{quote(ref, safe='')}", headers)
            commit_sha = branch.get("commit", {}).get("sha")
            if not commit_sha:
                raise HTTPException(422, "GitHub did not return the requested branch commit.")
            files = await _github_source_files(client, root, commit_sha, headers)
    except httpx.TimeoutException as error:
        raise HTTPException(504, "GitHub did not respond before the scan timed out.") from error
    except httpx.HTTPError as error:
        raise HTTPException(502, "Could not connect to GitHub.") from error
    selected = set(request.rule_ids) if request.rule_ids is not None else None
    if selected is not None:
        valid = {rule["id"] for rule in load_rules()}
        if not selected or selected - valid:
            raise HTTPException(422, "One or more selected rule IDs are invalid.")
    return await _save_scan(files, repo=request.repo, owner=request.owner, source="github", user_id=user["id"], enabled_rule_ids=selected, ref=ref, git_commit=commit_sha)


@app.get("/api/v1/scans")
async def list_scans(limit: int = 50, user: dict = Depends(current_user)) -> dict:
    if not 1 <= limit <= 100:
        raise HTTPException(422, "Limit must be between 1 and 100.")
    scans = await store.list(limit, user["id"])
    return {"scans": scans, "count": len(scans)}


@app.get("/api/v1/scans/{scan_id}/sarif")
async def scan_sarif(scan_id: str, user: dict = Depends(current_user)) -> Response:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return JSONResponse(to_sarif(scan), media_type="application/sarif+json")


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, user: dict = Depends(current_user)) -> dict:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return scan


@app.get("/api/v1/scans/{scan_id}/graph")
async def scan_graph(scan_id: str, format: str = "json", user: dict = Depends(current_user)) -> Response:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    graph = lineage_store.save(build_lineage(scan))
    if format == "json":
        return JSONResponse(graph)
    nx_graph = lineage_store.networkx[scan_id]
    if format == "graphml":
        return Response(to_graphml(nx_graph), media_type="application/graphml+xml")
    if format == "svg":
        return Response(to_svg(graph), media_type="image/svg+xml")
    if format == "png":
        return Response(to_png(graph), media_type="image/png")
    raise HTTPException(422, "Format must be json, graphml, svg, or png.")


@app.get("/api/v1/scans/{scan_id}/inventory")
async def scan_inventory(scan_id: str, user: dict = Depends(current_user)) -> dict:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return {"sdk_inventory": scan.get("sdk_inventory", []), "outbound_hosts": scan.get("outbound_hosts", []), "erasure_coverage": scan.get("erasure_coverage", {"stores": 0, "covered": 0, "percent": 100})}


@app.post("/api/v1/scans/{scan_id}/tests")
async def generate_tests(scan_id: str, request: TestGenerationRequest, user: dict = Depends(current_user)) -> dict:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    all_findings = scan.get("findings", [])
    if request.finding_ids:
        selected = [finding for finding in all_findings if finding["id"] in set(request.finding_ids)]
        if len(selected) != len(set(request.finding_ids)):
            raise HTTPException(404, "One or more findings were not found.")
    else:
        selected = all_findings
    pending = [finding for finding in selected if not finding.get("verified")]
    if pending:
        raise HTTPException(409, "Regression tests are generated only after a sandbox rescan verifies the fix.")
    generated = []
    metadata = {"test_framework": scan.get("test_framework"), "test_setup_config": scan.get("test_setup_config")}
    for finding in selected:
        result = generate_regression_test(finding, metadata)
        generated.append({"finding_id": finding["id"], "rule_id": finding["rule_id"], **result})
    return {"scan_id": scan_id, "tests": generated, "count": len(generated)}


@app.post("/api/v1/scans/{scan_id}/fixes/{finding_id}")
async def verify_fix(
    scan_id: str,
    finding_id: str,
    file: UploadFile = File(...),
    ai_enabled: bool = Form(default=False),
    user: dict = Depends(current_user),
) -> dict:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    finding = next((item for item in scan.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    if finding.get("verified"):
        raise HTTPException(409, "This finding already has a verified fix.")
    payload = await file.read(50 * 1024 * 1024 + 1)
    await file.close()
    try:
        files = read_zip(payload)
    except ArchiveError as error:
        raise HTTPException(422, str(error)) from error
    if _scan_hash(files) != scan["scan_hash"] and scan.get("source") == "github":
        files = _normalize_github_archive_root(files)
    if _scan_hash(files) != scan["scan_hash"]:
        raise HTTPException(409, "This ZIP does not match the scanned snapshot. For a GitHub scan, download the archive for the same branch or commit and try again.")

    candidate = None
    verification = {"verified": False, "reason": "No bounded template patch applies to this code pattern."}
    tier = "Template"
    ai_result = None
    gemini_configured = bool(os.getenv("GEMINI_API_KEY", "").strip())
    if ai_enabled and gemini_configured and finding.get("rule_id") == "PL008":
        ai_result = await run_gemini_agent(files, finding, scan)
        if ai_result and ai_result.get("candidate") and ai_result.get("verification", {}).get("verified"):
            candidate = ai_result["candidate"]
            verification = {**ai_result["verification"], "patched_files": ai_result["patched_files"]}
            tier = "Gemini"
    if not verification.get("verified"):
        candidate = tier0_candidate(finding, files)
        verification = verify_candidate(files, finding, candidate) if candidate else {"verified": False, "reason": "No bounded template patch applies to this code pattern."}
    if not verification.get("verified") and ai_enabled and gemini_configured and finding.get("rule_id") != "PL008":
        ai_result = await run_gemini_agent(files, finding, scan)
        if ai_result and ai_result.get("candidate") and ai_result.get("verification", {}).get("verified"):
            candidate = ai_result["candidate"]
            verification = {**ai_result["verification"], "patched_files": ai_result["patched_files"]}
            tier = "Gemini"
    if not candidate or not verification.get("verified"):
        await store.audit_event(user_id=user["id"], event="fix_attempt", outcome="guidance", metadata={"scan_id": scan_id, "finding_id": finding_id, "model": (ai_result or {}).get("model"), "iterations": (ai_result or {}).get("iterations", 0), "tier": "none"})
        guidance = guidance_for(finding)
        guidance["ai_available"] = bool(os.getenv("GEMINI_API_KEY", "").strip())
        return guidance

    verified_scan = await _save_scan(
        verification["patched_files"], repo=scan["repo"], owner=scan.get("owner"), source="sandbox",
        user_id=user["id"], verified_fix_bonus=1,
    )
    try:
        await store.mark_verified(source_scan_id=scan_id, finding_id=finding_id, verified_scan_id=verified_scan["id"], user_id=user["id"], patch=candidate["patch"])
    except ValueError as error:
        raise HTTPException(409, "The scan changed before the verified result could be recorded.") from error
    await store.audit_event(user_id=user["id"], event="fix_attempt", outcome="verified", metadata={"scan_id": scan_id, "finding_id": finding_id, "model": (ai_result or {}).get("model"), "iterations": (ai_result or {}).get("iterations", 0), "tier": tier})
    return {
        "status": "verified", "verified": True, "tier": tier,
        "patch": candidate["patch"],
        "patch_preview": candidate.get("patch_preview", candidate["patch"]),
        "explanation": candidate.get("explanation", verification.get("reason", "The patch passed deterministic sandbox rescan.")),
        "assumptions": candidate.get("assumptions", []), "dpdp_section": finding.get("dpdp_section"),
        "verified_scan_id": verified_scan["id"], "score_before": scan["score"], "score_after": verified_scan["score"],
        "rescan": {"files_scanned": verified_scan["files_scanned"], "findings": len(verified_scan["findings"]), "parse_errors": verified_scan["parse_errors"]},
        "ai_used": tier == "Gemini",
        "ai_notice": (ai_result or {}).get("error") if ai_result and tier != "Gemini" else None,
    }


@app.post("/api/v1/scans/{scan_id}/pull-request", status_code=201)
async def create_pull_request(scan_id: str, request: PullRequestRequest, user: dict = Depends(current_user)) -> dict:
    scan = await store.get(scan_id, user["id"])
    if not scan:
        raise HTTPException(404, "Scan not found.")
    if scan.get("source") != "github" or not scan.get("owner"):
        raise HTTPException(409, "Pull requests can only be created from a GitHub repository scan.")
    finding_by_id = {finding["id"]: finding for finding in scan.get("findings", [])}
    selected_ids = [fix.finding_id for fix in request.fixes]
    if len(selected_ids) != len(set(selected_ids)):
        raise HTTPException(422, "Select each verified finding only once.")
    selected = []
    source_paths: set[str] = set()
    for fix in request.fixes:
        finding = finding_by_id.get(fix.finding_id)
        if not finding or not finding.get("verified"):
            raise HTTPException(409, "Only findings with sandbox-verified fixes can be included.")
        if finding["file"] in source_paths:
            raise HTTPException(409, "Choose at most one fix per source file in a pull request.")
        source_paths.add(finding["file"])
        expected_hash = await store.verified_patch_hash(source_scan_id=scan_id, finding_id=fix.finding_id, user_id=user["id"])
        if not expected_hash or hashlib.sha256(fix.patch.encode("utf-8")).hexdigest() != expected_hash:
            raise HTTPException(409, "A selected patch no longer matches the version verified by the sandbox. Re-verify the fix first.")
        selected.append((finding, fix.patch))

    token = request.github_token.strip()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PrivacyLint/0.2", "Authorization": f"Bearer {token}"}
    root = f"https://api.github.com/repos/{quote(scan['owner'], safe='')}/{quote(scan['repo'], safe='')}"
    timeout = httpx.Timeout(30, connect=8)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            await _github_json(client, "https://api.github.com/user", headers)
            repository = await _github_json(client, root, headers)
            if repository.get("permissions") and not repository["permissions"].get("push"):
                raise HTTPException(403, "This GitHub token needs write access to repository contents and pull requests.")
            base_branch = scan.get("ref") or repository.get("default_branch") or "main"
            branch_data = await _github_json(client, f"{root}/branches/{quote(base_branch, safe='')}", headers)
            base_commit = branch_data.get("commit", {}).get("sha")
            base_tree = branch_data.get("commit", {}).get("commit", {}).get("tree", {}).get("sha")
            if not base_commit or not base_tree:
                raise HTTPException(502, "GitHub did not return a valid base branch commit.")
            source_files = await _github_source_files(client, root, base_commit, headers)
            if _scan_hash(source_files) != scan.get("scan_hash"):
                raise HTTPException(409, "This branch changed after the scan. Run a fresh scan before opening a pull request.")

            patched_source = dict(source_files)
            tests: dict[str, str] = {}
            added_setup: set[str] = set()
            for finding, patch_text in selected:
                candidate = regenerate_secret_candidate(patched_source, finding, patch_text)
                if candidate:
                    candidate_files = dict(patched_source)
                    candidate_files[candidate["file"]] = candidate["after"].encode("utf-8")
                else:
                    if finding.get("rule_id") == "PL008":
                        raise HTTPException(409, "The secret-removal plan no longer matches this source. Re-verify the fix.")
                    try:
                        candidate_files = apply_unified_diff(patched_source, patch_text)
                    except (ValueError, UnicodeDecodeError) as error:
                        raise HTTPException(409, "A verified patch no longer applies to the scanned branch.") from error
                changed = [path for path in candidate_files if candidate_files[path] != patched_source.get(path)]
                if changed != [finding["file"]]:
                    raise HTTPException(422, "A verified patch must update only its finding's source file.")
                if not candidate:
                    candidate = {
                        "file": finding["file"],
                        "before": patched_source[finding["file"]].decode("utf-8", errors="strict"),
                        "after": candidate_files[finding["file"]].decode("utf-8", errors="strict"),
                        "patch": patch_text,
                    }
                verification = await run_in_threadpool(verify_candidate, patched_source, finding, candidate)
                if not verification.get("verified"):
                    raise HTTPException(409, "A selected patch no longer passes the deterministic sandbox rescan.")
                patched_source = verification["patched_files"]
                generated = generate_regression_test(finding, {"test_framework": scan.get("test_framework"), "test_setup_config": scan.get("test_setup_config")})
                if not generated.get("supported"):
                    raise HTTPException(409, "The repository's test framework has no safe regression-test template for a selected finding.")
                test_path = generated["path"]
                if test_path in source_files or test_path in tests:
                    stem, separator, suffix = test_path.rpartition(".")
                    test_path = f"{stem}_{finding['id'][:6]}{separator}{suffix}" if separator else f"{test_path}_{finding['id'][:6]}"
                tests[test_path] = generated["content"]
                setup = generated.get("setup_config")
                if setup and setup.get("path") not in added_setup:
                    setup_path = setup["path"]
                    setup_content = setup["content"]
                    if setup_path == "requirements-privacylint.txt":
                        existing = source_files.get(setup_path, b"").decode("utf-8", errors="replace")
                        tests[setup_path] = (existing.rstrip() + "\n" + setup_content.lstrip()).lstrip()
                    elif setup_path == "pom.xml":
                        pom = patched_source.get(setup_path, source_files.get(setup_path, b"<project></project>")).decode("utf-8", errors="replace")
                        if "</dependencies>" in pom:
                            pom = pom.replace("</dependencies>", f"{setup_content}</dependencies>", 1)
                        elif "</project>" in pom:
                            pom = pom.replace("</project>", f"<dependencies>{setup_content}</dependencies></project>", 1)
                        else:
                            raise HTTPException(409, "Could not safely add the generated JUnit dependency to pom.xml.")
                        tests[setup_path] = pom
                    added_setup.add(setup_path)

            rescanned = await run_in_threadpool(scan_files, patched_source)
            after_score = calculate_score(rescanned["findings"])["score"]
            changed_files = {path: content for path, content in patched_source.items() if source_files.get(path) != content}
            changed_files.update({path: content.encode("utf-8") for path, content in tests.items()})
            if not changed_files:
                raise HTTPException(422, "No source or regression-test changes were generated.")

            branch_name = f"privacylint/fixes-{scan_id[:8]}-{uuid4().hex[:6]}"
            blob_semaphore = asyncio.Semaphore(6)

            async def create_blob(path: str, content: bytes) -> dict:
                async with blob_semaphore:
                    return await _github_write(client, "POST", f"{root}/git/blobs", headers, {"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"})

            blob_rows = await asyncio.gather(*(create_blob(path, content) for path, content in changed_files.items()))
            tree_rows = [{"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]} for (path, _), blob in zip(changed_files.items(), blob_rows)]
            tree = await _github_write(client, "POST", f"{root}/git/trees", headers, {"base_tree": base_tree, "tree": tree_rows})
            commit_message = f"PrivacyLint: apply {len(selected)} verified privacy fix{'es' if len(selected) != 1 else ''}"
            commit = await _github_write(client, "POST", f"{root}/git/commits", headers, {"message": commit_message, "tree": tree["sha"], "parents": [base_commit]})
            await _github_write(client, "POST", f"{root}/git/refs", headers, {"ref": f"refs/heads/{branch_name}", "sha": commit["sha"]})
            included = "\n".join(f"- `{finding['rule_id']}` {finding['title']} — `{finding['file']}:{finding['line']}` ({finding['dpdp_section']})" for finding, _ in selected)
            unverified = [finding for finding in scan.get("findings", []) if not finding.get("verified")]
            manual = "\n".join(f"- `{finding['rule_id']}` `{finding['file']}:{finding['line']}` — manual review required" for finding in unverified[:30]) or "None"
            body = (
                "## PrivacyLint verified remediation\n\n"
                f"Applied {len(selected)} patch(es) that passed a deterministic sandbox rescan. Generated regression tests are included in this branch.\n\n"
                f"**Posture score:** {scan['score']:.0f} → {after_score:.0f}\n"
                f"**Scan hash:** `{scan['scan_hash']}`\n"
                f"**Base branch:** `{base_branch}`\n\n"
                f"### Included fixes\n{included}\n\n"
                f"### Findings still requiring manual review ({len(unverified)})\n{manual}\n\n"
                "Review the generated tests and code changes before merging. PrivacyLint does not merge pull requests."
            )
            pull = await _github_write(client, "POST", f"{root}/pulls", headers, {
                "title": f"PrivacyLint: {len(selected)} verified privacy fix{'es' if len(selected) != 1 else ''}",
                "head": branch_name, "base": base_branch, "body": body,
            })
    except httpx.TimeoutException as error:
        raise HTTPException(504, "GitHub did not respond before the pull request workflow timed out.") from error
    except httpx.HTTPError as error:
        raise HTTPException(502, "Could not connect to GitHub to create the pull request.") from error
    await store.audit_event(user_id=user["id"], event="github_pr", outcome="opened", metadata={"scan_id": scan_id, "finding_id": ",".join(selected_ids), "tier": "verified"})
    return {
        "status": "created", "url": pull.get("html_url"), "number": pull.get("number"), "branch": branch_name,
        "base": base_branch, "commit": commit.get("sha"), "files_changed": len(changed_files),
        "fixes": len(selected), "tests": len(tests), "score_before": scan["score"], "score_after": after_score,
    }


@app.get("/api/v1/badge/{owner}/{repo}.svg")
async def badge(owner: str, repo: str) -> Response:
    scans = await store.list(100)
    scan = next((item for item in scans if item.get("owner") and item["owner"].casefold() == owner.casefold() and item["repo"].casefold() == repo.casefold()), None)
    if not scan:
        raise HTTPException(404, "No scan found for this repository.")
    color = "#34d399" if scan["score"] >= 75 else "#fbbf24" if scan["score"] >= 45 else "#f87171"
    label = f"PrivacyLint {scan['grade']} · {scan['score']:.0f}/100"
    width = max(220, len(label) * 7 + 28)
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="28" role="img" aria-label="{label}"><rect width="100%" height="100%" rx="6" fill="#121821"/><circle cx="14" cy="14" r="4" fill="{color}"/><text x="26" y="18" fill="#e5e7eb" font-family="Inter,Arial,sans-serif" font-size="12">{label}</text></svg>'
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=300"})
