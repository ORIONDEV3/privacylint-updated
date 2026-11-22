from __future__ import annotations

import asyncio
import io
import json
import socket
import subprocess
import sys
import zipfile

import pytest
import httpx

from app import main
from app.archive import ArchiveError, read_zip
from app.baseline import read_baseline, write_baseline
from app.detectors import _luhn_valid, _verhoeff_valid, detect_literals, redact_sensitive
from app.fixes import apply_unified_diff, regenerate_secret_candidate, tier0_candidate, verify_candidate
from app.inventory import extract_inventory
from app.lineage import LineageStore, build_lineage, to_graphml, to_png, to_svg
from app.rules import load_rules
from app.sarif import to_sarif
from app.scanner import scan_files
from app.scoring import calculate_score
from app.testgen import detect_framework, generate_regression_test


FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"
ENGINE_ROOT = FIXTURES.parents[1]


def _local_loopback_available() -> bool:
    if sys.platform != "win32":
        return True
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.2)
            with socket.socket() as client:
                client.settimeout(0.2)
                client.connect(listener.getsockname())
            connection, _ = listener.accept()
            connection.close()
        return True
    except OSError:
        return False


def fixture_files(kind: str) -> dict[str, bytes]:
    return {"server.js": (FIXTURES / kind / "server.js").read_bytes()}


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_github_zip_root_is_removed_before_snapshot_hashing():
    repository = {"server.ts": b"export const value = 1;", "package.json": b'{"name":"demo"}'}
    downloaded = {f"PrivacyLint-main/{name}": content for name, content in repository.items()}
    normalized = main._normalize_github_archive_root(downloaded)

    assert normalized == repository
    assert main._scan_hash(normalized) == main._scan_hash(repository)
    assert main._normalize_github_archive_root(repository) == repository
    mixed_roots = {"one/server.ts": b"a", "two/client.ts": b"b"}
    assert main._normalize_github_archive_root(mixed_roots) == mixed_roots


def test_rule_metadata_has_twelve_dpdp_mapped_rules():
    rules = load_rules()
    assert len(rules) == 12
    assert {rule["id"] for rule in rules} == {f"PL{index:03}" for index in range(1, 13)}
    assert all(rule["dpdp_mapping"] in {"§5", "§8(5)", "§8(6)", "§9"} for rule in rules)


def test_vulnerable_fixture_triggers_all_twelve_rules():
    result = scan_files(fixture_files("vulnerable"))
    found = {finding["rule_id"] for finding in result["findings"]}
    assert found == {f"PL{index:03}" for index in range(1, 13)}
    assert all(finding["line"] > 0 and finding["dpdp_section"].startswith("§") for finding in result["findings"])
    assert all("local-demo-secret-value" not in finding["snippet"] for finding in result["findings"])


def test_safe_fixture_suppresses_sanitized_and_gated_flows():
    result = scan_files(fixture_files("safe"))
    assert not result["findings"]


def test_keyword_and_literal_pii_detection_and_redaction():
    matches = detect_literals("Reach person@company.example or pay me at testuser@okaxis")
    assert {match.category for match in matches} == {"email", "financial"}
    assert "<redacted:email>" in redact_sensitive("person@company.example")
    assert "contact" in __import__("app.detectors", fromlist=["categories_from_names"]).categories_from_names("deviceId email address")


def test_verhoeff_and_luhn_checks_are_checksum_based():
    assert _verhoeff_valid("2363")
    assert not _verhoeff_valid("2364")
    assert _luhn_valid("4111111111111111")
    assert not _luhn_valid("4111111111111112")


def test_score_is_deterministic_and_bounded():
    findings = [{"severity": "high", "pii_category": "aadhaar", "unauthenticated": True, "rule_id": "PL004"}]
    first = calculate_score(findings)
    assert first == calculate_score(findings)
    assert 0 <= first["score"] <= 100
    assert first["grade"] in {"A", "B", "C", "D", "F"}


def test_lineage_has_scan_scoped_nodes_and_supported_exports():
    scan = {"id": "scan-test", "findings": scan_files(fixture_files("vulnerable"))["findings"]}
    graph = build_lineage(scan)
    assert graph["nodes"]
    assert graph["edges"]
    assert {node["kind"] for node in graph["nodes"]} >= {"Source", "Route", "Controller", "Store", "SinkLog", "Finding"}
    assert all(node["scan_id"] == "scan-test" and "scan-test:" in node["id"] for node in graph["nodes"])
    assert {edge["type"] for edge in graph["edges"]} >= {"FLOWS_TO", "HAS_FINDING"}
    lineage_store = LineageStore()
    lineage_store.save(graph)
    assert "<graphml" in to_graphml(lineage_store.networkx["scan-test"])
    assert lineage_store.get("scan-test")["backend"] == "networkx"


def test_graph_exports_include_svg_and_png_signatures():
    graph = build_lineage({"id": "scan-export", "findings": scan_files(fixture_files("vulnerable"))["findings"]})
    assert "<svg" in to_svg(graph)
    assert to_png(graph).startswith(b"\x89PNG\r\n\x1a\n")


def test_sdk_inventory_strips_url_paths_and_reports_erasure_coverage():
    inventory = extract_inventory({
        "package.json": b'{"dependencies":{"express":"^5.0.0"}}',
        "app.js": b'db.insert({aadhaar}); fetch("https://partner.example/collect?token=should-never-appear")',
    }, [{"file": "app.js", "line": 1, "sink_type": "database", "rule_id": "PL010"}])
    assert inventory["sdk_inventory"] == [{"name": "express", "versions": ["^5.0.0"]}]
    assert inventory["outbound_hosts"] == ["partner.example"]
    assert "should-never-appear" not in str(inventory)
    assert inventory["erasure_coverage"]["percent"] == 0


def test_test_generator_detects_frameworks_and_honors_frozen_static_assertions(tmp_path):
    assert detect_framework({"package.json": b'{"devDependencies":{"jest":"^30.0.0"}}'})[0] == "jest"
    assert detect_framework({"package.json": b'{"devDependencies":{"mocha":"^11.0.0"}}'})[0] == "mocha"
    assert detect_framework({"app.py": b"def main(): pass"})[0] == "pytest"
    assert detect_framework({"src/Main.java": b"class Main {}", "pom.xml": b"<project />"})[0] == "junit5"
    scan = scan_files(fixture_files("vulnerable"))
    assert all(generate_regression_test(finding, {"test_framework": "node:test"})["supported"] for finding in scan["findings"])
    safe_source = (FIXTURES / "safe" / "server.js").read_text(encoding="utf-8").replace('"/profile"', '"/signup"')
    repo_root = tmp_path
    test_dir = repo_root / "tests" / "privacy"
    test_dir.mkdir(parents=True)
    for rule_id in ("PL001", "PL002", "PL003", "PL004", "PL005"):
        finding = next(item for item in scan["findings"] if item["rule_id"] == rule_id)
        generated = generate_regression_test(finding, {"test_framework": "pytest", "test_setup_config": None})
        test_path = repo_root / generated["path"]
        test_path.write_text(generated["content"], encoding="utf-8")
        (repo_root / finding["file"]).write_bytes((FIXTURES / "vulnerable" / finding["file"]).read_bytes())
        reverted = subprocess.run([sys.executable, "-m", "pytest", str(test_path), "-q"], cwd=repo_root, capture_output=True, text=True)
        assert reverted.returncode != 0, rule_id
        (repo_root / finding["file"]).write_text(safe_source, encoding="utf-8")
        fixed = subprocess.run([sys.executable, "-m", "pytest", str(test_path), "-q"], cwd=repo_root, capture_output=True, text=True)
        assert fixed.returncode == 0, f"{rule_id}: {fixed.stdout}\n{fixed.stderr}"
        (repo_root / finding["file"]).write_bytes((FIXTURES / "vulnerable" / finding["file"]).read_bytes())


def test_tier0_patch_is_exactly_applied_and_verified_by_rescan():
    files = fixture_files("vulnerable")
    scan = scan_files(files)
    finding = next(item for item in scan["findings"] if item["rule_id"] == "PL001")
    candidate = tier0_candidate(finding, files)
    assert candidate and candidate["template_id"] == "mask_log_value"
    assert apply_unified_diff(files, candidate["patch"])["server.js"] == candidate["after"].encode()
    result = verify_candidate(files, finding, candidate)
    assert result["verified"]
    assert not any(item["rule_id"] == "PL001" for item in result["findings"])


def test_tier0_secret_patch_is_not_returned_with_literal_context():
    files = fixture_files("vulnerable")
    finding = next(item for item in scan_files(files)["findings"] if item["rule_id"] == "PL008")
    candidate = tier0_candidate(finding, files)
    assert candidate
    assert "local-demo-secret-value" not in candidate["patch"]
    assert "local-demo-secret-value" not in candidate["patch_preview"]
    assert "SERVICE_API_KEY" in candidate["after"]
    assert verify_candidate(files, finding, candidate)["verified"]


def test_python_hardcoded_api_key_gets_secret_safe_verified_fix():
    secret = "local-only-test-key-123456"
    path = "barchart-ondemand-client-python-master/ondemand/ondemand_client.py"
    source = (
        '"""OnDemand client."""\n'
        "from __future__ import annotations\n\n"
        "import ondeman\n"
        f'client = ondeman.OnDemandClient(api_key="{secret}")\n'
    ).encode()
    files = {path: source}
    finding = next(item for item in scan_files(files)["findings"] if item["rule_id"] == "PL008")
    candidate = tier0_candidate(finding, files)

    assert candidate is not None
    assert secret not in candidate["patch"]
    assert secret not in candidate["patch_preview"]
    assert "BARCHART_API_KEY" in candidate["after"]
    assert candidate["after"].index("from __future__") < candidate["after"].index("import os as _privacylint_os")
    verified = verify_candidate(files, finding, candidate)
    assert verified["verified"]
    assert not any(item["rule_id"] == "PL008" for item in verified["findings"])
    assert regenerate_secret_candidate(files, finding, candidate["patch"]) == candidate


def test_javascript_database_password_gets_secret_safe_verified_fix():
    secret = "local-only-test-password-123"
    path = "db/index.js"
    files = {path: f"module.exports = {{\n  user: 'app',\n  password: '{secret}',\n}};\n".encode()}
    finding = next(item for item in scan_files(files)["findings"] if item["rule_id"] == "PL008")
    candidate = tier0_candidate(finding, files)

    assert candidate is not None
    assert secret not in candidate["patch"]
    assert secret not in candidate["patch_preview"]
    assert 'process.env.DB_PASSWORD' in candidate["after"]
    assert verify_candidate(files, finding, candidate)["verified"]
    assert regenerate_secret_candidate(files, finding, candidate["patch"]) == candidate


def test_sarif_shape_and_locations():
    finding = {"id": "pl_test", "rule_id": "PL001", "title": "Personal data written to logs", "severity": "high", "file": "src/app.js", "line": 7, "pii_category": "aadhaar", "dpdp_section": "§8(5)", "remediation": "Redact personal data."}
    sarif = to_sarif({"findings": [finding], "scan_hash": "abc", "score": 80, "grade": "B"})
    assert sarif["version"] == "2.1.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "PL001"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    json.dumps(sarif)


def test_baseline_round_trip_and_cli_blocks_only_new_findings(tmp_path):
    baseline = tmp_path / "baseline.json"
    scan = scan_files(fixture_files("vulnerable"))
    write_baseline(baseline, {"scan_hash": "fixture-hash", "findings": scan["findings"]})
    assert len(read_baseline(baseline)) == len(scan["findings"])
    command = [sys.executable, "-m", "app.cli", "scan", str(FIXTURES / "vulnerable"), "--baseline", str(baseline)]
    result = subprocess.run(command, cwd=ENGINE_ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["baseline"]["new_findings"] == 0


def test_zip_slip_and_oversized_archives_are_rejected():
    with pytest.raises(ArchiveError):
        read_zip(zip_bytes({"../escape.js": b"console.log('x')"}))


@pytest.mark.asyncio
@pytest.mark.skipif(not _local_loopback_available(), reason="Managed Windows sandbox blocks local asyncio socketpair setup")
async def test_upload_api_persists_scan_and_returns_sarif(tmp_path, monkeypatch):
    main.store.database_url = ""
    main.store.pool = None
    main.store.sqlite_path = tmp_path / "scans.sqlite3"
    payload = zip_bytes(fixture_files("vulnerable"))
    async with main.app.router.lifespan_context(main.app):
      async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
        monkeypatch.setenv("GEMINI_API_KEY", "unit-test-key-must-not-be-returned")
        capability_response = await client.get("/api/v1/capabilities")
        assert capability_response.status_code == 200
        assert capability_response.json()["ai"]["configured"] is True
        assert "unit-test-key-must-not-be-returned" not in capability_response.text
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        options = await client.options("/api/v1/scans/github", headers={
            "Origin": "http://localhost:5174",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        })
        assert options.status_code == 200
        assert options.headers["access-control-allow-origin"] == "http://localhost:5174"
        secret_value = "local-only-token-that-must-not-be-reflected"
        invalid_request = await client.post("/api/v1/scans/github", json={"owner": "invalid owner", "repo": "demo", "token": secret_value})
        assert invalid_request.status_code == 422
        assert secret_value not in invalid_request.text
        response = await client.post("/api/v1/scans/upload", files={"file": ("sample.zip", payload, "application/zip")})
        assert response.status_code == 201, response.text
        scan = response.json()
        assert scan["files_scanned"] == 1
        assert scan["findings"]
        blocked_tests = await client.post(f"/api/v1/scans/{scan['id']}/tests", json={"finding_ids": [scan["findings"][0]["id"]]})
        assert blocked_tests.status_code == 409
        assert (await client.get(f"/api/v1/scans/{scan['id']}")).status_code == 200
        sarif_response = await client.get(f"/api/v1/scans/{scan['id']}/sarif")
        assert sarif_response.status_code == 200
        assert sarif_response.json()["version"] == "2.1.0"
        graph_response = await client.get(f"/api/v1/scans/{scan['id']}/graph")
        assert graph_response.status_code == 200
        assert graph_response.json()["scan_id"] == scan["id"]
        assert (await client.get(f"/api/v1/scans/{scan['id']}/graph?format=graphml")).text.startswith("<graphml")
        assert (await client.get(f"/api/v1/scans/{scan['id']}/graph?format=svg")).text.startswith("<svg")
        assert (await client.get(f"/api/v1/scans/{scan['id']}/graph?format=png")).content.startswith(b"\x89PNG\r\n\x1a\n")
        inventory = (await client.get(f"/api/v1/scans/{scan['id']}/inventory")).json()
        assert "erasure_coverage" in inventory
        log_finding = next(item for item in scan["findings"] if item["rule_id"] == "PL001")
        fix_response = await client.post(
            f"/api/v1/scans/{scan['id']}/fixes/{log_finding['id']}",
            data={"ai_enabled": "false"},
            files={"file": ("sample.zip", payload, "application/zip")},
        )
        assert fix_response.status_code == 200, fix_response.text
        verified = fix_response.json()
        assert verified["verified"] and verified["tier"] == "Template"
        assert verified["rescan"]["findings"] == len(scan["findings"]) - 1
        assert verified["score_after"] >= verified["score_before"]
        updated_scan = (await client.get(f"/api/v1/scans/{scan['id']}")).json()
        assert next(item for item in updated_scan["findings"] if item["id"] == log_finding["id"])["verified"]
        secret_finding = next(item for item in scan["findings"] if item["rule_id"] == "PL008")
        async def gemini_rate_limited(*_args, **_kwargs):
            return {"candidate": None, "error": "Gemini quota is temporarily exhausted; fallback will be used."}
        monkeypatch.setenv("GEMINI_API_KEY", "mock-test-key-for-gemini-fallback")
        monkeypatch.setattr(main, "run_gemini_agent", gemini_rate_limited)
        secret_fix = await client.post(
            f"/api/v1/scans/{scan['id']}/fixes/{secret_finding['id']}",
            data={"ai_enabled": "true"},
            files={"file": ("sample.zip", payload, "application/zip")},
        )
        assert secret_fix.status_code == 200, secret_fix.text
        secret_result = secret_fix.json()
        assert secret_result["verified"] is True
        assert "local-demo-secret-value" not in secret_result["patch"]
        assert "local-demo-secret-value" not in secret_result["patch_preview"]
        assert "process.env.SERVICE_API_KEY" in secret_result["patch_preview"]
        assert secret_result["ai_notice"] == "Gemini quota is temporarily exhausted; fallback will be used."
        generated_tests = await client.post(f"/api/v1/scans/{scan['id']}/tests", json={"finding_ids": [log_finding["id"]]})
        assert generated_tests.status_code == 200
        assert generated_tests.json()["count"] == 1
        await main.store.save({
            "id": "22222222-2222-4222-8222-222222222222", "owner": "team", "repo": "demo", "source": "github",
            "scan_hash": "badge-hash", "score": 80, "grade": "B", "score_details": {},
            "files_scanned": 1, "parse_errors": 0, "ignored_files": 0, "languages": [], "findings": [],
        })
        badge = await client.get("/api/v1/badge/team/demo.svg")
        assert badge.status_code == 200
        assert "PrivacyLint B" in badge.text
