from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

from .scanner import LANGUAGE_BY_EXTENSION, scan_files
from .sarif import to_sarif
from .scoring import calculate_score
from .baseline import finding_key, read_baseline, write_baseline


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _read_repository(path: Path) -> dict[str, bytes]:
    files = {}
    for file in path.rglob("*"):
        if not file.is_file() or file.is_symlink() or file.suffix.lower() not in LANGUAGE_BY_EXTENSION:
            continue
        try:
            relative = file.relative_to(path).as_posix()
            if file.stat().st_size <= 1_000_000:
                files[relative] = file.read_bytes()
        except OSError:
            continue
    return files


def _scan(args) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print("Scan path must be an existing directory.", file=sys.stderr)
        return 2
    files = _read_repository(root)
    result = scan_files(files)
    score = calculate_score(result["findings"])
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    output = {
        "repository": root.name,
        "scan_hash": digest.hexdigest(),
        "files_scanned": result["files_scanned"],
        "parse_errors": result["parse_errors"],
        "ignored_files": result["ignored_files"],
        "languages": result["languages"],
        "score": score["score"],
        "grade": score["grade"],
        "score_details": score,
        "findings": result["findings"],
    }
    changed_findings = result["findings"]
    if args.baseline:
        baseline_path = Path(args.baseline).expanduser()
        if baseline_path.exists():
            try:
                existing = read_baseline(baseline_path)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                print(f"Baseline could not be read: {error}", file=sys.stderr)
                return 2
            changed_findings = [item for item in result["findings"] if finding_key(item) not in existing]
            output["new_findings"] = changed_findings
            output["baseline"] = {"path": str(baseline_path), "existing_findings": len(existing), "new_findings": len(changed_findings)}
        if args.update_baseline:
            write_baseline(baseline_path, {"scan_hash": output["scan_hash"], "findings": result["findings"]})
    elif args.update_baseline:
        print("--update-baseline requires --baseline.", file=sys.stderr)
        return 2
    if args.format == "sarif":
        print(json.dumps(to_sarif(output), indent=2))
    else:
        print(json.dumps(output, indent=2))
    threshold = SEVERITY_ORDER[args.fail_on]
    return int(any(SEVERITY_ORDER.get(item["severity"], 3) <= threshold for item in changed_findings))


async def _survey_async(args) -> int:
    list_path = Path(args.list).expanduser()
    if not list_path.is_file():
        print("Repository list file was not found.", file=sys.stderr)
        return 2
    repositories = [line.strip() for line in list_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    token = os.getenv(args.token_env, "") if args.token_env else ""
    async with httpx.AsyncClient(timeout=180) as client:
        for repository in repositories:
            parts = repository.removeprefix("https://github.com/").strip("/").split("/")
            if len(parts) != 2 or any(not part for part in parts):
                print(f"{repository}: expected owner/repository")
                continue
            response = await client.post(f"{args.api_url.rstrip('/')}/api/v1/scans/github", json={"owner": parts[0], "repo": parts[1], "token": token or None})
            if not response.is_success:
                print(f"{repository}: scan failed ({response.status_code})")
                continue
            scan = response.json()
            print(f"{repository}: grade {scan['grade']} ({scan['score']:.0f}/100), {len(scan['findings'])} findings")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="privacylint", description="Deterministic DPDP privacy scanning")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a local repository without uploading its source")
    scan_parser.add_argument("path", help="repository directory")
    scan_parser.add_argument("--format", choices=["json", "sarif"], default="json")
    scan_parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high")
    scan_parser.add_argument("--baseline", help="baseline JSON used to identify newly introduced findings")
    scan_parser.add_argument("--update-baseline", action="store_true", help="write the current finding set to --baseline")
    scan_parser.set_defaults(handler=_scan)
    survey_parser = subparsers.add_parser("survey", help="scan repositories listed in a text file")
    survey_parser.add_argument("--list", required=True, help="text file with one owner/repository per line")
    survey_parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    survey_parser.add_argument("--token-env", default="GITHUB_TOKEN", help="environment variable containing a GitHub token")
    survey_parser.set_defaults(handler=lambda args: asyncio.run(_survey_async(args)))
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
