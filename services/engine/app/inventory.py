from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


URL_RE = re.compile(r"https?://[^\s\"'`<>]+", re.IGNORECASE)
DB_WRITE_RE = re.compile(r"(?i)\b(insert\s+into|update\s+\w+\s+set|\.\s*(insert|create|save|update|execute|query)\s*\()")
ERASURE_RE = re.compile(r"(?i)\b(delete|erase|erasure|anonymi[sz]e|retention|purge)\b")


def extract_inventory(files: dict[str, bytes], findings: list[dict]) -> dict:
    dependencies: dict[str, set[str]] = {}
    outbound_hosts: set[str] = set()
    for path, content in files.items():
        filename = path.rsplit("/", 1)[-1].lower()
        text = content.decode("utf-8", errors="replace")
        if filename == "package.json":
            try:
                package = json.loads(text)
                for group in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    for name, version in package.get(group, {}).items():
                        dependencies.setdefault(name, set()).add(str(version))
            except (ValueError, AttributeError):
                pass
        elif filename == "requirements.txt" or filename.endswith(".requirements.txt"):
            for line in text.splitlines():
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|!=|>|<)\s*([^;\s]+)", line)
                if match:
                    dependencies.setdefault(match.group(1), set()).add(match.group(2))
        elif filename == "pom.xml":
            try:
                root = ET.fromstring(text)
                for item in root.iter():
                    if item.tag.endswith("dependency"):
                        values = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in item}
                        if values.get("groupId") and values.get("artifactId"):
                            name = f"{values['groupId']}:{values['artifactId']}"
                            dependencies.setdefault(name, set()).add(values.get("version", "unspecified"))
            except ET.ParseError:
                pass
        for match in URL_RE.finditer(text):
            try:
                host = urlsplit(match.group(0).rstrip(".,);]")).hostname
                if host:
                    outbound_hosts.add(host.lower())
            except ValueError:
                continue

    db_stores = set()
    covered_stores = set()
    for path, content in files.items():
        lines = content.decode("utf-8", errors="replace").splitlines()
        has_file_erasure_path = any(ERASURE_RE.search(line) for line in lines)
        for line_number, line in enumerate(lines, 1):
            if DB_WRITE_RE.search(line):
                store = (path, line_number)
                db_stores.add(store)
                if has_file_erasure_path:
                    covered_stores.add(store)
    covered = len(covered_stores)
    erasure_percent = 100.0 if not db_stores else round(covered * 100 / len(db_stores), 2)
    return {
        "sdk_inventory": [{"name": name, "versions": sorted(versions)} for name, versions in sorted(dependencies.items())],
        "outbound_hosts": sorted(outbound_hosts),
        "erasure_coverage": {"stores": len(db_stores), "covered": covered, "percent": erasure_percent},
    }
