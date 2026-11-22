from __future__ import annotations

import json
import os
import sqlite3
import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .rules import ROOT


class ScanStore:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "").strip()
        self.pool = None
        self.sqlite_path = Path(os.getenv("PRIVACYLINT_STATE_DIR", str(ROOT / ".local-db"))) / "engine.sqlite3"

    async def connect(self) -> None:
        if self.database_url:
            import asyncpg

            self.pool = await asyncpg.create_pool(self.database_url, min_size=1, max_size=10)
            async with self.pool.acquire() as connection:
                await connection.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id UUID PRIMARY KEY, created_by UUID REFERENCES users(id) ON DELETE SET NULL,
                        owner TEXT, repo TEXT NOT NULL, source TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), scan_hash TEXT NOT NULL,
                        score NUMERIC(5,2) NOT NULL, grade CHAR(1) NOT NULL,
                        files_scanned INTEGER NOT NULL, parse_errors INTEGER NOT NULL,
                        ignored_files INTEGER NOT NULL, languages JSONB NOT NULL, summary JSONB NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY, scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        rule_id TEXT NOT NULL, severity TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,
                        snippet TEXT NOT NULL, sink_type TEXT NOT NULL, pii_category TEXT NOT NULL,
                        dpdp_section TEXT NOT NULL, data JSONB NOT NULL,
                        verified BOOLEAN NOT NULL DEFAULT FALSE,
                        verified_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL
                    );
                    ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;
                    ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;
                    ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL;
                    CREATE TABLE IF NOT EXISTS verified_fixes (
                        source_scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        finding_id TEXT NOT NULL, verified_scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        created_by UUID REFERENCES users(id) ON DELETE SET NULL, patch_hash TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(source_scan_id,finding_id)
                    );
                    CREATE TABLE IF NOT EXISTS analysis_audit (
                        id BIGSERIAL PRIMARY KEY, user_id UUID, event TEXT NOT NULL, outcome TEXT NOT NULL,
                        metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
                    CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);
                """)
        else:
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            with self._sqlite() as connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY, created_by TEXT, owner TEXT, repo TEXT NOT NULL, source TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, scan_hash TEXT NOT NULL,
                        score REAL NOT NULL, grade TEXT NOT NULL, files_scanned INTEGER NOT NULL,
                        parse_errors INTEGER NOT NULL, ignored_files INTEGER NOT NULL,
                        languages_json TEXT NOT NULL, summary_json TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        rule_id TEXT NOT NULL, severity TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,
                        snippet TEXT NOT NULL, sink_type TEXT NOT NULL, pii_category TEXT NOT NULL,
                        dpdp_section TEXT NOT NULL, data_json TEXT NOT NULL,
                        verified INTEGER NOT NULL DEFAULT 0, verified_scan_id TEXT
                    );
                    CREATE TABLE IF NOT EXISTS verified_fixes (
                        source_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        finding_id TEXT NOT NULL, verified_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        created_by TEXT, patch_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY(source_scan_id,finding_id)
                    );
                    CREATE TABLE IF NOT EXISTS analysis_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, event TEXT NOT NULL, outcome TEXT NOT NULL,
                        metadata_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
                    CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);
                """)
                scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
                if "created_by" not in scan_columns:
                    connection.execute("ALTER TABLE scans ADD COLUMN created_by TEXT")
                finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
                if "verified" not in finding_columns:
                    connection.execute("ALTER TABLE findings ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
                if "verified_scan_id" not in finding_columns:
                    connection.execute("ALTER TABLE findings ADD COLUMN verified_scan_id TEXT")

    @contextmanager
    def _sqlite(self):
        connection = sqlite3.connect(self.sqlite_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()

    async def save(self, scan: dict) -> None:
        owner, repo = scan.get("owner"), scan["repo"]
        summary = {
            "findings": scan.get("findings", []), "score_details": scan.get("score_details", {}),
            "sdk_inventory": scan.get("sdk_inventory", []), "outbound_hosts": scan.get("outbound_hosts", []),
            "erasure_coverage": scan.get("erasure_coverage", {"stores": 0, "covered": 0, "percent": 100}),
            "test_framework": scan.get("test_framework", "node:test"),
            "test_setup_config": scan.get("test_setup_config"),
        }
        if self.pool:
            async with self.pool.acquire() as connection:
                async with connection.transaction():
                    await connection.execute(
                        """INSERT INTO scans(id,created_by,owner,repo,source,scan_hash,score,grade,files_scanned,parse_errors,ignored_files,languages,summary)
                        VALUES($1,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb)""",
                        scan["id"], scan.get("user_id"), owner, repo, scan["source"], scan["scan_hash"], scan["score"], scan["grade"],
                        scan["files_scanned"], scan["parse_errors"], scan["ignored_files"], json.dumps(scan["languages"]), json.dumps(summary),
                    )
                    if scan["findings"]:
                        await connection.executemany(
                            """INSERT INTO findings(id,scan_id,rule_id,severity,file,line,snippet,sink_type,pii_category,dpdp_section,data)
                            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)""",
                            [(f"{scan['id']}:{item['id']}", scan["id"], item["rule_id"], item["severity"], item["file"], item["line"], item["snippet"], item["sink_type"], item["pii_category"], item["dpdp_section"], json.dumps(item)) for item in scan["findings"]],
                        )
        else:
            with self._sqlite() as connection:
                connection.execute(
                    """INSERT INTO scans(id,created_by,owner,repo,source,scan_hash,score,grade,files_scanned,parse_errors,ignored_files,languages_json,summary_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan["id"], scan.get("user_id"), owner, repo, scan["source"], scan["scan_hash"], scan["score"], scan["grade"], scan["files_scanned"], scan["parse_errors"], scan["ignored_files"], json.dumps(scan["languages"]), json.dumps(summary)),
                )
                connection.executemany(
                    """INSERT INTO findings(id,scan_id,rule_id,severity,file,line,snippet,sink_type,pii_category,dpdp_section,data_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    [(f"{scan['id']}:{item['id']}", scan["id"], item["rule_id"], item["severity"], item["file"], item["line"], item["snippet"], item["sink_type"], item["pii_category"], item["dpdp_section"], json.dumps(item)) for item in scan["findings"]],
                )

    async def get(self, scan_id: str, user_id: str | None = None) -> dict | None:
        if self.pool:
            async with self.pool.acquire() as connection:
                row = await connection.fetchrow("SELECT * FROM scans WHERE id=$1::uuid AND ($2::uuid IS NULL OR created_by=$2::uuid)", scan_id, user_id)
                if not row:
                    return None
                findings = await connection.fetch("SELECT data FROM findings WHERE scan_id=$1::uuid ORDER BY file,line,rule_id", scan_id)
                return self._from_pg(row, findings)
        with self._sqlite() as connection:
            if user_id:
                row = connection.execute("SELECT * FROM scans WHERE id=? AND created_by=?", (scan_id, user_id)).fetchone()
            else:
                row = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            findings = connection.execute("SELECT data_json FROM findings WHERE scan_id=? ORDER BY file,line,rule_id", (scan_id,)).fetchall()
            value = dict(row)
            return self._from_sqlite(value, findings)

    async def list(self, limit: int = 50, user_id: str | None = None) -> list[dict]:
        if self.pool:
            async with self.pool.acquire() as connection:
                rows = await connection.fetch("SELECT * FROM scans WHERE ($2::uuid IS NULL OR created_by=$2::uuid) ORDER BY created_at DESC LIMIT $1", limit, user_id)
                return [self._from_pg(row, await connection.fetch("SELECT data FROM findings WHERE scan_id=$1::uuid ORDER BY file,line,rule_id", row["id"])) for row in rows]
        with self._sqlite() as connection:
            if user_id:
                rows = connection.execute("SELECT * FROM scans WHERE created_by=? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [self._from_sqlite(dict(row), connection.execute("SELECT data_json FROM findings WHERE scan_id=? ORDER BY file,line,rule_id", (row["id"],)).fetchall()) for row in rows]

    async def mark_verified(self, *, source_scan_id: str, finding_id: str, verified_scan_id: str, user_id: str | None, patch: str) -> None:
        patch_hash = hashlib.sha256(patch.encode("utf-8")).hexdigest()
        verified_at = datetime.now(timezone.utc).isoformat()
        if self.pool:
            async with self.pool.acquire() as connection:
                async with connection.transaction():
                    row = await connection.fetchrow("SELECT summary FROM scans WHERE id=$1::uuid AND ($2::uuid IS NULL OR created_by=$2::uuid)", source_scan_id, user_id)
                    if not row:
                        raise ValueError("Scan is not available to this user")
                    raw_summary = row["summary"]
                    summary = raw_summary if isinstance(raw_summary, dict) else json.loads(raw_summary)
                    finding = next((item for item in summary.get("findings", []) if item.get("id") == finding_id), None)
                    if not finding:
                        raise ValueError("Finding was not found")
                    finding.update({"verified": True, "verified_at": verified_at, "verified_scan_id": verified_scan_id})
                    await connection.execute("UPDATE scans SET summary=$2::jsonb WHERE id=$1::uuid", source_scan_id, json.dumps(summary))
                    await connection.execute("UPDATE findings SET verified=TRUE,verified_scan_id=$3::uuid,data=$4::jsonb WHERE scan_id=$1::uuid AND id=$2", source_scan_id, f"{source_scan_id}:{finding_id}", verified_scan_id, json.dumps(finding))
                    await connection.execute("""INSERT INTO verified_fixes(source_scan_id,finding_id,verified_scan_id,created_by,patch_hash)
                        VALUES($1::uuid,$2,$3::uuid,$4::uuid,$5) ON CONFLICT(source_scan_id,finding_id) DO UPDATE
                        SET verified_scan_id=EXCLUDED.verified_scan_id,created_by=EXCLUDED.created_by,patch_hash=EXCLUDED.patch_hash,created_at=NOW()""",
                        source_scan_id, finding_id, verified_scan_id, user_id, patch_hash)
        else:
            with self._sqlite() as connection:
                row = connection.execute("SELECT summary_json FROM scans WHERE id=? AND (? IS NULL OR created_by=?)", (source_scan_id, user_id, user_id)).fetchone()
                if not row:
                    raise ValueError("Scan is not available to this user")
                summary = json.loads(row["summary_json"])
                finding = next((item for item in summary.get("findings", []) if item.get("id") == finding_id), None)
                if not finding:
                    raise ValueError("Finding was not found")
                finding.update({"verified": True, "verified_at": verified_at, "verified_scan_id": verified_scan_id})
                connection.execute("UPDATE scans SET summary_json=? WHERE id=?", (json.dumps(summary), source_scan_id))
                connection.execute("UPDATE findings SET verified=1,verified_scan_id=?,data_json=? WHERE scan_id=? AND id=?", (verified_scan_id, json.dumps(finding), source_scan_id, f"{source_scan_id}:{finding_id}"))
                connection.execute("""INSERT INTO verified_fixes(source_scan_id,finding_id,verified_scan_id,created_by,patch_hash)
                    VALUES(?,?,?,?,?) ON CONFLICT(source_scan_id,finding_id) DO UPDATE SET verified_scan_id=excluded.verified_scan_id,
                    created_by=excluded.created_by,patch_hash=excluded.patch_hash,created_at=CURRENT_TIMESTAMP""",
                    (source_scan_id, finding_id, verified_scan_id, user_id, patch_hash))

    async def verified_patch_hash(self, *, source_scan_id: str, finding_id: str, user_id: str | None) -> str | None:
        if self.pool:
            async with self.pool.acquire() as connection:
                row = await connection.fetchrow(
                    "SELECT patch_hash FROM verified_fixes WHERE source_scan_id=$1::uuid AND finding_id=$2 AND ($3::uuid IS NULL OR created_by=$3::uuid)",
                    source_scan_id, finding_id, user_id
                )
                return row["patch_hash"] if row else None
        with self._sqlite() as connection:
            row = connection.execute(
                "SELECT patch_hash FROM verified_fixes WHERE source_scan_id=? AND finding_id=? AND (? IS NULL OR created_by=?)",
                (source_scan_id, finding_id, user_id, user_id)
            ).fetchone()
            return row["patch_hash"] if row else None

    async def audit_event(self, *, user_id: str | None, event: str, outcome: str, metadata: dict) -> None:
        details = {key: metadata[key] for key in ("scan_id", "finding_id", "model", "iterations", "tier") if key in metadata}
        if self.pool:
            async with self.pool.acquire() as connection:
                await connection.execute("INSERT INTO analysis_audit(user_id,event,outcome,metadata) VALUES($1::uuid,$2,$3,$4::jsonb)", user_id, event, outcome, json.dumps(details))
        else:
            with self._sqlite() as connection:
                connection.execute("INSERT INTO analysis_audit(user_id,event,outcome,metadata_json) VALUES(?,?,?,?)", (user_id, event, outcome, json.dumps(details)))

    @staticmethod
    def _from_pg(row, findings) -> dict:
        value = dict(row)
        value["languages"] = value.pop("languages")
        if isinstance(value["languages"], str):
            value["languages"] = json.loads(value["languages"])
        summary = value.pop("summary")
        if isinstance(summary, str):
            summary = json.loads(summary)
        value.update(summary)
        value["findings"] = [item["data"] if isinstance(item["data"], dict) else json.loads(item["data"]) for item in findings]
        value["created_at"] = value["created_at"].isoformat()
        value["score"] = float(value["score"])
        return value

    @staticmethod
    def _from_sqlite(value: dict, findings) -> dict:
        value["languages"] = json.loads(value.pop("languages_json"))
        summary = json.loads(value.pop("summary_json"))
        value.update(summary)
        value["findings"] = [json.loads(item["data_json"]) for item in findings]
        value["score"] = float(value["score"])
        return value
