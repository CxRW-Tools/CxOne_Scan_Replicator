"""sqlite3 state DB: resume + de-dup. All access serialized through one lock."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

JOB_COLS = ["mode", "source_scan_id", "t1_project_id", "project_name", "branch", "source_created_at",
            "scan_types", "status", "error_code", "error_message", "attempts", "zip_bytes",
            "zip_sha256", "zip_path", "t2_project_id", "t2_project_created", "t2_scan_id",
            "started_at", "updated_at"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  mode TEXT NOT NULL, source_scan_id TEXT NOT NULL, t1_project_id TEXT, project_name TEXT,
  branch TEXT, source_created_at TEXT, scan_types TEXT, status TEXT, error_code TEXT,
  error_message TEXT, attempts INTEGER DEFAULT 0, zip_bytes INTEGER, zip_sha256 TEXT,
  zip_path TEXT, t2_project_id TEXT, t2_project_created INTEGER, t2_scan_id TEXT,
  started_at TEXT, updated_at TEXT, PRIMARY KEY (mode, source_scan_id));
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, mode TEXT, scan_types TEXT, started_at TEXT, finished_at TEXT,
  args_json TEXT, env_files TEXT, t1_tenant TEXT, t2_tenant TEXT, counts_json TEXT);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StateDB:
    def __init__(self, path: str, readonly: bool = False):
        """readonly (dry-run): never creates or modifies the file; a missing file reads as empty."""
        self.path = path
        self._lock = threading.Lock()
        if readonly:
            import os
            from pathlib import Path
            if path != ":memory:" and os.path.isfile(path):
                self._db = sqlite3.connect(Path(os.path.abspath(path)).as_uri() + "?mode=ro", uri=True,
                                           check_same_thread=False, timeout=30)
            else:
                self._db = sqlite3.connect(":memory:", check_same_thread=False)
                self._db.executescript(SCHEMA)
            self._db.row_factory = sqlite3.Row
            return
        self._db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.execute("PRAGMA synchronous=NORMAL")   # WAL: safe across process crashes
            self._db.executescript(SCHEMA)
            self._db.commit()

    def close(self):
        with self._lock:
            self._db.close()

    # -- jobs
    def get(self, mode: str, sid: str) -> Optional[dict]:
        with self._lock:
            row = self._db.execute("SELECT * FROM jobs WHERE mode=? AND source_scan_id=?",
                                   (mode, sid)).fetchone()
        return dict(row) if row else None

    def upsert(self, mode: str, sid: str, **fields):
        fields = {k: v for k, v in fields.items() if k in JOB_COLS and k not in ("mode", "source_scan_id")}
        if "scan_types" in fields and isinstance(fields["scan_types"], (list, tuple)):
            fields["scan_types"] = ",".join(fields["scan_types"])
        if "t2_project_created" in fields and fields["t2_project_created"] is not None:
            fields["t2_project_created"] = int(bool(fields["t2_project_created"]))
        fields["updated_at"] = now_iso()
        cols = ["mode", "source_scan_id"] + list(fields)
        vals = [mode, sid] + list(fields.values())
        sets = ", ".join(f"{c}=excluded.{c}" for c in fields)
        sql = (f"INSERT INTO jobs ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
               f"ON CONFLICT(mode, source_scan_id) DO UPDATE SET {sets}")
        with self._lock:
            self._db.execute(sql, vals)
            self._db.commit()

    def count_by_status(self, mode: str) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT status, COUNT(*) c FROM jobs WHERE mode=? GROUP BY status",
                                    (mode,)).fetchall()
        return {r["status"]: r["c"] for r in rows}

    # -- runs
    def start_run(self, run_id, mode, scan_types, args_json, env_files, t1_tenant, t2_tenant):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO runs (run_id, mode, scan_types, started_at, args_json, env_files,"
                " t1_tenant, t2_tenant) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, mode, ",".join(scan_types or []), now_iso(), json.dumps(args_json, default=str),
                 json.dumps(env_files), t1_tenant, t2_tenant))
            self._db.commit()

    def finish_run(self, run_id, counts: dict):
        with self._lock:
            self._db.execute("UPDATE runs SET finished_at=?, counts_json=? WHERE run_id=?",
                             (now_iso(), json.dumps(counts), run_id))
            self._db.commit()
