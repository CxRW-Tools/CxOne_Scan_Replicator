"""Download manifest (CSV + JSONL) writer/reader, plus zip path layout/sanitizing."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import threading

MANIFEST_VERSION = 1
FIELDS = ["manifest_version", "source_scan_id", "t1_tenant", "t1_base_url", "t1_project_id",
          "project_name", "branch", "source_status", "source_created_at", "source_engines", "tags",
          "status", "error_code", "error_message", "zip_path", "zip_bytes", "zip_sha256",
          "downloaded_at", "tool_version", "run_id"]

_BAD = re.compile(r'[/\\:*?"<>|\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def _p(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def sanitize_segment(name: str, max_len: int = 120) -> str:
    """Filesystem-safe segment; appends an 8-char hash of the original when it was altered."""
    original = name
    s = _BAD.sub("_", name or "").rstrip(" .")
    if not s:
        s = "_"
    if s.split(".")[0].upper() in _RESERVED:
        s = "_" + s
    changed = s != original or len(s) > max_len
    if changed:
        h = hashlib.sha256(original.encode("utf-8", "replace")).hexdigest()[:8]
        s = s[:max_len - 9].rstrip(" .") + "_" + h
    return s


def zip_relpath(scan_id: str, project: str, branch: str, layout: str) -> str:
    if layout == "by-project":
        return "/".join([sanitize_segment(project), sanitize_segment(branch or "_no-branch"),
                         f"{scan_id}.zip"])
    return f"{scan_id}.zip"


def _flat(row: dict) -> dict:
    flat = dict(row)
    flat["tags"] = json.dumps(row.get("tags") or {}, ensure_ascii=False)
    flat["source_engines"] = json.dumps(row.get("source_engines") or [])
    return flat


class ManifestWriter:
    """Appends rows to manifest.jsonl and manifest.csv; each append opens, writes, closes."""

    def __init__(self, out_dir: str):
        self.dir = _p(out_dir)
        self.jsonl = os.path.join(self.dir, "manifest.jsonl")
        self.csv = os.path.join(self.dir, "manifest.csv")
        self._lock = threading.Lock()

    def append(self, row: dict):
        row = {"manifest_version": MANIFEST_VERSION, **row}
        with self._lock:
            with open(_p(self.jsonl), "a", encoding="utf-8") as jf:
                jf.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            new_csv = not os.path.exists(self.csv) or os.path.getsize(self.csv) == 0
            with open(_p(self.csv), "a", encoding="utf-8", newline="") as cf:
                w = csv.DictWriter(cf, fieldnames=FIELDS, extrasaction="ignore")
                if new_csv:
                    w.writeheader()
                w.writerow(_flat(row))

    def close(self):
        pass


def read_manifest(out_dir: str) -> dict:
    """{source_scan_id: row}; the last row per ID wins."""
    path = os.path.join(_p(out_dir), "manifest.jsonl")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"manifest not found: {path}")
    rows = {}
    with open(_p(path), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue  # torn final line after a crash
            if r.get("source_scan_id"):
                rows[r["source_scan_id"]] = r
    return rows


def compact_manifest(out_dir: str) -> int:
    """Rewrite manifest.jsonl / manifest.csv with exactly one row per scan ID."""
    out_dir = _p(out_dir)
    rows = read_manifest(out_dir)
    for name in ("manifest.jsonl", "manifest.csv"):
        p = os.path.join(out_dir, name)
        if os.path.exists(p):
            os.remove(p)
    w = ManifestWriter(out_dir)
    for r in rows.values():
        w.append(r)
    return len(rows)


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(_p(path), "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def safe_join(base: str, rel: str) -> str:
    """Join a manifest-supplied relative path under base; refuses escapes."""
    base = _p(base)
    full = _p(os.path.join(base, rel))
    if os.path.commonpath([base, full]) != base:
        raise ValueError(f"path escapes output dir: {rel}")
    return full
