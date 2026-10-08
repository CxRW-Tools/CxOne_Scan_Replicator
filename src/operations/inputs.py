"""Read scan IDs from CLI, a file (.txt/.csv/.json) or stdin."""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import uuid
from dataclasses import dataclass, field

from src.model import FatalError


@dataclass
class IdReport:
    ids: list = field(default_factory=list)       # unique, valid, first-occurrence order
    given: int = 0
    invalid: list = field(default_factory=list)

    @property
    def unique(self) -> int:
        return len(self.ids)

    def summary(self) -> str:
        return f"scan IDs: given={self.given} unique={self.unique} invalid={len(self.invalid)}"


def _norm(raw: str):
    try:
        return str(uuid.UUID(str(raw).strip()))
    except (ValueError, AttributeError):
        return None


def _from_txt(text: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _from_csv(text: str) -> list:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    col = None
    for name in ("scan_id", "scanid"):
        if name in header:
            col = header.index(name)
            break
    if col is None:
        # no named column: first column; treat row 0 as data if it looks like an id
        col = 0
        data = rows if _norm(rows[0][0] if rows[0] else "") else rows[1:]
    else:
        data = rows[1:]
    return [r[col].strip() for r in data if len(r) > col and r[col].strip()]


def _from_json(text: str) -> list:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise FatalError(f"scan IDs file is not valid JSON: {e}") from e
    if not isinstance(data, list):
        raise FatalError("scan IDs JSON must be a list of IDs or of objects with id/scanId")
    out = []
    for item in data:
        if isinstance(item, dict):
            out.append(str(item.get("id") or item.get("scanId") or item.get("scan_id") or ""))
        else:
            out.append(str(item))
    return out


def read_ids_file(path: str) -> list:
    if path == "-":
        return _from_txt(sys.stdin.read())
    p = os.path.normpath(os.path.abspath(path))
    if not os.path.isfile(p):
        raise FatalError(f"scan IDs file not found: {path}")
    with open(p, encoding="utf-8-sig") as fh:
        text = fh.read()
    ext = os.path.splitext(p)[1].lower()
    if ext == ".csv":
        return _from_csv(text)
    if ext == ".json":
        return _from_json(text)
    return _from_txt(text)


def collect_ids(scan_ids: str = None, scan_ids_file: str = None) -> IdReport:
    raw = []
    if scan_ids:
        raw += [s.strip() for s in scan_ids.split(",") if s.strip()]
    if scan_ids_file:
        raw += read_ids_file(scan_ids_file)
    rep = IdReport(given=len(raw))
    seen = set()
    for r in raw:
        n = _norm(r)
        if n is None:
            rep.invalid.append(r)
        elif n not in seen:
            seen.add(n)
            rep.ids.append(n)
    return rep
