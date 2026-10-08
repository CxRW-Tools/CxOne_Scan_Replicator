"""Source tenant side: metadata, source availability and streamed download."""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import requests

from src.model import E, FatalError, JobFailure
from src.utils.http import REDIRECTS

CHUNK = 1 << 20
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")


def _p(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def remove_file(path: Optional[str]):
    """Delete a file if it exists; never raises."""
    if not path:
        return
    target = os.path.normpath(os.path.abspath(path))
    try:
        if os.path.isfile(target):
            os.remove(target)
    except OSError:
        pass


# --------------------------------------------------------------------------- metadata
def fetch_metadata(client, ids: list, batch: int = 50, workers: int = 4) -> dict:
    """GET /api/scans?scan-ids=...&limit=50 in batches -> {id: scan dict}."""
    batch = max(1, min(batch, 50))
    chunks = [ids[i:i + batch] for i in range(0, len(ids), batch)]

    def one(chunk):
        params = [("scan-ids", i) for i in chunk] + [("limit", len(chunk))]
        r = client.request("GET", "/api/scans", params=params)
        if r.status_code != 200:
            raise FatalError(f"Source tenant metadata request failed: HTTP {r.status_code} "
                             f"(needs view-scans permission)")
        return r.json().get("scans") or []

    out = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(chunks) or 1))) as ex:
        for scans in ex.map(one, chunks):
            for s in scans:
                if s.get("id"):
                    out[str(s["id"]).lower()] = s
    return out


def head_source(client, scan_id: str):
    """-> (http_status, content_length|None). Raises JobFailure on 404/401/403."""
    try:
        r = client.request("HEAD", f"/api/repostore/scans/{scan_id}")
    except requests.RequestException:
        # availability probe is best-effort; the download surfaces real problems
        return None, None
    if r.status_code in (404, 410):
        raise JobFailure(E.SOURCE_UNAVAILABLE, "source archive no longer available in Source tenant")
    if r.status_code in (401, 403):
        raise JobFailure(E.NO_SOURCE_PERMISSION, f"HTTP {r.status_code} on source availability check")
    length = None
    cl = r.headers.get("Content-Length")
    if r.status_code < 300 and cl and cl.isdigit():
        length = int(cl)
    return r.status_code, length


# --------------------------------------------------------------------------- memory budget / payloads
class MemoryBudget:
    """Byte-counting budget for in-memory zips; try_acquire never blocks (callers spill to disk)."""

    def __init__(self, capacity_bytes: int):
        self.capacity = capacity_bytes
        self.in_use = 0
        self.peak = 0
        self._lock = threading.Lock()

    def try_acquire(self, n: int) -> bool:
        with self._lock:
            if self.in_use + n > self.capacity:
                return False
            self.in_use += n
            self.peak = max(self.peak, self.in_use)
            return True

    def release(self, n: int):
        with self._lock:
            self.in_use = max(0, self.in_use - n)


class Payload:
    """A downloaded (or manifest-supplied) zip: in memory, in a temp file, or an existing file."""

    def __init__(self, size: int, sha256: str, *, buf: Optional[io.BytesIO] = None,
                 path: Optional[str] = None, delete_path: bool = False,
                 budget: Optional[MemoryBudget] = None):
        self.size = size
        self.sha256 = sha256
        self.buf = buf
        self.path = path
        self.delete_path = delete_path
        self.budget = budget
        self._released = False

    @property
    def in_memory(self) -> bool:
        return self.buf is not None

    @contextlib.contextmanager
    def open(self):
        if self.buf is not None:
            self.buf.seek(0)
            yield self.buf
        else:
            with open(_p(self.path), "rb") as fh:
                yield fh

    def release(self):
        """Free memory budget / delete temp file. Never deletes a pre-existing (manifest) zip."""
        if self._released:
            return
        self._released = True
        if self.buf is not None:
            if self.budget:
                self.budget.release(self.size)
            self.buf = None
        if self.delete_path:
            remove_file(self.path)


class SpoolSink:
    """Memory first (budget permitting), spilling to a 0600 temp file."""

    def __init__(self, budget: MemoryBudget, mem_max: int, temp_dir: Optional[str]):
        self.budget, self.mem_max, self.temp_dir = budget, mem_max, temp_dir
        self.buf: Optional[io.BytesIO] = io.BytesIO()
        self.mem_len = 0
        self.fh = None
        self.path: Optional[str] = None

    def hint_length(self, n: Optional[int]):
        if n and n > self.mem_max and self.fh is None:
            self._spill()

    def _spill(self):
        fd, self.path = tempfile.mkstemp(prefix="cxrep-", suffix=".zip", dir=self.temp_dir)
        self.fh = os.fdopen(fd, "wb")
        if self.buf is not None:
            self.fh.write(self.buf.getvalue())
            self.budget.release(self.mem_len)
            self.buf = None
            self.mem_len = 0

    def write(self, chunk: bytes):
        if self.fh is None:
            if self.mem_len + len(chunk) <= self.mem_max and self.budget.try_acquire(len(chunk)):
                self.buf.write(chunk)
                self.mem_len += len(chunk)
                return
            self._spill()
        self.fh.write(chunk)

    def finish(self, size: int, sha: str) -> Payload:
        if self.fh is not None:
            self.fh.flush()
            self.fh.close()
            return Payload(size, sha, path=self.path, delete_path=True)
        return Payload(size, sha, buf=self.buf, budget=self.budget)

    def abort(self):
        if self.fh is not None:
            with contextlib.suppress(OSError):
                self.fh.close()
        remove_file(self.path)
        if self.buf is not None:
            self.budget.release(self.mem_len)
            self.buf = None


class FileSink:
    """Atomic: write <final>.part, fsync, os.replace."""

    def __init__(self, final_path: str):
        self.final = _p(final_path)
        self.part = self.final + ".part"
        os.makedirs(os.path.dirname(self.final), exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        self.fd = os.open(self.part, flags, 0o600)
        os.chmod(self.part, 0o600)
        self._open = True

    def hint_length(self, n):
        pass

    def write(self, chunk: bytes):
        view = memoryview(chunk)
        while view:
            n = os.write(self.fd, view)
            view = view[n:]

    def _close(self):
        if self._open:
            self._open = False
            os.close(self.fd)

    def finish(self, size: int, sha: str) -> Payload:
        os.fsync(self.fd)
        self._close()
        os.replace(self.part, self.final)
        return Payload(size, sha, path=self.final, delete_path=False)

    def abort(self):
        with contextlib.suppress(OSError):
            self._close()
        remove_file(self.part)


class NullSink:
    """--no-save-zips: hash and discard."""

    def hint_length(self, n):
        pass

    def write(self, chunk: bytes):
        pass

    def finish(self, size: int, sha: str) -> Payload:
        return Payload(size, sha)

    def abort(self):
        pass


# --------------------------------------------------------------------------- download
class _Transient(Exception):
    pass


@contextlib.contextmanager
def open_source_stream(client, scan_id: str, max_hops: int = 5):
    """GET repostore/code/{id} following redirects by hand.

    The bearer token is only sent when the (redirect) host is the tenant's own host.
    """
    url = client.absolute(f"/api/repostore/code/{scan_id}")
    for _ in range(max_hops):
        with client.stream("GET", url, allow_redirects=False, transfer=True) as r:
            loc = r.headers.get("Location")
            if r.status_code in REDIRECTS and loc:
                url = client.absolute(loc, base=url)
                continue
            yield r
            return
    raise JobFailure(E.DOWNLOAD_FAILED, "too many redirects fetching source")


def verify_zip_payload(payload: Payload):
    try:
        with payload.open() as fh:
            with zipfile.ZipFile(fh) as zf:
                bad = zf.testzip()
        if bad is not None:
            raise JobFailure(E.BAD_ZIP, f"corrupt member in zip: {bad}")
    except zipfile.BadZipFile as e:
        raise JobFailure(E.BAD_ZIP, f"not a valid zip: {e}") from e


def download_source(client, scan_id: str, make_sink: Callable, *, max_bytes: int = 0,
                    verify: bool = False, progress: Optional[Callable[[int, Optional[int]], None]] = None,
                    retries: int = 4, sleep=time.sleep) -> Payload:
    """Stream the source zip into a sink; retry transient errors with a fresh redirect each time."""
    last = "unknown error"
    for attempt in range(1, retries + 1):
        sink = make_sink()
        h = hashlib.sha256()
        size = 0
        head = b""
        try:
            with open_source_stream(client, scan_id) as r:
                code = r.status_code
                if code in (404, 410):
                    raise JobFailure(E.SOURCE_UNAVAILABLE, f"HTTP {code} fetching source")
                if code in (401, 403):
                    raise JobFailure(E.NO_SOURCE_PERMISSION, f"HTTP {code} fetching source")
                if code == 429 or code >= 500:
                    raise _Transient(f"HTTP {code}")
                if code != 200:
                    raise JobFailure(E.DOWNLOAD_FAILED, f"unexpected HTTP {code} fetching source")
                cl = r.headers.get("Content-Length")
                clen = int(cl) if cl and cl.isdigit() else None
                if max_bytes and clen and clen > max_bytes:
                    raise JobFailure(E.TOO_LARGE, f"zip is {clen} bytes (limit {max_bytes})")
                sink.hint_length(clen)
                if progress:
                    progress(0, clen)
                for chunk in r.iter_content(CHUNK):
                    if not chunk:
                        continue
                    if len(head) < 4:
                        head = (head + chunk)[:4]
                    h.update(chunk)
                    size += len(chunk)
                    if max_bytes and size > max_bytes:
                        raise JobFailure(E.TOO_LARGE, f"zip exceeds {max_bytes} bytes")
                    sink.write(chunk)
                    if progress:
                        progress(len(chunk), clen)
                if clen is not None and size != clen:
                    raise _Transient(f"truncated download ({size} of {clen} bytes)")
            if head not in ZIP_SIGNATURES:
                raise JobFailure(E.BAD_ZIP, "downloaded data does not start with a zip signature")
            payload = sink.finish(size, h.hexdigest())
            if verify and (payload.buf is not None or payload.path):
                try:
                    verify_zip_payload(payload)
                except JobFailure:
                    payload.release()
                    if payload.path and not payload.delete_path:
                        remove_file(payload.path)   # don't leave a corrupt "final" zip behind
                    raise
            return payload
        except (_Transient, requests.RequestException) as e:
            sink.abort()
            last = type(e).__name__ if isinstance(e, requests.RequestException) else str(e)
            if progress:
                progress(-size, None)  # roll back counted bytes
            if attempt < retries:
                sleep(min(2 ** (attempt - 1), 8))
                continue
        except BaseException:
            sink.abort()
            raise
    raise JobFailure(E.DOWNLOAD_FAILED, f"download failed after {retries} attempts: {last}")
