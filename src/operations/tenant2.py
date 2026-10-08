"""Target tenant side: projects, upload, scan start, queue depth, de-dup index."""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Optional

import requests

from src.model import E, FatalError, JobFailure
from src.utils import scan_types as st

JSON_V1 = {"Content-Type": "application/json; version=1.0"}
TAG_FROM_SCAN = "cx-replicated-from-scan"
TAG_FROM_TENANT = "cx-replicated-from-tenant"
TAG_FROM_PROJECT = "cx-replicated-from-project"
TAG_TYPES = "cx-replicated-scan-types"
TAG_AT = "cx-replicated-at"


class ScanStartAmbiguous(Exception):
    """The POST may or may not have created the scan (timeout / 5xx / connection error)."""


class ScanStartRejected(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body

    @property
    def mentions_apisec(self) -> bool:
        return "apisec" in self.body.lower()


def _id_from_response(r) -> str:
    try:
        body = r.json()
        if isinstance(body, dict) and body.get("id"):
            return str(body["id"])
    except ValueError:
        pass
    loc = r.headers.get("Location") or ""
    m = re.search(r"([0-9a-fA-F-]{8,})/?$", loc)
    return m.group(1) if m else ""


class Tenant2:
    def __init__(self, client, config: tuple, *, sleep=time.sleep, sast_value: Optional[dict] = None):
        """config: fixed engine tuple for the whole run; empty => derive from each job's scan_types."""
        self.client = client
        self.config = config
        self.sast_value = sast_value
        self.sleep = sleep
        self._proj_cache: dict = {}
        self._proj_locks: dict = {}
        self._guard = threading.Lock()

    # ---------------------------------------------------------------- projects
    def find_project(self, name: str) -> Optional[str]:
        r = self.client.request("GET", "/api/projects", params={"names": name, "limit": 2})
        if r.status_code != 200:
            raise JobFailure(E.PROJECT_FAILED, f"project lookup failed: HTTP {r.status_code}")
        for p in r.json().get("projects") or []:
            if p.get("name") == name:          # exact, case-sensitive
                return str(p["id"])
        return None

    def _create_project(self, name: str):
        """-> (project_id, created_by_us)"""
        r = self.client.request("POST", "/api/projects", data=json.dumps({"name": name}),
                                headers=JSON_V1, retry="post")
        if r.status_code in (200, 201):
            pid = _id_from_response(r)
            if pid:
                return pid, True
            return self.find_project(name), True
        if r.status_code in (400, 409):
            existing = self.find_project(name)       # lost a race with another process
            if existing:
                return existing, False
        raise JobFailure(E.PROJECT_FAILED, f"project create failed: HTTP {r.status_code} {r.text[:200]}")

    def resolve_project(self, name: str, create: bool = True):
        """-> (project_id|None, created). Cached; one creator per name."""
        with self._guard:
            if name in self._proj_cache:
                return self._proj_cache[name], False
            lock = self._proj_locks.setdefault(name, threading.Lock())
        with lock:
            with self._guard:
                if name in self._proj_cache:
                    return self._proj_cache[name], False
            pid = self.find_project(name)
            created = False
            if pid is None:
                if not create:
                    return None, False
                try:
                    pid, created = self._create_project(name)
                except requests.RequestException as e:
                    # ambiguous create: look again before giving up
                    pid = self.find_project(name)
                    if pid is None:
                        raise JobFailure(E.PROJECT_FAILED, f"project create failed: {type(e).__name__}") from e
            with self._guard:
                self._proj_cache[name] = pid
            return pid, created

    # ---------------------------------------------------------------- upload
    def _new_upload_url(self) -> str:
        r = self.client.request("POST", "/api/uploads", data="{}", headers=JSON_V1, retry="post")
        if r.status_code not in (200, 201):
            raise JobFailure(E.UPLOAD_FAILED, f"could not get upload URL: HTTP {r.status_code}")
        url = (r.json() or {}).get("url")
        if not url:
            raise JobFailure(E.UPLOAD_FAILED, "upload URL missing in response")
        return url

    def upload(self, payload, multipart_threshold: int = 0, attempts: int = 3) -> str:
        """Upload the zip; returns the URL to hand to the scan. New upload URL on every retry."""
        last = ""
        for n in range(1, attempts + 1):
            try:
                if multipart_threshold and payload.size > multipart_threshold:
                    return self._multipart(payload, multipart_threshold)
                url = self._new_upload_url()
                with payload.open() as fh:
                    r = self.client.request("PUT", url, data=fh, retry="none", transfer=True,
                                            headers={"Content-Type": "application/zip"})
                if r.status_code in (200, 201, 204):
                    return url
                last = f"HTTP {r.status_code}"
            except requests.RequestException as e:
                last = type(e).__name__
            except JobFailure as e:
                last = e.message
            if n < attempts:
                self.sleep(2 ** (n - 1))
        raise JobFailure(E.UPLOAD_FAILED, f"upload failed after {attempts} attempts: {last}")

    def _multipart(self, payload, part_size: int) -> str:
        """Experimental: see README checklist item 4 (completion response shape is unverified)."""
        c = self.client
        r = c.request("POST", "/api/uploads/start-multipart-upload",
                      data=json.dumps({"fileSize": payload.size}), headers=JSON_V1, retry="post")
        if r.status_code not in (200, 201):
            raise JobFailure(E.UPLOAD_FAILED, f"multipart start failed: HTTP {r.status_code}")
        info = r.json()
        obj, upload_id = info.get("objectName"), info.get("uploadID")
        try:
            parts = []
            with payload.open() as fh:
                num = 0
                while True:
                    chunk = fh.read(part_size)
                    if not chunk:
                        break
                    num += 1
                    pr = c.request("POST", "/api/uploads/multipart-presigned", headers=JSON_V1,
                                   data=json.dumps({"objectName": obj, "uploadID": upload_id,
                                                    "partNumber": num}), retry="post")
                    purl = (pr.json() or {}).get("presignedURL")
                    if pr.status_code not in (200, 201) or not purl:
                        raise JobFailure(E.UPLOAD_FAILED, f"multipart presign failed: HTTP {pr.status_code}")
                    put = c.request("PUT", purl, data=chunk, retry="none", transfer=True)
                    if put.status_code not in (200, 201, 204):
                        raise JobFailure(E.UPLOAD_FAILED, f"multipart part {num}: HTTP {put.status_code}")
                    parts.append({"partNumber": num, "eTag": put.headers.get("ETag", "")})
            done = c.request("POST", "/api/uploads/complete-multipart-upload", headers=JSON_V1,
                             data=json.dumps({"objectName": obj, "uploadID": upload_id, "partList": parts}),
                             retry="post")
            if done.status_code not in (200, 201):
                raise JobFailure(E.UPLOAD_FAILED, f"multipart complete failed: HTTP {done.status_code}")
            body = done.json() if done.content else {}
            url = (body or {}).get("url") or (body or {}).get("uploadUrl") or (body or {}).get("location")
            if not url:
                raise JobFailure(E.UPLOAD_FAILED, "multipart completion response had no URL "
                                                  "(shape unverified; use single PUT)")
            return url
        except (JobFailure, requests.RequestException):
            try:
                c.request("POST", "/api/uploads/abort-multipart-upload", headers=JSON_V1, retry="none",
                          data=json.dumps({"objectName": obj, "uploadID": upload_id}))
            except requests.RequestException:
                pass
            raise

    # ---------------------------------------------------------------- scan start
    def build_body(self, job, upload_url: str, tags: dict) -> dict:
        handler = {"uploadUrl": upload_url}
        if job.branch:
            handler["branch"] = job.branch
        config = self.config or st.build_config(job.scan_types, self.sast_value)
        return {"type": "upload", "handler": handler, "project": {"id": job.t2_project_id},
                "config": st.config_payload(config), "tags": tags}

    def start_scan(self, body: dict) -> str:
        """POST /api/scans. Only 429 is retried inside the client; ambiguity is surfaced."""
        try:
            r = self.client.request("POST", "/api/scans", data=json.dumps(body), headers=JSON_V1,
                                    retry="post")
        except requests.RequestException as e:
            raise ScanStartAmbiguous(type(e).__name__) from e
        if r.status_code in (200, 201):
            sid = _id_from_response(r)
            if not sid:
                raise ScanStartAmbiguous("scan created but no id in response")
            return sid
        if r.status_code >= 500 or r.status_code == 429:
            raise ScanStartAmbiguous(f"HTTP {r.status_code}")
        raise ScanStartRejected(r.status_code, r.text or "")

    def confirm_started(self, project_id: str, source_scan_id: str) -> Optional[str]:
        """Is there already a Target tenant scan tagged with this source scan id?"""
        r = self.client.request("GET", "/api/scans", params=[
            ("project-id", project_id), ("tags-keys", TAG_FROM_SCAN), ("tags-values", source_scan_id),
            ("sort", "-created_at"), ("limit", 5)])
        if r.status_code != 200:
            return None
        for s in r.json().get("scans") or []:
            if (s.get("tags") or {}).get(TAG_FROM_SCAN) == source_scan_id:   # verify client-side
                return str(s["id"])
        return None

    # ---------------------------------------------------------------- queue / dedupe / verify
    def queue_depth(self, count_running: bool = False) -> int:
        try:
            r = self.client.request("GET", "/api/scans/summary")
            if r.status_code == 200:
                status = {str(k).lower(): v for k, v in ((r.json() or {}).get("status") or {}).items()}
                if "queued" in status:
                    n = int(status.get("queued") or 0)
                    if count_running:
                        n += int(status.get("running") or 0)
                    return n
        except (requests.RequestException, ValueError, TypeError):
            pass
        wanted = ["Queued"] + (["Running"] if count_running else [])
        total = 0
        for status in wanted:
            offset = 0
            while True:
                r = self.client.request("GET", "/api/scans", params={"statuses": status, "limit": 500,
                                                                     "offset": offset})
                if r.status_code != 200:
                    raise JobFailure(E.UNEXPECTED, f"queue check failed: HTTP {r.status_code}")
                rows = r.json().get("scans") or []
                total += len(rows)
                if len(rows) < 500:
                    break
                offset += len(rows)
        return total

    def dedupe_index(self, t1_tenants: Optional[set] = None) -> dict:
        """{(t1_tenant, source_scan_id): (t2_scan_id, scan_types_tag)} from Target tenant scan tags."""
        out, offset = {}, 0
        while True:
            r = self.client.request("GET", "/api/scans", params={
                "tags-keys": TAG_FROM_SCAN, "limit": 500, "offset": offset})
            if r.status_code != 200:
                raise FatalError(f"Target tenant de-dup query failed: HTTP {r.status_code} (needs view-scans)")
            rows = r.json().get("scans") or []
            for s in rows:
                tags = s.get("tags") or {}
                src, ten = tags.get(TAG_FROM_SCAN), tags.get(TAG_FROM_TENANT)
                if src and ten and (t1_tenants is None or ten in t1_tenants):
                    out[(ten, src)] = (str(s.get("id")), tags.get(TAG_TYPES, ""))
            if len(rows) < 500:     # never trust totalCount under filters
                break
            offset += len(rows)
        return out

    def scan_engines(self, ids: list) -> dict:
        params = [("scan-ids", i) for i in ids] + [("limit", len(ids))]
        r = self.client.request("GET", "/api/scans", params=params)
        if r.status_code != 200:
            return {}
        return {str(s["id"]): [str(e).lower() for e in (s.get("engines") or [])]
                for s in r.json().get("scans") or []}

    def tenant_sast_defaults(self) -> dict:
        r = self.client.request("GET", "/api/configuration/tenant")
        if r.status_code != 200:
            raise FatalError(f"--force-tenant-defaults: could not read tenant configuration: HTTP {r.status_code}")
        vals = {c.get("key"): c.get("value") for c in r.json() if isinstance(c, dict)}
        out = {}
        if vals.get("scan.config.sast.presetName"):
            out["presetName"] = vals["scan.config.sast.presetName"]
        if vals.get("scan.config.sast.incremental") is not None:
            out["incremental"] = str(vals["scan.config.sast.incremental"]).lower()
        return out
