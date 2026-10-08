"""Fake HTTP layer for both tenants (no network)."""
from __future__ import annotations

import base64
import io
import json
import random
import threading
import uuid
import zipfile
from urllib.parse import parse_qsl, urlparse

import requests
from requests.structures import CaseInsensitiveDict

T1_HOST, T2_HOST = "t1.example.com", "t2.example.com"
T1_IAM, T2_IAM = "iam.t1.example.com", "iam.t2.example.com"
UPLOAD_HOST = "upload.t2.example.com"
S3_HOST = "s3.t1-archive.example.net"


def make_zip(tag="x", size=0) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("a.txt", tag * 10)
        if size:
            z.writestr("pad.bin", b"0" * size)
    return bio.getvalue()


def make_jwt(tenant, iam_host, base_host):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return ".".join([b64({"alg": "none"}),
                     b64({"iss": f"https://{iam_host}/auth/realms/{tenant}",
                          "ast-base-url": f"https://{base_host}"}), "sig"])


class FakeResp:
    def __init__(self, status=200, json_data=None, content=b"", headers=None, url=""):
        self.status_code = status
        self._json = json_data
        self.content = json.dumps(json_data).encode() if json_data is not None else content
        self.headers = CaseInsensitiveDict(headers or {})
        self.url = url
        self.closed = False

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def iter_content(self, n):
        for i in range(0, len(self.content), n):
            yield self.content[i:i + n]

    def close(self):
        self.closed = True


class FakeWorld:
    def __init__(self, seed=1):
        self.lock = threading.RLock()
        self.rng = random.Random(seed)
        self.requests = []          # (method, host, path, authorization_sent)
        self.tokens = {"t1": set(), "t2": set()}
        self.tok_n = 0
        # tenant1
        self.t1_scans = {}          # id -> meta
        self.t1_sources = {}        # id -> bytes | None
        self.t1_redirect_host = None    # set to S3_HOST for foreign-host redirect tests
        # tenant2
        self.projects = {}          # name -> id
        self.t2_scans = []          # dicts
        self.uploads = {}           # url -> bytes
        self.scan_bodies = []
        self.queued = 0             # int or callable
        self.summary_ok = True
        # failure injection (rates 0..1)
        self.dl_5xx_rate = 0.0
        self.put_fail_rate = 0.0
        self.start_5xx_rate = 0.0       # ambiguous: scan IS created, response is 500
        self.start_timeout_rate = 0.0   # ambiguous: scan NOT created, timeout
        self.start_400_apisec = False
        self.project_race = False
        self.rate_limit_next = 0        # next N T2 GETs answer 429
        self.expire_tokens_once = False
        self.upload_n = 0
        self.hook = None

    # ----------------------------------------------------------- scenario helpers
    def add_scan(self, project="proj", branch="main", created=None, source=True, tags=None, status="Completed",
                 engines=("sast", "sca")):
        sid = str(uuid.UUID(int=self.rng.getrandbits(128), version=4))
        created = created or f"2024-01-01T00:{len(self.t1_scans) // 60 % 60:02d}:{len(self.t1_scans) % 60:02d}Z"
        self.t1_scans[sid] = {"id": sid, "projectId": "p-" + project, "projectName": project, "branch": branch,
                              "status": status, "createdAt": created, "tags": tags or {},
                              "engines": list(engines), "sourceType": "zip"}
        self.t1_sources[sid] = make_zip(sid[:8]) if source is True else source
        return sid

    def calls(self, host):
        return [r for r in self.requests if r[1] == host]

    def queue_depth(self):
        return self.queued() if callable(self.queued) else self.queued

    # ----------------------------------------------------------- session surface
    def post(self, url, data=None, timeout=None, headers=None):      # AuthManager(http=...)
        return self.request("POST", url, data=data, headers=headers)

    def request(self, method, url, headers=None, stream=False, allow_redirects=True, timeout=None,
                params=None, data=None, json=None, **kw):
        u = urlparse(url)
        headers = headers or {}
        path = u.path
        q = list(parse_qsl(u.query))
        if params:
            q += list(params.items()) if isinstance(params, dict) else list(params)
        auth = headers.get("Authorization")
        with self.lock:
            self.requests.append((method, u.netloc, path, auth))
        if self.hook:
            self.hook(method, u.netloc, path)
        if u.netloc in (T1_IAM, T2_IAM):
            return self._token(u.netloc, path)
        if u.netloc == UPLOAD_HOST:
            return self._upload_put(method, url, data, auth)
        if u.netloc == S3_HOST:
            return self._s3(path, auth)
        which = "t1" if u.netloc == T1_HOST else "t2" if u.netloc == T2_HOST else None
        if which is None:
            raise requests.ConnectionError(f"unknown host {u.netloc}")
        if not auth or auth.split(" ", 1)[-1] not in self.tokens[which]:
            return FakeResp(401, {"error": "unauthorized"}, url=url)
        if which == "t1":
            return self._t1(method, path, q, url)
        return self._t2(method, path, q, data if data is not None else json, url)

    # ----------------------------------------------------------- auth
    def _token(self, host, path):
        which = "t1" if host == T1_IAM else "t2"
        with self.lock:
            self.tok_n += 1
            tok = f"tok-{which}-{self.tok_n}"
            self.tokens[which].add(tok)
        return FakeResp(200, {"access_token": tok, "expires_in": 600})

    def invalidate_tokens(self, which):
        with self.lock:
            self.tokens[which] = set()

    # ----------------------------------------------------------- tenant 1
    def _t1(self, method, path, q, url):
        if path == "/api/scans":
            ids = [v for k, v in q if k == "scan-ids"]
            return FakeResp(200, {"scans": [self.t1_scans[i] for i in ids if i in self.t1_scans]})
        if path.startswith("/api/repostore/scans/"):
            sid = path.rsplit("/", 1)[-1]
            data = self.t1_sources.get(sid)
            if data is None:
                return FakeResp(404)
            return FakeResp(200, headers={"Content-Length": str(len(data))})
        if path.startswith("/api/repostore/code/"):
            sid = path.rsplit("/", 1)[-1]
            if self.t1_sources.get(sid) is None:
                return FakeResp(404)
            if self.rng.random() < self.dl_5xx_rate:
                return FakeResp(503)
            host = self.t1_redirect_host or T1_HOST
            scheme_path = f"/storage/{sid}" if host == T1_HOST else f"/bucket/{sid}"
            return FakeResp(302, headers={"Location": f"https://{host}{scheme_path}?X-Amz-Signature=SECRETSIG"})
        if path.startswith("/storage/"):
            sid = path.rsplit("/", 1)[-1]
            data = self.t1_sources.get(sid)
            if data is None:
                return FakeResp(404)
            return FakeResp(200, content=data, headers={"Content-Length": str(len(data))})
        return FakeResp(404)

    def _s3(self, path, auth):
        sid = path.rsplit("/", 1)[-1]
        data = self.t1_sources.get(sid)
        return FakeResp(200, content=data, headers={"Content-Length": str(len(data))})

    # ----------------------------------------------------------- tenant 2
    def _t2(self, method, path, q, body, url):
        if isinstance(body, (bytes, str)):
            body = json.loads(body) if body else {}
        if self.rate_limit_next > 0 and method == "GET":
            with self.lock:
                self.rate_limit_next -= 1
            return FakeResp(429, headers={"Retry-After": "0"})
        if path == "/api/projects" and method == "GET":
            names = [v for k, v in q if k == "names"]
            with self.lock:
                rows = [{"id": self.projects[n], "name": n} for n in names if n in self.projects]
            return FakeResp(200, {"projects": rows})
        if path == "/api/projects" and method == "POST":
            with self.lock:
                name = body["name"]
                if name in self.projects or self.project_race:
                    self.projects.setdefault(name, "pid-" + uuid.uuid4().hex[:8])
                    return FakeResp(409, {"message": "already exists"})
                pid = "pid-" + uuid.uuid4().hex[:8]
                self.projects[name] = pid
            return FakeResp(201, {"id": pid})
        if path == "/api/uploads" and method == "POST":
            with self.lock:
                self.upload_n += 1
                n = self.upload_n
            return FakeResp(200, {"url": f"https://{UPLOAD_HOST}/put/{n}?X-Amz-Signature=UPSECRET"})
        if path == "/api/scans/summary":
            if not self.summary_ok:
                return FakeResp(500)
            return FakeResp(200, {"status": {"Queued": self.queue_depth(), "Running": 3}})
        if path == "/api/scans" and method == "POST":
            return self._start(body)
        if path == "/api/scans" and method == "GET":
            return self._list_scans(q)
        if path == "/api/configuration/tenant":
            return FakeResp(200, [{"key": "scan.config.sast.presetName", "value": "Default"},
                                  {"key": "scan.config.sast.incremental", "value": "false"}])
        return FakeResp(404)

    def _upload_put(self, method, url, data, auth):
        if auth:
            return FakeResp(403, {"error": "token must not be sent to upload host"})
        if self.rng.random() < self.put_fail_rate:
            return FakeResp(500)
        payload = data.read() if hasattr(data, "read") else data
        with self.lock:
            self.uploads[url] = payload
        return FakeResp(200)

    def _start(self, body):
        with self.lock:
            if self.start_400_apisec and any(c["type"] == "apisec" for c in body["config"]):
                return FakeResp(400, {"message": "invalid config type apisec"})
            r = self.rng.random()
            if r < self.start_timeout_rate:
                raise requests.ReadTimeout("timeout")
            self.scan_bodies.append(body)
            sid = "t2scan-" + uuid.uuid4().hex[:10]
            self.t2_scans.append({"id": sid, "projectId": body["project"]["id"], "tags": body["tags"],
                                  "status": "Queued", "branch": body["handler"].get("branch"),
                                  "engines": [c["type"] for c in body["config"]],
                                  "uploadUrl": body["handler"]["uploadUrl"]})
            if r < self.start_timeout_rate + self.start_5xx_rate:
                return FakeResp(500)
        return FakeResp(201, {"id": sid})

    def _list_scans(self, q):
        qd = {}
        for k, v in q:
            qd.setdefault(k, []).append(v)
        with self.lock:
            rows = list(self.t2_scans)
        if "tags-keys" in qd:
            rows = [r for r in rows if qd["tags-keys"][0] in r["tags"]]
        if "tags-values" in qd:
            rows = [r for r in rows if qd["tags-values"][0] in r["tags"].values()]
        if "project-id" in qd:
            rows = [r for r in rows if r["projectId"] == qd["project-id"][0]]
        if "statuses" in qd:
            rows = [r for r in rows if r["status"] == qd["statuses"][0]]
        if "scan-ids" in qd:
            rows = [r for r in rows if r["id"] in qd["scan-ids"]]
        off = int(qd.get("offset", ["0"])[0])
        lim = int(qd.get("limit", ["20"])[0])
        # totalCount deliberately wrong (tenant-wide), as on the real API
        return FakeResp(200, {"totalCount": len(self.t2_scans) + 999, "scans": rows[off:off + lim]})
