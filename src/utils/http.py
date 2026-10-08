"""TenantClient: one pooled session per tenant, retries, 429/AIMD, redaction."""
from __future__ import annotations

import contextlib
import random
import re
import threading
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from src.model import USER_AGENT

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60
REDIRECTS = (301, 302, 303, 307, 308)

# --------------------------------------------------------------------------- redaction
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_KV_RE = re.compile(r"(?i)\b(refresh_token|access_token|api[_-]?key|password|client_secret|"
                    r"x-amz-signature|x-amz-credential|x-amz-security-token|signature|token)=([^&\s\"']+)")
_URL_RE = re.compile(r"(https?://[^\s\"'<>?]+)\?[^\s\"'<>]*")


def redact_url(url: str) -> str:
    """host + path only; query string of (pre-signed) URLs is never kept."""
    try:
        u = urlparse(url)
    except ValueError:
        return "<url>"
    return f"{u.scheme}://{u.netloc}{u.path}" if u.netloc else u.path


def redact_text(text) -> str:
    s = str(text)
    s = _URL_RE.sub(lambda m: m.group(1) + "?<redacted>", s)
    s = _BEARER_RE.sub(r"\1<redacted>", s)
    s = _JWT_RE.sub("<jwt-redacted>", s)
    s = _KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", s)
    return s


# --------------------------------------------------------------------------- AIMD limiter
class AdaptiveLimiter:
    """Concurrency limiter: halves on repeated 429s, +1 per 50 consecutive successes."""

    def __init__(self, limit: int):
        self.max = max(1, limit)
        self.limit = self.max
        self._in_use = 0
        self._cond = threading.Condition()
        self._consec_429 = 0
        self._successes = 0

    def acquire(self):
        with self._cond:
            while self._in_use >= self.limit:
                self._cond.wait()
            self._in_use += 1

    def release(self):
        with self._cond:
            self._in_use -= 1
            self._cond.notify_all()

    def on_429(self):
        with self._cond:
            self._successes = 0
            self._consec_429 += 1
            if self._consec_429 >= 2:
                self.limit = max(1, self.limit // 2)
                self._consec_429 = 0

    def on_success(self):
        with self._cond:
            self._consec_429 = 0
            self._successes += 1
            if self._successes >= 50:
                self._successes = 0
                if self.limit < self.max:
                    self.limit += 1
                    self._cond.notify_all()


def _retry_after(resp) -> Optional[float]:
    v = resp.headers.get("Retry-After")
    if not v:
        return None
    try:
        return max(0.0, min(float(v), 120.0))
    except ValueError:
        return None


class TenantClient:
    """HTTP access to one tenant. The bearer token is only ever sent to the tenant's own host."""

    def __init__(self, name: str, base_url: str, auth, *, max_concurrency: int = 8,
                 pool_size: int = 16, transfer_timeout: int = 900, session=None,
                 sleep=time.sleep, max_retries: int = 4):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.host = (urlparse(self.base_url).netloc or "").lower()
        self.auth = auth
        self.transfer_timeout = transfer_timeout
        self.limiter = AdaptiveLimiter(max_concurrency)
        self.sleep = sleep
        self.max_retries = max_retries
        if session is None:
            session = requests.Session()
            adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            session.headers["User-Agent"] = USER_AGENT
        self.session = session

    # -- helpers
    def absolute(self, url_or_path: str, base: Optional[str] = None) -> str:
        if re.match(r"^https?://", url_or_path):
            return url_or_path
        if base:
            return urljoin(base, url_or_path)
        return self.base_url + (url_or_path if url_or_path.startswith("/") else "/" + url_or_path)

    def is_own_host(self, url: str) -> bool:
        return (urlparse(url).netloc or "").lower() == self.host

    def _backoff(self, n: int) -> float:
        base = 2 ** (n - 1)
        return base + random.uniform(0, base * 0.5)

    # -- core
    def _do(self, method, url, *, auth, retry, stream, allow_redirects, transfer, hold, **kw):
        full = self.absolute(url)
        send_auth = bool(auth) and self.is_own_host(full)
        read_to = self.transfer_timeout if transfer else READ_TIMEOUT
        n = 0
        refreshed = False
        while True:
            n += 1
            headers = dict(kw.get("headers") or {})
            token = None
            if send_auth:
                token = self.auth.ensure_authenticated()
                headers["Authorization"] = f"Bearer {token}"
            body = kw.get("data")
            if hasattr(body, "seek"):
                body.seek(0)
            call_kw = {k: v for k, v in kw.items() if k != "headers"}
            self.limiter.acquire()
            try:
                resp = self.session.request(method, full, headers=headers, stream=stream,
                                            allow_redirects=allow_redirects,
                                            timeout=(CONNECT_TIMEOUT, read_to), **call_kw)
            except requests.RequestException:
                self.limiter.release()
                if retry == "safe" and n <= self.max_retries:
                    self.sleep(self._backoff(n))
                    continue
                raise
            status = resp.status_code
            if status == 401 and send_auth and not refreshed:
                refreshed = True
                self.auth.invalidate(token)
                resp.close()
                self.limiter.release()
                n -= 1
                continue
            if status == 429:
                self.limiter.on_429()
                if retry != "none" and n <= max(self.max_retries, 5):
                    wait = _retry_after(resp) or self._backoff(n)
                    resp.close()
                    self.limiter.release()
                    self.sleep(wait)
                    continue
            elif status >= 500 and retry == "safe" and n <= self.max_retries:
                resp.close()
                self.limiter.release()
                self.sleep(self._backoff(n))
                continue
            else:
                self.limiter.on_success()
            if not hold:
                self.limiter.release()
            return resp

    def request(self, method, url, *, auth=True, retry="safe", stream=False,
                allow_redirects=True, transfer=False, **kw):
        """retry: 'safe' (GET/HEAD/PUT: conn errors, 5xx, 429) | 'post' (429 only) | 'none'."""
        return self._do(method, url, auth=auth, retry=retry, stream=stream,
                        allow_redirects=allow_redirects, transfer=transfer, hold=False, **kw)

    @contextlib.contextmanager
    def stream(self, method, url, *, auth=True, retry="safe", allow_redirects=False,
               transfer=True, **kw):
        """Streaming request that holds a concurrency slot until the body is consumed."""
        resp = self._do(method, url, auth=auth, retry=retry, stream=True,
                        allow_redirects=allow_redirects, transfer=transfer, hold=True, **kw)
        try:
            yield resp
        finally:
            with contextlib.suppress(Exception):
                resp.close()
            self.limiter.release()
