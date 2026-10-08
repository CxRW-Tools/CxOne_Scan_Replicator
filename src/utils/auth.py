"""Thread-safe AuthManager (API key -> access token via refresh_token grant)."""
from __future__ import annotations

import threading
import time
from typing import Optional

import requests

from src.model import USER_AGENT


class AuthError(Exception):
    pass


class AuthManager:
    def __init__(self, iam_url: str, tenant_name: str, api_key: str, debug: bool = False,
                 http=None):
        self.tenant_name = tenant_name
        self.api_key = api_key
        self.debug = debug
        self.auth_url = f"{iam_url.rstrip('/')}/auth/realms/{tenant_name}/protocol/openid-connect/token"
        self._http = http or requests
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._expires_at = 0.0

    def _valid(self) -> bool:
        return self._token is not None and time.time() < self._expires_at - 60

    def ensure_authenticated(self) -> str:
        if self._valid():
            return self._token
        with self._lock:
            if not self._valid():
                self._authenticate()
            return self._token

    def invalidate(self, bad_token: Optional[str] = None):
        """Drop the cached token (only if it is still the one that failed)."""
        with self._lock:
            if bad_token is None or bad_token == self._token:
                self._token = None
                self._expires_at = 0.0

    def _authenticate(self):
        data = {"grant_type": "refresh_token", "client_id": "ast-app", "refresh_token": self.api_key}
        try:
            r = self._http.post(self.auth_url, data=data, timeout=(10, 60),
                                headers={"Content-Type": "application/x-www-form-urlencoded",
                                         "User-Agent": USER_AGENT})
        except requests.RequestException as e:
            raise AuthError(f"authentication request failed for tenant '{self.tenant_name}': "
                            f"{type(e).__name__}")
        if r.status_code != 200:
            raise AuthError(f"authentication failed for tenant '{self.tenant_name}': HTTP {r.status_code}")
        try:
            body = r.json()
            token = body["access_token"]
        except Exception:
            raise AuthError(f"authentication response for '{self.tenant_name}' had no access_token")
        self._token = token
        self._expires_at = time.time() + float(body.get("expires_in", 600))

    def get_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.ensure_authenticated()}"}
