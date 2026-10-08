"""Env-file loading, precedence, per-tenant config and JWT derivation.

Precedence per field: CLI > --env-file values (last file wins) > process
environment > built-in default.
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from dotenv import dotenv_values

from src.model import FatalError

TENANT_FIELDS = ("base_url", "iam_url", "tenant", "api_key")

# option attr -> (env var, converter, default)  (None default = no built-in default)
OPTION_ENV = {
    "scan_types": ("REPLICATOR_SCAN_TYPES", str, None),
    "output_dir": ("REPLICATOR_OUTPUT_DIR", str, None),
    "state_db": ("REPLICATOR_STATE_DB", str, "./replicator-state.sqlite"),
    "log_dir": ("REPLICATOR_LOG_DIR", str, "./logs"),
    "download_workers": ("REPLICATOR_DOWNLOAD_WORKERS", int, None),
    "upload_workers": ("REPLICATOR_UPLOAD_WORKERS", int, 4),
    "queue_max": ("REPLICATOR_QUEUE_MAX", int, 500),
}


class EnvSources:
    """Env-file values with per-key source attribution, falling back to os.environ."""

    def __init__(self, values: Optional[dict] = None, sources: Optional[dict] = None,
                 files: Optional[list] = None, environ: Optional[dict] = None,
                 warnings: Optional[list] = None):
        self.values = values or {}
        self.sources = sources or {}
        self.files = files or []
        self.environ = os.environ if environ is None else environ
        self.warnings = warnings or []

    def get(self, key: str):
        """Return (value, source) or (None, None)."""
        if key in self.values and self.values[key] not in (None, ""):
            return self.values[key], self.sources[key]
        v = self.environ.get(key)
        if v not in (None, ""):
            return v, "environment"
        return None, None


def load_env_files(paths: list, cwd: str = ".", environ: Optional[dict] = None) -> EnvSources:
    values, sources, files, warns = {}, {}, [], []
    if not paths:
        default = os.path.join(cwd, ".env")
        paths = [default] if os.path.isfile(default) else []
    for p in paths:
        if not os.path.isfile(p):
            raise FatalError(f"env file not found or not a file: {p}")
        try:
            data = dotenv_values(p)
        except (OSError, UnicodeError, ValueError) as e:
            raise FatalError(f"env file unreadable: {p} ({type(e).__name__})") from e
        if os.name == "posix":
            try:
                if os.stat(p).st_mode & 0o077:
                    warns.append(f"env file {p} is group/world accessible; chmod 600 it")
            except OSError:
                pass
        files.append(p)
        for k, v in data.items():
            values[k] = v
            sources[k] = f"env-file:{p}"
    return EnvSources(values, sources, files, environ, warns)


def preparse_env_files(argv: list) -> list:
    import argparse
    pre = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre.add_argument("--env-file", action="append", default=[])
    known, _ = pre.parse_known_args(argv)
    return known.env_file


def resolve_field(cli_value: Any, env_key: Optional[str], env: EnvSources, default: Any = None):
    """Return (value, source)."""
    if cli_value not in (None, ""):
        return cli_value, "cli"
    if env_key:
        v, src = env.get(env_key)
        if v is not None:
            return v, src
    if default is not None:
        return default, "default"
    return None, None


def apply_option_env(args, env: EnvSources) -> dict:
    """Fill env-capable options on args in place; return {attr: source}."""
    srcs = {}
    for attr, (key, conv, default) in OPTION_ENV.items():
        value, src = resolve_field(getattr(args, attr, None), key, env, default)
        if value is not None:
            try:
                value = conv(value)
            except (TypeError, ValueError):
                raise FatalError(f"invalid value for {attr} ({src}): {value!r}")
        setattr(args, attr, value)
        srcs[attr] = src
    return srcs


def decode_jwt_payload(token: str) -> dict:
    """Decode (without verifying) a JWT payload; {} if it isn't one."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part.encode()))
    except (ValueError, IndexError, AttributeError):
        return {}
    return data if isinstance(data, dict) else {}


def _iam_from_base(base_url: str) -> Optional[str]:
    host = urlparse(base_url).hostname or ""
    new = re.sub(r"(^|\.)ast\.", r"\1iam.", host, count=1)
    if new == host:
        return None
    return f"https://{new}"


@dataclass
class TenantConfig:
    label: str                       # "T1" / "T2"
    base_url: str = ""
    iam_url: str = ""
    tenant: str = ""
    api_key: str = field(default="", repr=False)
    sources: dict = field(default_factory=dict)

    def describe(self) -> str:
        s = self.sources
        return (f"{self.label}: tenant={self.tenant} [{s.get('tenant')}]  "
                f"base_url={self.base_url} [{s.get('base_url')}]  "
                f"iam_url={self.iam_url} [{s.get('iam_url')}]  api_key=*** [{s.get('api_key')}]")


def resolve_tenant(label: str, args, env: EnvSources) -> TenantConfig:
    n = label.lower()
    cfg = TenantConfig(label=label)
    for f in TENANT_FIELDS:
        v, src = resolve_field(getattr(args, f"{n}_{f}", None), f"CXONE_{label}_{f.upper()}", env)
        setattr(cfg, f, v or "")
        cfg.sources[f] = src
    if not cfg.api_key:
        raise FatalError(f"{label}: API key is required (--{n}-api-key or CXONE_{label}_API_KEY)")
    claims = decode_jwt_payload(cfg.api_key)
    iss = claims.get("iss") or ""
    if not cfg.tenant and iss:
        cfg.tenant, cfg.sources["tenant"] = iss.rstrip("/").rsplit("/", 1)[-1], "jwt"
    if not cfg.base_url and claims.get("ast-base-url"):
        cfg.base_url, cfg.sources["base_url"] = claims["ast-base-url"], "jwt"
    if not cfg.iam_url and iss:
        u = urlparse(iss)
        if u.scheme and u.netloc:
            cfg.iam_url, cfg.sources["iam_url"] = f"{u.scheme}://{u.netloc}", "jwt"
    if not cfg.iam_url and cfg.base_url:
        derived = _iam_from_base(cfg.base_url)
        if derived:
            cfg.iam_url, cfg.sources["iam_url"] = derived, "derived-from-base-url"
    missing = [f for f in ("base_url", "iam_url", "tenant") if not getattr(cfg, f)]
    if missing:
        raise FatalError(f"{label}: could not determine {', '.join(missing)} "
                         f"(set --{n}-<name> or CXONE_{label}_<NAME>; the API key's JWT didn't supply it)")
    cfg.base_url = cfg.base_url.rstrip("/")
    cfg.iam_url = cfg.iam_url.rstrip("/")
    for f in ("base_url", "iam_url"):
        if not re.match(r"^https?://", getattr(cfg, f)):
            setattr(cfg, f, "https://" + getattr(cfg, f))
    return cfg


def same_tenant(a: TenantConfig, b: TenantConfig) -> bool:
    return a.tenant.lower() == b.tenant.lower() and a.base_url.lower() == b.base_url.lower()
