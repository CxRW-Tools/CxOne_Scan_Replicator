"""Env-file loading, precedence, per-tenant config and JWT derivation.

Precedence per field: CLI > --env-file values (last file wins) > process
environment > built-in default.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
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
    warnings: list = field(default_factory=list)

    @property
    def role(self) -> str:
        return "source" if self.label == "T1" else "target"

    def describe(self) -> str:
        s = self.sources
        return (f"{self.role.capitalize()}: tenant={self.tenant} [{s.get('tenant')}]  "
                f"base_url={self.base_url} [{s.get('base_url')}]  "
                f"iam_url={self.iam_url} [{s.get('iam_url')}]  api_key=*** [{s.get('api_key')}]")


def load_tenant_env(path: Optional[str]) -> Optional[EnvSources]:
    """Load one tenant's own env file (template format: CXONE_BASE_URL, CXONE_TENANT, CXONE_API_KEY,
    CXONE_IAM_URL, CXONE_DEBUG). The process environment is deliberately NOT consulted for these
    un-prefixed names, so source and target can never be mixed up."""
    if not path:
        return None
    return load_env_files([path], environ={})


def resolve_tenant(label: str, args, env: EnvSources, tenant_env: Optional[EnvSources] = None) -> TenantConfig:
    """Per field: CLI > this tenant's env file (CXONE_*) > legacy CXONE_T1_*/CXONE_T2_* in --env-file/env > JWT."""
    n = label.lower()
    cfg = TenantConfig(label=label)
    role = "source" if label == "T1" else "target"
    for f in TENANT_FIELDS:
        v, src = resolve_field(getattr(args, f"{n}_{f}", None), None, env)
        if v is None and tenant_env is not None:
            v, src = tenant_env.get(f"CXONE_{f.upper()}")
        if v is None:
            v, src = env.get(f"CXONE_{label}_{f.upper()}")
        setattr(cfg, f, v or "")
        cfg.sources[f] = src
    if not cfg.api_key:
        raise FatalError(f"{role} tenant: API key is required (--{role}-env-file with CXONE_API_KEY, "
                         f"or --{role}-api-key)")
    claims = decode_jwt_payload(cfg.api_key)
    iss = claims.get("iss") or ""
    if not cfg.tenant and iss:
        cfg.tenant, cfg.sources["tenant"] = iss.rstrip("/").rsplit("/", 1)[-1], "jwt"
    if not cfg.base_url and claims.get("ast-base-url"):
        cfg.base_url, cfg.sources["base_url"] = claims["ast-base-url"], "jwt"
    # IAM URL: explicit > derived from the base URL (ast.* -> iam.*, as in the CxOne template) > JWT issuer.
    # The base URL wins over the JWT because an API key's issuer region can differ from where the
    # tenant is actually served.
    if not cfg.iam_url and cfg.base_url:
        derived = _iam_from_base(cfg.base_url)
        if derived:
            cfg.iam_url, cfg.sources["iam_url"] = derived, "derived-from-base-url"
    if not cfg.iam_url and iss:
        u = urlparse(iss)
        if u.scheme and u.netloc:
            cfg.iam_url, cfg.sources["iam_url"] = f"{u.scheme}://{u.netloc}", "jwt"
    missing = [f for f in ("base_url", "iam_url", "tenant") if not getattr(cfg, f)]
    if missing:
        raise FatalError(f"{role} tenant: could not determine {', '.join(missing)} "
                         f"(set CXONE_<NAME> in --{role}-env-file or --{role}-<name>; "
                         f"the API key's JWT didn't supply it)")
    cfg.base_url = cfg.base_url.rstrip("/")
    cfg.iam_url = cfg.iam_url.rstrip("/")
    for f in ("base_url", "iam_url"):
        if not re.match(r"^https?://", getattr(cfg, f)):
            setattr(cfg, f, "https://" + getattr(cfg, f))
    validate_against_jwt(cfg, claims)
    return cfg


def _host(url: str) -> str:
    return (urlparse(url if "//" in url else "https://" + url).hostname or "").lower()


def validate_against_jwt(cfg: TenantConfig, claims: dict):
    """Cross-check configured values against the API key's JWT claims.

    A key issued for a different tenant is fatal (it cannot authenticate to the configured realm);
    a region/host mismatch is reported as a warning because the key may still work.
    """
    role = cfg.role
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and 0 < exp < time.time():
        raise FatalError(f"{role} tenant: the API key in the env file has expired "
                         f"(exp {time.strftime('%Y-%m-%d', time.gmtime(exp))})")
    iss = claims.get("iss") or ""
    if not iss:
        return
    jwt_tenant = iss.rstrip("/").rsplit("/", 1)[-1]
    if cfg.sources.get("tenant") != "jwt" and jwt_tenant and cfg.tenant.lower() != jwt_tenant.lower():
        raise FatalError(f"{role} tenant: configured tenant '{cfg.tenant}' does not match the API key's "
                         f"tenant '{jwt_tenant}'; wrong key or wrong CXONE_TENANT in the {role} env file")
    jwt_iam = _host(iss)
    if jwt_iam and _host(cfg.iam_url) != jwt_iam:
        cfg.warnings.append(f"{role} tenant: IAM host {_host(cfg.iam_url)} (from "
                            f"{cfg.sources.get('iam_url')}) differs from the API key's issuer {jwt_iam}; "
                            f"the key may belong to another region")
    jwt_base = _host(claims.get("ast-base-url") or "")
    if jwt_base and _host(cfg.base_url) != jwt_base:
        cfg.warnings.append(f"{role} tenant: base URL host {_host(cfg.base_url)} (from "
                            f"{cfg.sources.get('base_url')}) differs from the API key's {jwt_base}")


def same_tenant(a: TenantConfig, b: TenantConfig) -> bool:
    return a.tenant.lower() == b.tenant.lower() and a.base_url.lower() == b.base_url.lower()
