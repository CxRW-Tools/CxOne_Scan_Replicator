"""Parse / validate / normalize --scan-types and build the API `config` array.

User-facing names (sast, iac, api, sca) are mapped to API engine names
(sast, kics, apisec, sca) only here.
"""
from __future__ import annotations

import copy
from typing import Optional

from src.model import FatalError

CANONICAL = ["sast", "iac", "api", "sca"]
API_TYPE = {"sast": "sast", "iac": "kics", "api": "apisec", "sca": "sca"}
LABEL = {"sast": "SAST", "iac": "IaC (KICS)", "api": "API Security", "sca": "SCA"}
ALIASES = {"kics": "iac", "apisec": "api"}
DISALLOWED = {"containers", "container", "secrets", "2ms", "microengines",
              "scorecard", "aisc", "cisec", "fusion"}
ALLOWED_TEXT = ", ".join(CANONICAL)

MISSING_MSG = ("--scan-types is required (choose from: sast, iac, api, sca), "
               "e.g. --scan-types sast,iac,api,sca")


class ScanTypeError(FatalError):
    pass


def parse_scan_types(raw: Optional[str]) -> list:
    """Return the normalized, de-duplicated list in canonical order."""
    if raw is None or not str(raw).strip():
        raise ScanTypeError(MISSING_MSG)
    wanted = set()
    for part in str(raw).split(","):
        v = "".join(part.split()).lower()
        if not v:
            continue
        if v in DISALLOWED:
            raise ScanTypeError(f"'{v}' is not supported by this tool; allowed: {ALLOWED_TEXT}")
        v = ALIASES.get(v, v)
        if v not in CANONICAL:
            raise ScanTypeError(f"unknown scan type '{v}'; valid values: {ALLOWED_TEXT} "
                                f"(aliases: kics=iac, apisec=api)")
        wanted.add(v)
    if not wanted:
        raise ScanTypeError("--scan-types is empty after parsing; " + MISSING_MSG)
    return [t for t in CANONICAL if t in wanted]


def from_source_engines(engines) -> list:
    """Map an original scan's `engines` to the supported selection (canonical order).

    Engines this tool never runs (containers, microengines/secrets, aisc, ...) are dropped.
    """
    wanted = set()
    for e in engines or []:
        v = ALIASES.get(str(e).strip().lower(), str(e).strip().lower())
        if v in CANONICAL:
            wanted.add(v)
    return [t for t in CANONICAL if t in wanted]


def build_config(types: list, sast_value: Optional[dict] = None) -> tuple:
    """Immutable-ish `config` array: exactly the selected engines, each with value {}."""
    if not types:
        raise ScanTypeError(MISSING_MSG)
    out = []
    for t in types:
        value = {}
        if t == "sast" and sast_value:
            value = dict(sast_value)
        out.append((API_TYPE[t], value))
    return tuple(out)


def config_payload(config: tuple) -> list:
    """Fresh JSON-able copy of the config array for one request."""
    return [{"type": t, "value": copy.deepcopy(v)} for t, v in config]


def tag_value(types: list) -> str:
    return ",".join(types)


def labels(types: list) -> str:
    return " · ".join(LABEL[t] for t in types)


def api_names(types: list) -> list:
    return [API_TYPE[t] for t in types]


def warnings_for(types: list) -> list:
    out = []
    if "api" in types and "sast" not in types:
        out.append("API Security selected without SAST: API Security may depend on SAST in "
                   "CxOne and might not run (verify on a live tenant).")
    return out
