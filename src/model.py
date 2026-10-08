"""Shared model: modes, job states, error codes, ScanJob."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional

VERSION = "1.0.0"
USER_AGENT = f"cxone-scan-replicator/{VERSION}"


class Mode(str, enum.Enum):
    REPLICATE = "replicate"
    DOWNLOAD_ONLY = "download-only"
    FROM_MANIFEST = "from-manifest"

    @property
    def uses_t1(self) -> bool:
        return self in (Mode.REPLICATE, Mode.DOWNLOAD_ONLY)

    @property
    def uses_t2(self) -> bool:
        return self in (Mode.REPLICATE, Mode.FROM_MANIFEST)


class S:
    """Job statuses."""
    PENDING = "PENDING"
    METADATA = "METADATA"
    SOURCE_CHECK = "SOURCE_CHECK"
    DOWNLOADING = "DOWNLOADING"
    DOWNLOADED = "DOWNLOADED"
    LOADED = "LOADED"
    PROJECT_RESOLVED = "PROJECT_RESOLVED"
    UPLOADING = "UPLOADING"
    UPLOADED = "UPLOADED"
    STARTING = "STARTING"
    STARTED = "STARTED"
    SAVED = "SAVED"
    VERIFIED = "VERIFIED"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"
    SKIPPED_FAILED = "SKIPPED_FAILED"  # previously FAILED and --retry-failed not given
    FAILED = "FAILED"


DONE = {S.STARTED, S.SAVED, S.VERIFIED}
SKIPPED = {S.SKIPPED_DUPLICATE, S.SKIPPED_FAILED}
IN_PROGRESS = {S.METADATA, S.SOURCE_CHECK, S.DOWNLOADING, S.DOWNLOADED, S.LOADED,
               S.PROJECT_RESOLVED, S.UPLOADING, S.UPLOADED, S.STARTING}


class E:
    """Error codes."""
    SOURCE_SCAN_NOT_FOUND = "source_scan_not_found"
    SOURCE_UNAVAILABLE = "source_unavailable"
    NO_SOURCE_PERMISSION = "no_source_permission"
    DOWNLOAD_FAILED = "download_failed"
    BAD_ZIP = "bad_zip"
    TOO_LARGE = "too_large"
    FILE_EXISTS = "file_exists"
    DISK_ERROR = "disk_error"
    PROJECT_FAILED = "project_failed"
    UPLOAD_FAILED = "upload_failed"
    START_FAILED = "start_failed"
    START_AMBIGUOUS = "start_ambiguous"
    SCAN_TYPE_REJECTED = "scan_type_rejected"
    NO_SUPPORTED_ENGINES = "no_supported_engines"
    MANIFEST_ZIP_MISSING = "manifest_zip_missing"
    MANIFEST_ZIP_CORRUPT = "manifest_zip_corrupt"
    NOT_IN_MANIFEST = "not_in_manifest"
    INTERRUPTED = "interrupted"
    UNEXPECTED = "unexpected_error"


class FatalError(Exception):
    """Run-level failure; main() maps it to exit code 1."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


class JobFailure(Exception):
    """Per-job failure with an error code. Never stops the run."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


class JobBail(Exception):
    """Job abandoned (shutdown / run halted); it stays resumable."""


@dataclass(eq=False)
class ScanJob:
    source_scan_id: str
    mode: Mode = Mode.REPLICATE
    t1_project_id: str = ""
    project_name: str = ""
    branch: str = ""
    source_status: str = ""
    source_created_at: str = ""
    source_engines: list = field(default_factory=list)
    source_source_type: str = ""
    tags: dict = field(default_factory=dict)
    t1_tenant: str = ""
    t1_base_url: str = ""
    scan_types: list = field(default_factory=list)
    status: str = S.PENDING
    error_code: str = ""
    error_message: str = ""
    attempts: int = 0
    zip_bytes: Optional[int] = None
    zip_sha256: str = ""
    zip_path: str = ""          # relative to output dir (download-only/manifest) or absolute
    t2_project_id: str = ""
    t2_project_created: Optional[bool] = None
    t2_scan_id: str = ""
    started_at: str = ""
    dup_info: str = ""
    # transient, never persisted
    payload: Any = None
    upload_url: str = ""
    head_length: Optional[int] = None
    stage: str = "pending"
    stage_started: float = 0.0
    bytes_done: int = 0
    bytes_total: int = 0
    finalized: bool = False
    seq_key: str = ""
    prev_state: Optional[dict] = None
