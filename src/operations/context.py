"""RunContext: everything a run shares (config, clients, state, audit, stats)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.model import Mode, ScanJob


@dataclass
class RunContext:
    args: Any
    mode: Mode
    run_id: str
    scan_types: list = field(default_factory=list)
    config: tuple = ()
    t1: Any = None                 # TenantClient
    t2: Any = None                 # Tenant2 (operations wrapper)
    t1_cfg: Any = None
    t2_cfg: Any = None
    state: Any = None
    audit: Any = None
    logger: Any = None
    stats: Any = None
    manifest: Any = None
    out_dir: Optional[str] = None
    dry_run: bool = False
    stop: threading.Event = field(default_factory=threading.Event)
    interrupts: int = 0
    paths: dict = field(default_factory=dict)
    sleep: Any = time.sleep

    # ------------------------------------------------------------------ persistence
    def save(self, job: ScanJob):
        if self.dry_run or self.state is None:
            return
        self.state.upsert(
            self.mode.value, job.source_scan_id, t1_project_id=job.t1_project_id,
            project_name=job.project_name, branch=job.branch, source_created_at=job.source_created_at,
            scan_types=job.scan_types, status=job.status, error_code=job.error_code,
            error_message=job.error_message, attempts=job.attempts, zip_bytes=job.zip_bytes,
            zip_sha256=job.zip_sha256, zip_path=job.zip_path, t2_project_id=job.t2_project_id,
            t2_project_created=job.t2_project_created, t2_scan_id=job.t2_scan_id,
            started_at=job.started_at)

    def set_status(self, job: ScanJob, status: str, stage: str = "", **fields):
        """Record a state transition: job, state DB and text log."""
        old = job.status
        now = time.time()
        dur = now - job.stage_started if job.stage_started else 0.0
        job.status = status
        for k, v in fields.items():
            setattr(job, k, v)
        self.save(job)
        if self.audit:
            self.audit.transition(job, stage or status, f"{old}->{status}", dur)
