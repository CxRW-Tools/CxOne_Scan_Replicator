"""JSONL audit trail + rotating, redacted text log."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from src.utils.http import redact_text


class RedactingFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact_text(record.getMessage())
        record.args = ()
        return True


def setup_logger(log_file: str, debug: bool = False, name: str = "replicator") -> logging.Logger:
    log_file = os.path.normpath(os.path.abspath(log_file))
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logger = logging.getLogger(name)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=20 * 1024 * 1024, backupCount=10,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    return logger


def _scrub(obj):
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub(v) for v in obj]
    return obj


class Audit:
    """Appends one JSON object per event (each write is opened, flushed, closed: crash-safe)
    and mirrors it to the text log at DEBUG."""

    def __init__(self, path: Optional[str], run_id: str, mode: str, logger: Optional[logging.Logger] = None):
        self.path = os.path.normpath(os.path.abspath(path)) if path else None
        self.run_id = run_id
        self.mode = mode
        self.logger = logger or logging.getLogger("replicator")
        self._lock = threading.Lock()
        if self.path:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def event(self, event: str, **fields):
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "run_id": self.run_id, "mode": self.mode, "event": event}
        rec.update(_scrub(fields))
        line = json.dumps(rec, default=str, ensure_ascii=False)
        if self.path:
            with self._lock:
                with open(os.path.normpath(os.path.abspath(self.path)), "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        self.logger.debug("event %s", line)

    def transition(self, job, stage: str, result: str, duration_s: float = 0.0):
        self.logger.info("run=%s mode=%s scan=%s project=%s stage=%s result=%s duration=%.2fs",
                         self.run_id, self.mode, job.source_scan_id, job.project_name, stage, result,
                         duration_s)

    def close(self):
        pass
