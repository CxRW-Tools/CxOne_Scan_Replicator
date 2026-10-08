"""Run statistics + rich Live status screen (with plain fallback)."""
from __future__ import annotations

import collections
import shutil
import sys
import threading
import time
from typing import Optional

from src.model import DONE, SKIPPED, S

STAGES = ["pending", "checking", "downloading", "uploading", "starting", "done", "skipped", "failed"]


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_dur(sec: float) -> str:
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


class Stats:
    """Thread-safe counters shared by the pipeline and the UI."""

    def __init__(self, mode: str, run_id: str, total: int = 0):
        self.mode, self.run_id, self.total = mode, run_id, total
        self.lock = threading.Lock()
        self.started = time.time()
        self.stage_counts = collections.Counter()
        self.active: dict = {}
        self.errors = collections.deque(maxlen=8)
        self.error_codes = collections.Counter()
        self.bytes_down = 0
        self.bytes_up = 0
        self.bytes_known_total = 0
        self.completions = collections.deque(maxlen=200)
        self.queue = {"queued": None, "running": None, "threshold": None, "state": "n/a", "resume_at": 0.0}
        self.header = {}
        self.warnings = []
        self.disk_free: Optional[int] = None
        self.disk_low = False
        self.notices = collections.deque(maxlen=4)
        self._down_marks = collections.deque(maxlen=60)
        self._up_marks = collections.deque(maxlen=60)

    # -- updates
    def set_stage(self, job, stage: str):
        with self.lock:
            old = job.stage
            if old in STAGES:
                self.stage_counts[old] -= 1
            job.stage, job.stage_started = stage, time.time()
            self.stage_counts[stage] += 1
            if stage in ("done", "skipped", "failed", "pending"):
                self.active.pop(job.source_scan_id, None)
            else:
                self.active[job.source_scan_id] = job

    def register_pending(self, jobs):
        with self.lock:
            for j in jobs:
                j.stage = "pending"
                self.stage_counts["pending"] += 1

    def finish(self, job, final: str, record: bool = True):
        self.set_stage(job, final)
        with self.lock:
            if record and final != "pending":
                self.completions.append(time.time())
            if final == "failed":
                self.error_codes[job.error_code] += 1
                self.errors.append((job.source_scan_id, job.error_code, job.error_message[:80]))

    def add_down(self, n: int):
        with self.lock:
            self.bytes_down += n
            self._down_marks.append((time.time(), self.bytes_down))

    def add_up(self, n: int):
        with self.lock:
            self.bytes_up += n
            self._up_marks.append((time.time(), self.bytes_up))

    def set_queue(self, **kw):
        with self.lock:
            self.queue.update(kw)

    # -- derived
    def finished_count(self) -> int:
        c = self.stage_counts
        return c["done"] + c["skipped"] + c["failed"]

    def rate_per_min(self) -> float:
        with self.lock:
            if len(self.completions) < 2:
                return 0.0
            span = time.time() - self.completions[0]
            return 60.0 * len(self.completions) / span if span > 1 else 0.0

    @staticmethod
    def _mbps(marks) -> float:
        if len(marks) < 2:
            return 0.0
        (t0, b0), (t1, b1) = marks[0], marks[-1]
        return (b1 - b0) / (1 << 20) / (t1 - t0) if t1 > t0 and time.time() - t1 < 10 else 0.0

    def eta(self) -> Optional[float]:
        rate = self.rate_per_min()
        remaining = self.total - self.finished_count()
        return None if rate <= 0 or remaining <= 0 else remaining / rate * 60


# --------------------------------------------------------------------------- rendering
class StatusUI:
    """rich Live screen refreshed ~4x/second; falls back to plain progress lines."""

    def __init__(self, stats: Stats, *, enabled: bool = True, quiet: bool = False,
                 out_dir: Optional[str] = None, stream=None):
        self.stats = stats
        self.quiet = quiet
        self.out_dir = out_dir
        self.stream = stream or sys.stdout
        self.rich = enabled and not quiet and getattr(self.stream, "isatty", lambda: False)()
        self._live = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self.quiet:
            return
        if self.rich:
            from rich.console import Console
            from rich.live import Live
            self._live = Live(self._render(), console=Console(file=self.stream), refresh_per_second=4,
                              transient=False)
            self._live.start()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ui")
        self._thread.start()

    def _loop(self):
        last_plain = 0.0
        while not self._stop.wait(0.25):
            if self.out_dir:
                try:
                    self.stats.disk_free = shutil.disk_usage(self.out_dir).free
                except OSError:
                    pass
            if self.rich:
                self._live.update(self._render())
            elif time.time() - last_plain >= 10:
                last_plain = time.time()
                self.plain_line()

    def plain_line(self):
        s = self.stats
        c = s.stage_counts
        line = (f"[{fmt_dur(time.time() - s.started)}] {s.finished_count()}/{s.total} "
                f"done={c['done']} skipped={c['skipped']} failed={c['failed']} "
                f"active={len(s.active)} queue={s.queue['state']}")
        print(line, file=self.stream, flush=True)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._live:
            self._live.update(self._render())
            self._live.stop()

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.progress_bar import ProgressBar
        from rich.table import Table
        from rich.text import Text

        s = self.stats
        h = s.header
        elapsed = time.time() - s.started
        eta = s.eta()
        head = Text()
        head.append(f"Mode: {s.mode}   Run: {s.run_id}\n", style="bold")
        head.append(f"Tenants: {h.get('tenants', '')}\n")
        if h.get("scan_types"):
            head.append(f"Scan types: {h['scan_types']}\n")
        for w in s.warnings:
            head.append(f"WARNING: {w}\n", style="yellow")
        if h.get("env_files"):
            head.append(f"Env file(s): {h['env_files']}\n")
        head.append(f"Elapsed {fmt_dur(elapsed)}   ETA {fmt_dur(eta) if eta else '-'}")

        total = max(1, s.total)
        c = s.stage_counts
        bar = Table.grid(padding=(0, 1))
        bar.add_row(ProgressBar(total=total, completed=s.finished_count(), width=40),
                    f"{s.finished_count()}/{s.total}  (done {c['done']}, skipped {c['skipped']}, "
                    f"failed {c['failed']})")
        if s.mode == "download-only":
            known = max(s.bytes_known_total, s.bytes_down, 1)
            bar.add_row(ProgressBar(total=known, completed=s.bytes_down, width=40),
                        f"{fmt_bytes(s.bytes_down)} / {fmt_bytes(s.bytes_known_total)} known")
            if s.disk_free is not None:
                msg = f"free disk: {fmt_bytes(s.disk_free)}"
                bar.add_row("", Text(msg + ("  LOW - downloads paused" if s.disk_low else ""),
                                     style="red" if s.disk_low else ""))

        stages = Table(title="Stages", show_header=True)
        for name in STAGES:
            stages.add_column(name)
        stages.add_row(*[str(max(0, c[n])) for n in STAGES])
        stages.caption = (f"{s.rate_per_min():.1f} scans/min   down {s._mbps(s._down_marks):.1f} MB/s   "
                          f"up {s._mbps(s._up_marks):.1f} MB/s")

        active = Table(title="Active jobs", show_header=True)
        for col in ("scan", "project", "branch", "stage", "progress", "elapsed"):
            active.add_column(col, overflow="ellipsis", max_width=28)
        with s.lock:
            jobs = list(s.active.values())[:12]
        for j in jobs:
            prog = ""
            if j.bytes_total:
                prog = f"{fmt_bytes(j.bytes_done)}/{fmt_bytes(j.bytes_total)}"
            elif j.bytes_done:
                prog = fmt_bytes(j.bytes_done)
            active.add_row(j.source_scan_id[:8], j.project_name, j.branch, j.stage, prog,
                           fmt_dur(time.time() - j.stage_started))

        parts = [Panel(head, title="cxone-scan-replicator"), bar, stages, active]
        if s.queue["state"] != "n/a":
            q = s.queue
            state = q["state"]
            if state == "PAUSED":
                state += f" (resume check in {fmt_dur(q['resume_at'] - time.time())})"
            parts.append(Panel(f"Queued {q['queued']}  Running {q['running']}  "
                               f"threshold {q['threshold']}  state: {state}", title="Target tenant queue"))
        if s.errors:
            t = Table(title="Recent errors")
            for col in ("scan", "code", "message"):
                t.add_column(col, overflow="ellipsis")
            for sid, code, msg in list(s.errors):
                t.add_row(sid[:8], code, msg)
            parts.append(t)
        return Group(*parts)
