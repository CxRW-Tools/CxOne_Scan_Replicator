"""Staged worker pipeline (mode-aware) + Tenant2 queue gate + per-project start ordering."""
from __future__ import annotations

import csv
import os
import queue
import shutil
import threading
import time
from collections import Counter
from datetime import datetime, timezone

import requests

from src.model import (DONE, SKIPPED, VERSION, E, JobBail, JobFailure, Mode, S, ScanJob)
from src.operations import tenant1, tenant2
from src.operations.tenant2 import (TAG_AT, TAG_FROM_PROJECT, TAG_FROM_SCAN, TAG_FROM_TENANT, TAG_TYPES,
                                    ScanStartAmbiguous, ScanStartRejected)
from src.utils import scan_types as st
from src.utils.manifest import safe_join, sha256_file, zip_relpath

REPORT_COLUMNS = ["source_scan_id", "project_name", "branch", "scan_types", "status", "error_code",
                  "zip_bytes", "zip_sha256", "zip_path", "t2_project_id", "t2_project_created",
                  "t2_scan_id", "attempts"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- helpers
class Tracker:
    """Counts admitted-but-unfinished jobs; `finished` is set when the feeder is done and none remain."""

    def __init__(self):
        self._n = 0
        self._closed = False
        self._lock = threading.Lock()
        self.finished = threading.Event()

    def add(self):
        with self._lock:
            self._n += 1

    def done(self):
        with self._lock:
            self._n -= 1
            if self._closed and self._n <= 0:
                self.finished.set()

    def close(self):
        with self._lock:
            self._closed = True
            if self._n <= 0:
                self.finished.set()


class Sequencer:
    """Starts scans of the same project in createdAt order, one in flight per project."""

    def __init__(self, jobs: list, enabled: bool):
        self.enabled = enabled
        self._lock = threading.Lock()
        self._p = {}
        if enabled:
            for j in jobs:
                p = self._p.setdefault(j.seq_key, {"order": [], "pos": 0, "ready": {}, "finished": set(),
                                                   "inflight": None})
                p["order"].append(j.source_scan_id)

    def _drain(self, p) -> list:
        out = []
        while p["pos"] < len(p["order"]):
            jid = p["order"][p["pos"]]
            if jid in p["finished"]:
                p["pos"] += 1
                continue
            if p["inflight"] is None and jid in p["ready"]:
                out.append(p["ready"].pop(jid))
                p["inflight"] = jid
            break
        return out

    def ready(self, job) -> list:
        if not self.enabled:
            return [job]
        with self._lock:
            p = self._p[job.seq_key]
            p["ready"][job.source_scan_id] = job
            return self._drain(p)

    def finished(self, job) -> list:
        if not self.enabled:
            return []
        with self._lock:
            p = self._p.get(job.seq_key)
            if p is None:
                return []
            p["finished"].add(job.source_scan_id)
            p["ready"].pop(job.source_scan_id, None)
            if p["inflight"] == job.source_scan_id:
                p["inflight"] = None
            return self._drain(p)


class QueueGate:
    """After every N starts, pause new uploads/starts while Tenant2's queue is over the threshold."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.open = threading.Event()
        self.open.set()
        self._lock = threading.Lock()

    def wait_open(self) -> bool:
        while not self.open.wait(0.25):
            if self.ctx.stop.is_set():
                return False
        return True

    def _depth(self):
        a = self.ctx.args
        try:
            return self.ctx.t2.queue_depth(a.queue_count == "running")
        except (JobFailure, requests.RequestException, ValueError) as e:
            self.ctx.logger.warning("queue depth check failed (%s); continuing", type(e).__name__)
            return None

    def check(self, reason: str = "periodic"):
        if not self._lock.acquire(blocking=False):
            return
        ctx, a = self.ctx, self.ctx.args
        try:
            paused = False
            while True:
                depth = self._depth()
                over = depth is not None and depth > a.queue_max
                ctx.audit.event("queue_check", reason=reason, depth=depth, threshold=a.queue_max,
                                counting=a.queue_count, decision="pause" if over else "ok")
                if not over:
                    ctx.stats.set_queue(queued=depth, threshold=a.queue_max, state="OK")
                    if paused:
                        ctx.audit.event("queue_resume", depth=depth)
                        ctx.logger.info("Tenant2 queue back under threshold (%s); resuming", depth)
                    self.open.set()
                    return
                if not paused:
                    paused = True
                    self.open.clear()
                    ctx.audit.event("queue_pause", depth=depth, threshold=a.queue_max,
                                    pause_seconds=a.queue_pause_seconds)
                    ctx.logger.warning("Tenant2 queue %s > %s: pausing %ss", depth, a.queue_max,
                                       a.queue_pause_seconds)
                resume_at = time.time() + a.queue_pause_seconds
                ctx.stats.set_queue(queued=depth, threshold=a.queue_max, state="PAUSED",
                                    resume_at=resume_at)
                while time.time() < resume_at:
                    if ctx.stop.wait(min(1.0, max(0.01, resume_at - time.time()))):
                        return          # stay closed; waiting jobs bail and remain resumable
                reason = "recheck"
        finally:
            self._lock.release()


# --------------------------------------------------------------------------- pipeline
class RunResult:
    def __init__(self):
        self.halted = ""           # run-level stop reason (apisec rejection)
        self.interrupted = False
        self.counts = Counter()
        self.not_processed = 0


class Pipeline:
    def __init__(self, ctx, plan):
        self.ctx, self.plan = ctx, plan
        a = ctx.args
        self.mode = ctx.mode
        self.tracker = Tracker()
        self.fin_lock = threading.Lock()
        self.halt = threading.Event()
        self.result = RunResult()
        self.budget = tenant1.MemoryBudget(int(a.memory_budget_mb) << 20)
        self.dl_workers = a.download_workers or (8 if self.mode == Mode.DOWNLOAD_ONLY else 4)
        self.q_first = queue.Queue(maxsize=max(2, self.dl_workers * 2))
        self.q_up = queue.Queue(maxsize=max(2, a.upload_workers * 2))
        self.q_start = queue.Queue()
        self.seq = Sequencer(plan.to_run, a.preserve_order and self.mode.uses_t2)
        self.gate = QueueGate(ctx) if self.mode.uses_t2 else None
        self.started_n = 0
        self.started_lock = threading.Lock()
        self.verify_batch = []
        self.threads = []
        self.mem_max = int(a.memory_zip_max_mb) << 20
        self.max_bytes = int(a.max_zip_mb) << 20
        self.disk_warned = False

    # ------------------------------------------------------------------ control
    def _spawn(self, n, q, handler, name):
        for i in range(n):
            t = threading.Thread(target=self._worker, args=(q, handler), name=f"{name}-{i}", daemon=True)
            t.start()
            self.threads.append(t)

    def _worker(self, q, handler):
        while True:
            try:
                job = q.get(timeout=0.2)
            except queue.Empty:
                if self.tracker.finished.is_set():
                    return
                continue
            try:
                handler(job)
            except JobBail:
                self.finalize(job, S.PENDING, E.INTERRUPTED, "run stopped; job is resumable")
            except JobFailure as f:
                self.finalize(job, S.FAILED, f.code, f.message)
            except Exception as e:  # last resort: a job error never stops the run
                self.ctx.logger.exception("unexpected error on %s", job.source_scan_id)
                self.finalize(job, S.FAILED, E.UNEXPECTED, f"{type(e).__name__}: {e}")

    def run(self) -> RunResult:
        ctx, a = self.ctx, self.ctx.args
        ctx.stats.register_pending(self.plan.jobs)
        run_ids = {id(j) for j in self.plan.to_run}
        for j in self.plan.jobs:
            if id(j) in run_ids:
                continue
            fin = "failed" if j.status == S.FAILED else "skipped"
            ctx.stats.finish(j, fin, record=False)
            if self.mode == Mode.DOWNLOAD_ONLY and j.status == S.FAILED and ctx.manifest:
                ctx.manifest.append(self._manifest_row(j, "FAILED"))
        if self.mode == Mode.DOWNLOAD_ONLY and not a.no_save_zips:
            self._clean_part_files()
        if self.gate:
            self.gate.check("startup")
        if self.mode == Mode.DOWNLOAD_ONLY:
            self._spawn(self.dl_workers, self.q_first, self._stage_download, "dl")
        elif self.mode == Mode.REPLICATE:
            self._spawn(self.dl_workers, self.q_first, self._stage_download, "dl")
            self._spawn(a.upload_workers, self.q_up, self._stage_upload, "up")
            self._spawn(a.start_workers, self.q_start, self._stage_start, "start")
        else:
            self._spawn(self.dl_workers, self.q_first, self._stage_load, "load")
            self._spawn(a.upload_workers, self.q_up, self._stage_upload, "up")
            self._spawn(a.start_workers, self.q_start, self._stage_start, "start")

        for job in self.plan.to_run:
            if ctx.stop.is_set() or self.halt.is_set():
                break
            self.tracker.add()
            while True:
                try:
                    self.q_first.put(job, timeout=0.25)
                    break
                except queue.Full:
                    if ctx.stop.is_set() or self.halt.is_set():
                        self.tracker.done()
                        job = None
                        break
            if job is None:
                break
        self.tracker.close()
        while not self.tracker.finished.wait(0.25):
            pass
        for t in self.threads:
            t.join(timeout=5)
        self._flush_verify()
        self.result.interrupted = ctx.stop.is_set()
        for j in self.plan.jobs:
            self.result.counts[j.status] += 1
        self.result.not_processed = sum(1 for j in self.plan.to_run if j.status == S.PENDING)
        return self.result

    def _clean_part_files(self):
        for root, _, files in os.walk(self.ctx.out_dir):
            for f in files:
                if f.endswith(".zip.part"):
                    tenant1.remove_file(os.path.join(root, f))

    # ------------------------------------------------------------------ finalize
    def finalize(self, job: ScanJob, status: str, code: str = "", msg: str = "", persist: bool = True):
        ctx = self.ctx
        with self.fin_lock:
            if job.finalized:
                return
            job.finalized = True
        if status == S.FAILED:
            job.error_code, job.error_message = code, msg
            ctx.audit.event("job_failed", source_scan_id=job.source_scan_id, project_name=job.project_name,
                            error_code=code, message=msg, stage=job.stage)
        elif status == S.PENDING:
            job.error_code, job.error_message = code, msg
        if job.payload is not None:
            job.payload.release()
            job.payload = None
        if persist:
            ctx.set_status(job, status, "final")
        else:
            job.status = status
        if self.mode == Mode.DOWNLOAD_ONLY and ctx.manifest and status in (S.SAVED, S.VERIFIED, S.FAILED):
            ctx.manifest.append(self._manifest_row(job, status))
        final = ("done" if status in DONE else "skipped" if status in SKIPPED
                 else "failed" if status == S.FAILED else "pending")
        ctx.stats.finish(job, final)
        if self.mode.uses_t2:
            for nxt in self.seq.finished(job):
                self.q_start.put(nxt)
        self.tracker.done()

    def _manifest_row(self, job, status) -> dict:
        return {"source_scan_id": job.source_scan_id, "t1_tenant": job.t1_tenant,
                "t1_base_url": job.t1_base_url, "t1_project_id": job.t1_project_id,
                "project_name": job.project_name, "branch": job.branch,
                "source_status": job.source_status, "source_created_at": job.source_created_at,
                "source_engines": job.source_engines, "tags": job.tags, "status": status,
                "error_code": job.error_code if status == S.FAILED else "",
                "error_message": job.error_message if status == S.FAILED else "",
                "zip_path": job.zip_path if status == S.SAVED else "", "zip_bytes": job.zip_bytes,
                "zip_sha256": job.zip_sha256, "downloaded_at": utc_now(), "tool_version": VERSION,
                "run_id": self.ctx.run_id}

    # ------------------------------------------------------------------ stage: download (T1)
    def _progress(self, job):
        stats = self.ctx.stats

        def cb(n, clen):
            if clen and not job.bytes_total:
                job.bytes_total = clen
                stats.bytes_known_total += clen
            job.bytes_done = max(0, job.bytes_done + n)
            stats.add_down(n)
        return cb

    def _wait_disk(self, job):
        ctx, a = self.ctx, self.ctx.args
        floor = a.min_free_gb * (1 << 30)
        while True:
            free = shutil.disk_usage(ctx.out_dir).free
            ctx.stats.disk_free = free
            if free >= floor:
                ctx.stats.disk_low = False
                self.disk_warned = False
                return
            ctx.stats.disk_low = True
            if not self.disk_warned:
                self.disk_warned = True
                ctx.audit.event("disk_low", free_bytes=free, min_free_gb=a.min_free_gb)
                ctx.logger.warning("free disk %s below %s GB; pausing downloads", free, a.min_free_gb)
            if ctx.stop.is_set():
                raise JobBail()
            ctx.stop.wait(1.0)

    def _stage_download(self, job: ScanJob):
        ctx, a = self.ctx, self.ctx.args
        job.attempts += 1
        job.started_at = job.started_at or utc_now()
        save_zip = self.mode == Mode.DOWNLOAD_ONLY and not a.no_save_zips
        final_path = None
        if save_zip:
            rel = zip_relpath(job.source_scan_id, job.project_name, job.branch, a.layout)
            final_path = safe_join(ctx.out_dir, rel)
            if os.path.isfile(final_path):
                prev = job.prev_state or {}
                known = prev.get("zip_sha256") if prev.get("status") == S.SAVED else ""
                if known and sha256_file(final_path) == known:
                    job.dup_info = "already downloaded (file present, SHA-256 matches)"
                    job.zip_path = rel
                    job.zip_bytes = os.path.getsize(final_path)
                    job.zip_sha256 = known
                    ctx.audit.event("dedupe_hit", source_scan_id=job.source_scan_id, via="file",
                                    zip_path=rel)
                    self.finalize(job, S.SKIPPED_DUPLICATE, persist=False)
                    return
                if not a.overwrite:
                    raise JobFailure(E.FILE_EXISTS, f"{rel} exists with different/unknown content "
                                                    f"(use --overwrite)")
        ctx.stats.set_stage(job, "checking")
        ctx.set_status(job, S.SOURCE_CHECK, "source_check")
        try:
            _, length = tenant1.head_source(ctx.t1, job.source_scan_id)
        except JobFailure as f:
            ctx.audit.event("source_unavailable", source_scan_id=job.source_scan_id, code=f.code)
            raise
        if length and self.max_bytes and length > self.max_bytes:
            raise JobFailure(E.TOO_LARGE, f"zip is {length} bytes (limit {self.max_bytes})")
        if save_zip:
            self._wait_disk(job)
        ctx.stats.set_stage(job, "downloading")
        ctx.set_status(job, S.DOWNLOADING, "download")
        ctx.audit.event("download_start", source_scan_id=job.source_scan_id, project_name=job.project_name,
                        branch=job.branch)
        t0 = time.time()
        if self.mode == Mode.DOWNLOAD_ONLY:
            make = (lambda: tenant1.FileSink(final_path)) if save_zip else tenant1.NullSink
        else:
            make = lambda: tenant1.SpoolSink(self.budget, self.mem_max, a.temp_dir)  # noqa: E731
        payload = tenant1.download_source(ctx.t1, job.source_scan_id, make, max_bytes=self.max_bytes,
                                          verify=a.verify_zip, progress=self._progress(job),
                                          sleep=ctx.sleep)
        job.zip_bytes, job.zip_sha256 = payload.size, payload.sha256
        ctx.audit.event("download_complete", source_scan_id=job.source_scan_id, zip_bytes=payload.size,
                        zip_sha256=payload.sha256, in_memory=payload.in_memory,
                        duration_ms=int((time.time() - t0) * 1000))
        if self.mode == Mode.DOWNLOAD_ONLY:
            if save_zip:
                job.zip_path = rel
                ctx.audit.event("zip_saved", source_scan_id=job.source_scan_id, zip_path=rel,
                                zip_bytes=payload.size, zip_sha256=payload.sha256)
                self.finalize(job, S.SAVED)
            else:
                job.zip_path = ""
                ctx.audit.event("zip_verified", source_scan_id=job.source_scan_id,
                                zip_bytes=payload.size, zip_sha256=payload.sha256)
                self.finalize(job, S.VERIFIED)
            return
        job.payload = payload
        ctx.set_status(job, S.DOWNLOADED, "download")
        self.q_up.put(job)

    # ------------------------------------------------------------------ stage: load (manifest)
    def _stage_load(self, job: ScanJob):
        ctx = self.ctx
        job.attempts += 1
        job.started_at = job.started_at or utc_now()
        ctx.stats.set_stage(job, "checking")
        job.payload = self._manifest_payload(job)
        ctx.set_status(job, S.LOADED, "load")
        self.q_up.put(job)

    def _manifest_payload(self, job: ScanJob) -> tenant1.Payload:
        try:
            path = safe_join(self.ctx.args.from_manifest, job.zip_path)
        except ValueError as e:
            raise JobFailure(E.MANIFEST_ZIP_MISSING, str(e)) from e
        if not os.path.isfile(path):
            raise JobFailure(E.MANIFEST_ZIP_MISSING, f"zip not found: {job.zip_path}")
        sha = sha256_file(path)
        if job.zip_sha256 and sha != job.zip_sha256:
            raise JobFailure(E.MANIFEST_ZIP_CORRUPT, "SHA-256 differs from manifest")
        job.zip_bytes = os.path.getsize(path)
        return tenant1.Payload(job.zip_bytes, sha, path=path, delete_path=False)   # never deleted

    # ------------------------------------------------------------------ stage: upload (T2)
    def _gate_or_bail(self):
        if self.gate and not self.gate.wait_open():
            raise JobBail()

    def _stage_upload(self, job: ScanJob):
        ctx, a = self.ctx, self.ctx.args
        self._gate_or_bail()
        if self.halt.is_set():
            raise JobBail()
        ctx.stats.set_stage(job, "uploading")
        pid, created = ctx.t2.resolve_project(job.project_name)
        job.t2_project_id, job.t2_project_created = pid, created
        ctx.audit.event("project_created" if created else "project_found",
                        source_scan_id=job.source_scan_id, project_name=job.project_name, t2_project_id=pid)
        ctx.set_status(job, S.PROJECT_RESOLVED, "project")
        self._gate_or_bail()       # a pause may have started while resolving
        ctx.set_status(job, S.UPLOADING, "upload")
        t0 = time.time()
        job.upload_url = ctx.t2.upload(job.payload, int(a.multipart_threshold_mb) << 20)
        ctx.stats.add_up(job.payload.size)
        ctx.audit.event("upload_complete", source_scan_id=job.source_scan_id, zip_bytes=job.payload.size,
                        duration_ms=int((time.time() - t0) * 1000))
        job.payload.release()
        job.payload = None
        ctx.set_status(job, S.UPLOADED, "upload")
        ctx.stats.set_stage(job, "starting")
        for nxt in self.seq.ready(job):
            self.q_start.put(nxt)

    # ------------------------------------------------------------------ stage: start (T2)
    def _tags(self, job: ScanJob) -> dict:
        tags = dict(job.tags)
        tags.update({TAG_FROM_SCAN: job.source_scan_id, TAG_FROM_TENANT: job.t1_tenant,
                     TAG_FROM_PROJECT: job.t1_project_id, TAG_TYPES: st.tag_value(self.ctx.scan_types),
                     TAG_AT: utc_now()})
        return tags

    def _stage_start(self, job: ScanJob):
        ctx = self.ctx
        if self.halt.is_set():
            raise JobBail()
        self._gate_or_bail()
        if self.halt.is_set():
            raise JobBail()
        ctx.stats.set_stage(job, "starting")
        job.scan_types = list(ctx.scan_types)
        ctx.set_status(job, S.STARTING, "start")
        tags = self._tags(job)
        t0 = time.time()
        body = ctx.t2.build_body(job, job.upload_url, tags)
        if not job.branch:
            ctx.logger.warning("scan %s has no branch; starting without one", job.source_scan_id)
        try:
            scan_id = ctx.t2.start_scan(body)
        except ScanStartRejected as e:
            self._rejected(job, e)
        except ScanStartAmbiguous as e:
            scan_id = self._resolve_ambiguous(job, tags, e)
        job.t2_scan_id = scan_id
        ctx.audit.event("scan_started", source_scan_id=job.source_scan_id, project_name=job.project_name,
                        branch=job.branch, scan_types=list(ctx.scan_types), t2_project_id=job.t2_project_id,
                        t2_scan_id=scan_id, duration_ms=int((time.time() - t0) * 1000))
        self.finalize(job, S.STARTED)
        self._after_start(job)

    def _rejected(self, job, e: ScanStartRejected):
        ctx = self.ctx
        if e.status == 400 and "api" in ctx.scan_types and e.mentions_apisec:
            self.halt.set()
            self.result.halted = ("Tenant2 rejected the 'apisec' engine (HTTP 400). Every scan would fail; "
                                  "stopped starting scans. Re-run without 'api' in --scan-types.")
            ctx.audit.event("scan_type_rejected", engine="apisec", status=e.status, message=e.body[:300])
            raise JobFailure(E.SCAN_TYPE_REJECTED, "Tenant2 rejected engine apisec")
        raise JobFailure(E.START_FAILED, str(e))

    def _resolve_ambiguous(self, job, tags, first: Exception) -> str:
        ctx = self.ctx
        ctx.audit.event("scan_start_ambiguous", source_scan_id=job.source_scan_id, reason=str(first))
        for attempt in range(3):
            try:
                found = ctx.t2.confirm_started(job.t2_project_id, job.source_scan_id)
            except requests.RequestException as e:
                raise JobFailure(E.START_AMBIGUOUS,
                                 f"could not confirm whether the scan started ({type(e).__name__})")
            if found:
                ctx.audit.event("scan_start_confirmed", source_scan_id=job.source_scan_id,
                                t2_scan_id=found, via="ambiguous_check")
                return found
            if attempt == 2:
                break
            ctx.sleep(1)
            if job.zip_path and self.mode == Mode.FROM_MANIFEST:    # zip still on disk: fresh upload
                payload = self._manifest_payload(job)
                job.upload_url = ctx.t2.upload(payload)
            body = ctx.t2.build_body(job, job.upload_url, tags)
            try:
                return ctx.t2.start_scan(body)
            except ScanStartRejected as e:
                self._rejected(job, e)
            except ScanStartAmbiguous as e:
                ctx.audit.event("scan_start_ambiguous", source_scan_id=job.source_scan_id, reason=str(e))
        raise JobFailure(E.START_FAILED, "scan start failed and no scan was created after retries")

    def _after_start(self, job):
        ctx, a = self.ctx, self.ctx.args
        if a.verify_engines:
            with self.started_lock:
                self.verify_batch.append(job)
                batch = self.verify_batch if len(self.verify_batch) >= 50 else None
                if batch:
                    self.verify_batch = []
            if batch:
                self._verify(batch)
        with self.started_lock:
            self.started_n += 1
            trigger = self.started_n % a.queue_check_every == 0
        if trigger:
            self.gate.check("periodic")

    def _flush_verify(self):
        if self.verify_batch:
            batch, self.verify_batch = self.verify_batch, []
            self._verify(batch)

    def _verify(self, jobs):
        ctx = self.ctx
        want = sorted(st.api_names(ctx.scan_types))
        try:
            got = ctx.t2.scan_engines([j.t2_scan_id for j in jobs])
        except requests.RequestException:
            return
        for j in jobs:
            engines = sorted(set(got.get(j.t2_scan_id, [])))
            if engines and engines != want:
                ctx.logger.warning("engine mismatch on %s: wanted %s got %s", j.t2_scan_id, want, engines)
                ctx.audit.event("engine_mismatch", source_scan_id=j.source_scan_id,
                                t2_scan_id=j.t2_scan_id, wanted=want, got=engines)


# --------------------------------------------------------------------------- report + summary
def write_report(ctx, jobs: list):
    path = ctx.paths.get("report")
    if not path:
        return
    path = os.path.normpath(os.path.abspath(path))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(REPORT_COLUMNS)
        for j in jobs:
            w.writerow([j.source_scan_id, j.project_name, j.branch,
                        ",".join(ctx.scan_types) if ctx.mode.uses_t2 else "", j.status, j.error_code,
                        "" if j.zip_bytes is None else j.zip_bytes, j.zip_sha256, j.zip_path,
                        j.t2_project_id, "" if j.t2_project_created is None else str(j.t2_project_created).lower(),
                        j.t2_scan_id, j.attempts])


def format_summary(ctx, result: RunResult, jobs: list) -> str:
    counts = Counter(j.status for j in jobs)
    L = ["", "=" * 70, f"Run {ctx.run_id} - mode: {ctx.mode.value}"]
    if ctx.mode.uses_t2:
        L.append(f"Scan types: {st.labels(ctx.scan_types)}")
    L.append(f"Total: {len(jobs)}")
    for k, v in sorted(counts.items()):
        L.append(f"  {k:<18}{v}")
    codes = Counter(j.error_code for j in jobs if j.status == S.FAILED)
    if codes:
        L.append("Top error codes:")
        for c, n in codes.most_common(5):
            L.append(f"  {c}: {n}")
    attention = [j for j in jobs if j.status == S.FAILED][:10]
    if attention:
        L.append("Need attention (first 10):")
        for j in attention:
            L.append(f"  {j.source_scan_id}  {j.error_code}  {j.error_message[:80]}")
    if result.halted:
        L.append("RUN HALTED: " + result.halted)
    if result.interrupted:
        L.append(f"Interrupted: {result.not_processed + sum(1 for j in jobs if j.status == S.PENDING)} "
                 f"job(s) not completed; re-run with the same input to resume.")
    for label, key in (("Log", "log"), ("Audit", "audit"), ("Report", "report")):
        if ctx.paths.get(key):
            L.append(f"{label}: {ctx.paths[key]}")
    L.append(f"State DB: {ctx.args.state_db}")
    if ctx.mode == Mode.DOWNLOAD_ONLY and ctx.out_dir:
        L.append(f"Output dir: {ctx.out_dir}")
        L.append(f"Manifest: {os.path.join(ctx.out_dir, 'manifest.jsonl')}")
    L.append("=" * 70)
    return "\n".join(L)
