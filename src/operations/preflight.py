"""Stage 0: build jobs from metadata/manifest, de-dup, state resume, ordering, dry-run plan."""
from __future__ import annotations

import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from src.model import E, FatalError, JobFailure, Mode, S, ScanJob
from src.operations import tenant1
from src.utils.manifest import read_manifest, safe_join, zip_relpath

OK_STATUSES = {"completed", "partial"}


@dataclass
class Plan:
    jobs: list = field(default_factory=list)       # every job, in input order
    to_run: list = field(default_factory=list)     # jobs that enter the pipeline
    notes: list = field(default_factory=list)
    create_names: list = field(default_factory=list)
    existing_projects: int = 0
    est_bytes: int = 0
    unknown_size: int = 0
    already_downloaded: int = 0

    def count(self, *statuses) -> int:
        return sum(1 for j in self.jobs if j.status in statuses)


def _new_job(ctx, sid: str) -> ScanJob:
    return ScanJob(source_scan_id=sid, mode=ctx.mode,
                   scan_types=list(ctx.scan_types) if ctx.mode.uses_t2 else [])


def _fail(ctx, job: ScanJob, code: str, msg: str):
    job.status, job.error_code, job.error_message = S.FAILED, code, msg
    ctx.audit.event("job_failed", source_scan_id=job.source_scan_id, error_code=code, message=msg)


# --------------------------------------------------------------------------- job construction
def jobs_from_tenant1(ctx, ids: list) -> list:
    meta = tenant1.fetch_metadata(ctx.t1, ids, batch=ctx.args.metadata_batch)
    jobs = []
    for sid in ids:
        j = _new_job(ctx, sid)
        j.t1_tenant, j.t1_base_url = ctx.t1_cfg.tenant, ctx.t1_cfg.base_url
        m = meta.get(sid)
        if m is None:
            _fail(ctx, j, E.SOURCE_SCAN_NOT_FOUND, "scan id not returned by Tenant1")
        else:
            j.t1_project_id = str(m.get("projectId") or "")
            j.project_name = m.get("projectName") or ""
            j.branch = m.get("branch") or ""
            j.source_status = m.get("status") or ""
            j.source_created_at = m.get("createdAt") or ""
            j.source_engines = m.get("engines") or []
            j.source_source_type = m.get("sourceType") or ""
            j.tags = {str(k): "" if v is None else str(v) for k, v in (m.get("tags") or {}).items()}
            if j.source_status.lower() not in OK_STATUSES:
                ctx.logger.warning("scan %s has status %r (not Completed/Partial); source may still exist",
                                   sid, j.source_status)
            if not j.project_name:
                _fail(ctx, j, E.SOURCE_SCAN_NOT_FOUND, "Tenant1 scan has no project name")
        jobs.append(j)
    return jobs


def jobs_from_manifest(ctx, ids) -> list:
    try:
        rows = read_manifest(ctx.args.from_manifest)
    except FileNotFoundError as e:
        raise FatalError(str(e)) from e
    order = ids if ids else list(rows)
    jobs = []
    for sid in order:
        j = _new_job(ctx, sid)
        r = rows.get(sid)
        if r is None:
            _fail(ctx, j, E.NOT_IN_MANIFEST, "scan id is not in the manifest")
            jobs.append(j)
            continue
        j.t1_tenant, j.t1_base_url = r.get("t1_tenant") or "", r.get("t1_base_url") or ""
        j.t1_project_id = str(r.get("t1_project_id") or "")
        j.project_name, j.branch = r.get("project_name") or "", r.get("branch") or ""
        j.source_status, j.source_created_at = r.get("source_status") or "", r.get("source_created_at") or ""
        j.source_engines = r.get("source_engines") or []
        j.tags = {str(k): "" if v is None else str(v) for k, v in (r.get("tags") or {}).items()}
        j.zip_path, j.zip_sha256, j.zip_bytes = r.get("zip_path") or "", r.get("zip_sha256") or "", r.get("zip_bytes")
        if r.get("status") not in ("SAVED",) or not j.zip_path:
            _fail(ctx, j, E.MANIFEST_ZIP_MISSING,
                  f"manifest row has status {r.get('status')} / no zip_path (nothing to upload)")
        elif not j.project_name:
            _fail(ctx, j, E.NOT_IN_MANIFEST, "manifest row has no project name")
        jobs.append(j)
    return jobs


# --------------------------------------------------------------------------- de-dup + resume
def apply_dedupe_and_state(ctx, jobs: list, plan: Plan):
    a = ctx.args
    dedupe = {}
    if ctx.mode.uses_t2 and not a.ignore_duplicates:
        tenants = {j.t1_tenant for j in jobs if j.t1_tenant}
        dedupe = ctx.t2.dedupe_index(tenants or None)
        ctx.audit.event("preflight", step="dedupe_index", entries=len(dedupe))

    for j in jobs:
        if j.status == S.FAILED:
            continue
        row = ctx.state.get(ctx.mode.value, j.source_scan_id) if ctx.state else None
        if row:
            j.prev_state = row
            j.attempts = row.get("attempts") or 0
            j.t2_project_id = row.get("t2_project_id") or ""
            if row.get("zip_sha256") and not j.zip_sha256:
                j.zip_sha256 = row["zip_sha256"]
            if row.get("zip_bytes") is not None and j.zip_bytes is None:
                j.zip_bytes = row["zip_bytes"]
            if row.get("zip_path") and not j.zip_path:
                j.zip_path = row["zip_path"]
        # 1) already replicated according to Tenant2 tags
        hit = dedupe.get((j.t1_tenant, j.source_scan_id))
        if hit:
            j.status, j.t2_scan_id = S.SKIPPED_DUPLICATE, hit[0]
            j.dup_info = f"tag: existing Tenant2 scan {hit[0]} (scan types: {hit[1] or 'unknown'})"
            ctx.audit.event("dedupe_hit", source_scan_id=j.source_scan_id, via="tags",
                            t2_scan_id=hit[0], existing_scan_types=hit[1])
            continue
        if row and not a.ignore_duplicates:
            st = row["status"]
            if ctx.mode.uses_t2 and st == S.STARTED:
                j.status, j.t2_scan_id = S.SKIPPED_DUPLICATE, row.get("t2_scan_id") or ""
                j.dup_info = f"state-db: already started as Tenant2 scan {j.t2_scan_id}"
                ctx.audit.event("dedupe_hit", source_scan_id=j.source_scan_id, via="state_db",
                                t2_scan_id=j.t2_scan_id)
                continue
            if st == S.FAILED and not a.retry_failed:
                j.status, j.error_code = S.SKIPPED_FAILED, row.get("error_code") or ""
                j.error_message = f"previously failed ({j.error_code}); use --retry-failed"
                continue
        if row and row["status"] in (S.STARTING,) and ctx.mode.uses_t2 and row.get("t2_project_id") \
                and not ctx.dry_run:
            found = ctx.t2.confirm_started(row["t2_project_id"], j.source_scan_id)
            if found:
                j.status, j.t2_scan_id = S.STARTED, found
                ctx.audit.event("scan_start_confirmed", source_scan_id=j.source_scan_id,
                                t2_scan_id=found, via="resume")
                ctx.save(j)
                continue
        if row and ctx.mode.uses_t2 and row["status"] != S.STARTED and row.get("scan_types") \
                and row["scan_types"] != ",".join(ctx.scan_types):
            ctx.logger.info("scan %s: resuming with scan types %s (was %s)", j.source_scan_id,
                            ",".join(ctx.scan_types), row["scan_types"])
            ctx.audit.event("preflight", step="scan_types_changed", source_scan_id=j.source_scan_id,
                            old=row["scan_types"], new=ctx.scan_types)
        j.status = S.PENDING            # reset any in-progress state left by a crash
        j.error_code = j.error_message = ""
        plan.to_run.append(j)


def order_work(ctx, plan: Plan):
    if ctx.args.preserve_order:
        plan.to_run.sort(key=lambda j: (j.source_created_at or "", j.source_scan_id))
    for j in plan.to_run:
        j.seq_key = j.project_name


def check_disk(ctx):
    a = ctx.args
    if ctx.mode != Mode.DOWNLOAD_ONLY or a.no_save_zips:
        return
    path = os.path.abspath(ctx.out_dir)
    while not os.path.exists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    free = shutil.disk_usage(path).free
    ctx.stats.disk_free = free
    if free < a.min_free_gb * (1 << 30):
        ctx.audit.event("disk_low", free_bytes=free, min_free_gb=a.min_free_gb)
        raise FatalError(f"free disk space {free / (1 << 30):.1f} GB is below --min-free-gb "
                         f"{a.min_free_gb} at {ctx.out_dir}")


def build_plan(ctx, ids: list, subset_ids=None) -> Plan:
    plan = Plan()
    check_disk(ctx)
    if ctx.mode == Mode.FROM_MANIFEST:
        jobs = jobs_from_manifest(ctx, subset_ids)
    else:
        jobs = jobs_from_tenant1(ctx, ids)
    plan.jobs = jobs
    ctx.audit.event("preflight", step="jobs_built", total=len(jobs),
                    not_found=sum(1 for j in jobs if j.status == S.FAILED))
    apply_dedupe_and_state(ctx, jobs, plan)
    order_work(ctx, plan)
    # persist preflight failures / skips so the report and state DB are complete
    for j in jobs:
        if j.status in (S.FAILED, S.SKIPPED_DUPLICATE, S.SKIPPED_FAILED) and not (
                j.status == S.SKIPPED_FAILED or (j.status == S.SKIPPED_DUPLICATE and j.dup_info.startswith("state-db"))):
            ctx.save(j)
    if not ctx.dry_run:
        for j in plan.to_run:
            ctx.save(j)
    return plan


# --------------------------------------------------------------------------- dry run
def dry_run_checks(ctx, plan: Plan):
    """Network-only checks: source HEADs (T1 modes), project lookups (T2 modes), manifest zips."""
    a = ctx.args
    if ctx.mode.uses_t1:
        def head(j):
            try:
                _, length = tenant1.head_source(ctx.t1, j.source_scan_id)
                j.head_length = length
                return j, None
            except JobFailure as e:
                return j, e
        with ThreadPoolExecutor(max_workers=max(1, a.download_workers or 4)) as ex:
            for j, err in ex.map(head, list(plan.to_run)):
                if err:
                    j.status, j.error_code, j.error_message = S.FAILED, err.code, err.message
                    ctx.audit.event("source_unavailable", source_scan_id=j.source_scan_id, code=err.code)
        plan.to_run = [j for j in plan.to_run if j.status != S.FAILED]
        for j in plan.to_run:
            if j.head_length is None:
                plan.unknown_size += 1
            else:
                plan.est_bytes += j.head_length
        if ctx.mode == Mode.DOWNLOAD_ONLY and not a.no_save_zips:
            for j in plan.to_run:
                rel = zip_relpath(j.source_scan_id, j.project_name, j.branch, a.layout)
                row = ctx.state.get(ctx.mode.value, j.source_scan_id)
                p = os.path.join(ctx.out_dir, rel)
                if row and row["status"] == S.SAVED and os.path.isfile(p) and row.get("zip_bytes") == os.path.getsize(p):
                    plan.already_downloaded += 1
    if ctx.mode == Mode.FROM_MANIFEST:
        for j in list(plan.to_run):
            try:
                p = safe_join(ctx.args.from_manifest, j.zip_path)
            except ValueError as e:
                j.status, j.error_code, j.error_message = S.FAILED, E.MANIFEST_ZIP_MISSING, str(e)
                continue
            if not os.path.isfile(p) or (j.zip_bytes is not None and os.path.getsize(p) != j.zip_bytes):
                j.status, j.error_code = S.FAILED, E.MANIFEST_ZIP_MISSING
                j.error_message = "zip missing or size differs from manifest"
        plan.to_run = [j for j in plan.to_run if j.status != S.FAILED]
    if ctx.mode.uses_t2:
        names = sorted({j.project_name for j in plan.to_run})

        def look(n):
            return n, ctx.t2.find_project(n)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for n, pid in ex.map(look, names):
                if pid:
                    plan.existing_projects += 1
                else:
                    plan.create_names.append(n)


def format_plan(ctx, plan: Plan) -> str:
    from src.utils import scan_types as st
    from src.utils.ui import fmt_bytes
    import json
    a = ctx.args
    L = []
    L.append(f"Plan ({'dry run' if ctx.dry_run else 'confirmation'}) - mode: {ctx.mode.value}")
    if ctx.mode.uses_t2:
        L.append(f"  Scan types: {st.labels(ctx.scan_types)}  ({','.join(ctx.scan_types)})")
        L.append("  config sent for every scan: " + json.dumps(st.config_payload(ctx.config)))
        for w in st.warnings_for(ctx.scan_types):
            L.append(f"  WARNING: {w}")
    L.append(f"  Total input: {len(plan.jobs)}")
    verb = {"replicate": "to start", "download-only": "to download", "from-manifest": "to start"}[ctx.mode.value]
    L.append(f"  {len(plan.to_run)} {verb}")
    L.append(f"  {plan.count(S.SKIPPED_DUPLICATE)} duplicates (already replicated/downloaded)")
    L.append(f"  {plan.count(S.SKIPPED_FAILED)} skipped (previously failed; --retry-failed to retry)")
    L.append(f"  {plan.count(S.FAILED)} failed in preflight")
    by = {}
    for j in plan.jobs:
        if j.status == S.FAILED:
            by[j.error_code] = by.get(j.error_code, 0) + 1
    for code, n in sorted(by.items()):
        L.append(f"      {code}: {n}")
    if ctx.mode.uses_t1 and ctx.dry_run:
        L.append(f"  estimated download size: {fmt_bytes(plan.est_bytes)} known"
                 + (f", {plan.unknown_size} unknown" if plan.unknown_size else ""))
    if ctx.mode == Mode.DOWNLOAD_ONLY and ctx.dry_run:
        L.append(f"  already downloaded (file present, size matches): {plan.already_downloaded}")
    if ctx.mode.uses_t2 and ctx.dry_run:
        L.append(f"  {len(plan.create_names)} Tenant2 projects to create, "
                 f"{plan.existing_projects} already exist")
        for n in plan.create_names[:25]:
            L.append(f"      + {n}")
        if len(plan.create_names) > 25:
            L.append(f"      ... and {len(plan.create_names) - 25} more")
    if a.ignore_duplicates:
        L.append("  --ignore-duplicates: tag/state de-dup is OFF; already-replicated sources WILL be re-scanned")
    return "\n".join(L)
