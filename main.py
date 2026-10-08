#!/usr/bin/env python3
"""cxone-scan-replicator: re-scan source-tenant code in the target tenant (zip upload), or download only."""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone

from src.model import VERSION, FatalError, Mode, S
from src.operations import inputs, pipeline, preflight
from src.operations.context import RunContext
from src.operations.tenant2 import Tenant2
from src.utils import scan_types as st
from src.utils.audit import Audit, setup_logger
from src.utils.auth import AuthError, AuthManager
from src.utils.config import (apply_option_env, load_env_files, load_tenant_env, preparse_env_files,
                              resolve_tenant, same_tenant)
from src.utils.http import TenantClient
from src.utils.manifest import ManifestWriter, compact_manifest
from src.utils.state import StateDB
from src.utils.ui import StatusUI, Stats


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py", allow_abbrev=False,
        description="Re-scan source-tenant code in the target tenant via zip upload, or download it only.")
    p.add_argument("--env-file", action="append", default=[], metavar="PATH",
                   help="dotenv file (repeatable; later files win). Without it ./.env is loaded if present.")
    p.add_argument("--source-env-file", metavar="PATH",
                   help="Source tenant credentials: CXONE_BASE_URL, CXONE_TENANT, CXONE_API_KEY, "
                        "[CXONE_IAM_URL], [CXONE_DEBUG]")
    p.add_argument("--target-env-file", metavar="PATH",
                   help="Target tenant credentials, same variable names as the source file")
    src = p.add_argument_group("input")
    src.add_argument("--scan-ids", help="comma-separated scan IDs")
    src.add_argument("--scan-ids-file", metavar="PATH|-", help=".txt/.csv/.json file of scan IDs, or - for stdin")
    src.add_argument("--from-manifest", metavar="DIR", help="replicate from a download-only output directory")
    p.add_argument("--scan-types", help="engines to run in the target tenant: any of sast,iac,api,sca. Optional: when omitted, each scan "
                        "runs the supported engines (sast/iac/api/sca) of its original scan")

    d = p.add_argument_group("download-only")
    d.add_argument("--download-only", action="store_true", help="download Source tenant source only; Target tenant is never contacted")
    d.add_argument("--output-dir", metavar="DIR")
    d.add_argument("--layout", choices=["flat", "by-project"], default="flat")
    d.add_argument("--no-save-zips", action="store_true", help="download, checksum and discard")
    d.add_argument("--overwrite", action="store_true")
    d.add_argument("--min-free-gb", type=float, default=5.0)
    d.add_argument("--compact-manifest", action="store_true", help="rewrite the manifest with one row per scan")

    for n, role in (("t1", "source"), ("t2", "target")):
        g = p.add_argument_group(f"{role} tenant")
        for fld in ("base-url", "iam-url", "tenant", "api-key"):
            # --t1-*/--t2-* kept as aliases of --source-*/--target-*
            g.add_argument(f"--{role}-{fld}", f"--{n}-{fld}", dest=f"{n}_{fld.replace('-', '_')}")

    c = p.add_argument_group("concurrency / memory")
    c.add_argument("--download-workers", type=int, default=None)
    c.add_argument("--upload-workers", type=int, default=None)
    c.add_argument("--start-workers", type=int, default=2)
    c.add_argument("--source-max-concurrency", "--t1-max-concurrency", dest="t1_max_concurrency",
                   type=int, default=8)
    c.add_argument("--target-max-concurrency", "--t2-max-concurrency", dest="t2_max_concurrency",
                   type=int, default=8)
    c.add_argument("--metadata-batch", type=int, default=50)
    c.add_argument("--memory-zip-max-mb", type=int, default=256)
    c.add_argument("--memory-budget-mb", type=int, default=2048)
    c.add_argument("--temp-dir")
    c.add_argument("--max-zip-mb", type=int, default=0)
    c.add_argument("--verify-zip", action="store_true")
    c.add_argument("--multipart-threshold-mb", type=int, default=0)
    c.add_argument("--transfer-timeout", type=int, default=900)

    q = p.add_argument_group("tenant2 queue gate")
    q.add_argument("--queue-check-every", type=int, default=100)
    q.add_argument("--queue-max", type=int, default=None)
    q.add_argument("--queue-pause-seconds", type=float, default=300)
    q.add_argument("--queue-count", choices=["queued", "running"], default="queued")

    r = p.add_argument_group("behaviour")
    r.add_argument("--preserve-order", action=argparse.BooleanOptionalAction, default=True)
    r.add_argument("--retry-failed", action="store_true")
    r.add_argument("--ignore-duplicates", action="store_true")
    r.add_argument("--yes-ignore-duplicates", action="store_true")
    r.add_argument("--verify-engines", action="store_true")
    r.add_argument("--force-tenant-defaults", action="store_true")
    r.add_argument("--allow-same-tenant", action="store_true")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--yes", action="store_true")

    o = p.add_argument_group("output")
    o.add_argument("--state-db")
    o.add_argument("--log-dir")
    o.add_argument("--log-file")
    o.add_argument("--audit-file")
    o.add_argument("--report")
    o.add_argument("--no-ui", action="store_true")
    o.add_argument("--quiet", action="store_true")
    o.add_argument("--debug", action="store_true")
    return p


def determine_mode(args) -> Mode:
    if args.download_only and args.from_manifest:
        raise FatalError("--download-only and --from-manifest are mutually exclusive")
    if args.download_only:
        return Mode.DOWNLOAD_ONLY
    if args.from_manifest:
        return Mode.FROM_MANIFEST
    return Mode.REPLICATE


def in_git_tree(path: str) -> bool:
    cur = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent


def _confirm(msg: str) -> bool:
    if not sys.stdin.isatty():
        return False
    return input(msg + " [y/N] ").strip().lower() in ("y", "yes")


def _say(args, msg: str):
    if not args.quiet:
        print(msg, file=sys.stderr)


def main(argv=None, *, session_factory=None, sleep=time.sleep) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):      # never crash on odd project names / legacy codepages
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        return _run(argv, session_factory, sleep)
    except FatalError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return e.code
    except AuthError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _run(argv, session_factory, sleep) -> int:
    env = load_env_files(preparse_env_files(argv))
    args = build_parser().parse_args(argv)
    sources = apply_option_env(args, env)
    for w in env.warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    mode = determine_mode(args)
    notices = []
    if mode != Mode.FROM_MANIFEST and not (args.scan_ids or args.scan_ids_file):
        raise FatalError("provide --scan-ids or --scan-ids-file (or --from-manifest DIR)")
    if mode == Mode.DOWNLOAD_ONLY:
        if not args.output_dir and not args.no_save_zips:
            raise FatalError("--output-dir is required with --download-only (or use --no-save-zips)")
        if args.scan_types:
            notices.append("--scan-types has no effect in --download-only mode")
        if any(getattr(args, f"t2_{f}", None) for f in ("base_url", "iam_url", "tenant", "api_key")):
            notices.append("Target tenant flags are ignored in --download-only mode")
    if mode == Mode.FROM_MANIFEST and any(getattr(args, f"t1_{f}", None)
                                           for f in ("base_url", "iam_url", "tenant", "api_key")):
        notices.append("Source tenant flags are ignored in --from-manifest mode")

    scan_types, config = [], ()
    inherit = mode.uses_t2 and args.scan_types is None      # no --scan-types: use each scan's original engines
    if mode.uses_t2 and not inherit:
        scan_types = st.parse_scan_types(args.scan_types)       # exits 1 before any network call
        config = st.build_config(scan_types)
    args.download_workers = args.download_workers or (8 if mode == Mode.DOWNLOAD_ONLY else 4)

    src_env = load_tenant_env(args.source_env_file) if mode.uses_t1 else None
    tgt_env = load_tenant_env(args.target_env_file) if mode.uses_t2 else None
    if mode == Mode.DOWNLOAD_ONLY and args.target_env_file:
        notices.append("--target-env-file is ignored in --download-only mode")
    if mode == Mode.FROM_MANIFEST and args.source_env_file:
        notices.append("--source-env-file is ignored in --from-manifest mode")
    for e in (src_env, tgt_env):
        if e:
            env.warnings.extend(e.warnings)
            if str(e.get("CXONE_DEBUG")[0] or "").lower() == "true":
                args.debug = True
    t1_cfg = resolve_tenant("T1", args, env, src_env) if mode.uses_t1 else None
    t2_cfg = resolve_tenant("T2", args, env, tgt_env) if mode.uses_t2 else None
    tenant_files = [e.files[0] for e in (src_env, tgt_env) if e]
    if mode == Mode.REPLICATE and same_tenant(t1_cfg, t2_cfg) and not args.allow_same_tenant:
        raise FatalError("Source tenant and Target tenant resolve to the same tenant and base URL; "
                         "pass --allow-same-tenant if that is intended")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
    log_dir = args.log_dir
    base = f"replicator-{mode.value}-{run_id}"
    paths = {"log": args.log_file or os.path.join(log_dir, base + ".log"),
             "audit": args.audit_file or os.path.join(log_dir, base + ".audit.jsonl"),
             "report": args.report or os.path.join(log_dir, base + ".csv")}
    logger = setup_logger(paths["log"], args.debug)
    audit = Audit(paths["audit"], run_id, mode.value, logger)

    # ---- preflight banner
    _say(args, f"Mode: {mode.value}")
    if inherit:
        _say(args, "Scan types: per scan, from the original scan's engines (--scan-types not given)")
    elif mode.uses_t2:
        _say(args, f"Scan types: {','.join(scan_types)} ({st.labels(scan_types)}) [source: {sources['scan_types']}]")
    all_files = env.files + tenant_files
    _say(args, "Env file(s): " + (", ".join(all_files) if all_files else "none"))
    for cfg in (t1_cfg, t2_cfg):
        if cfg:
            _say(args, "  " + cfg.describe())
    for n in notices:
        _say(args, "NOTICE: " + n)
    warnings = st.warnings_for(scan_types) if mode.uses_t2 else []
    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)
        logger.warning(w)

    out_dir = None
    if mode == Mode.DOWNLOAD_ONLY and not args.no_save_zips:
        out_dir = os.path.abspath(args.output_dir)
    elif mode == Mode.FROM_MANIFEST:
        out_dir = os.path.abspath(args.from_manifest)
    if mode == Mode.DOWNLOAD_ONLY and out_dir and in_git_tree(out_dir):
        print("WARNING: output dir is inside a git working tree; the zips contain customer source code",
              file=sys.stderr)

    mk = session_factory or (lambda label: None)
    stats = Stats(mode.value, run_id)
    if not args.dry_run:
        os.makedirs(os.path.dirname(os.path.abspath(args.state_db)), exist_ok=True)
    state = StateDB(args.state_db, readonly=args.dry_run)
    ctx = RunContext(args=args, mode=mode, run_id=run_id, scan_types=scan_types, config=config,
                     inherit_types=inherit,
                     t1_cfg=t1_cfg, t2_cfg=t2_cfg, state=state, audit=audit, logger=logger, stats=stats,
                     out_dir=out_dir, dry_run=args.dry_run, paths=paths, sleep=sleep)
    pool = max(args.download_workers, args.upload_workers, args.start_workers, 8) + 4
    if t1_cfg:
        a1 = AuthManager(t1_cfg.iam_url, t1_cfg.tenant, t1_cfg.api_key, args.debug, http=mk("AUTH"))
        ctx.t1 = TenantClient("T1", t1_cfg.base_url, a1, max_concurrency=args.t1_max_concurrency,
                              pool_size=pool, transfer_timeout=args.transfer_timeout,
                              session=mk("T1"), sleep=sleep)
        a1.ensure_authenticated()
    if t2_cfg:
        a2 = AuthManager(t2_cfg.iam_url, t2_cfg.tenant, t2_cfg.api_key, args.debug, http=mk("AUTH"))
        c2 = TenantClient("T2", t2_cfg.base_url, a2, max_concurrency=args.t2_max_concurrency,
                          pool_size=pool, transfer_timeout=args.transfer_timeout,
                          session=mk("T2"), sleep=sleep)
        a2.ensure_authenticated()
        sast_value = None
        if args.force_tenant_defaults and (inherit or "sast" in scan_types):
            sast_value = Tenant2(c2, ()).tenant_sast_defaults()
            if not inherit:
                ctx.config = st.build_config(scan_types, sast_value)
        ctx.t2 = Tenant2(c2, ctx.config, sleep=sleep, sast_value=sast_value)

    ids, subset = [], None
    if mode == Mode.FROM_MANIFEST:
        if args.scan_ids or args.scan_ids_file:
            rep = inputs.collect_ids(args.scan_ids, args.scan_ids_file)
            subset = rep.ids
            _say(args, rep.summary())
    else:
        rep = inputs.collect_ids(args.scan_ids, args.scan_ids_file)
        ids = rep.ids
        _say(args, rep.summary())
        if rep.invalid:
            print(f"WARNING: {len(rep.invalid)} invalid scan ID(s) ignored, e.g. {rep.invalid[:3]}",
                  file=sys.stderr)
        if not ids:
            raise FatalError("no valid scan IDs supplied")

    audit.event("run_start", mode=mode.value, scan_types=scan_types or "inherit-from-source",
                scan_types_source=sources.get("scan_types"), env_files=all_files,
                sources={c.label: c.sources for c in (t1_cfg, t2_cfg) if c},
                tenants={"t1": t1_cfg.tenant if t1_cfg else None, "t2": t2_cfg.tenant if t2_cfg else None},
                dry_run=args.dry_run, version=VERSION)
    if not args.dry_run:
        safe_args = {k: v for k, v in vars(args).items() if "api_key" not in k}
        state.start_run(run_id, mode.value, scan_types, safe_args, all_files,
                        t1_cfg.tenant if t1_cfg else "", t2_cfg.tenant if t2_cfg else "")

    plan = preflight.build_plan(ctx, ids, subset)
    stats.total = len(plan.jobs)
    stats.header = {"tenants": " -> ".join(c.tenant for c in (t1_cfg, t2_cfg) if c),
                    "scan_types": ("per scan (original engines)" if inherit
                                   else st.labels(scan_types) if scan_types else ""),
                    "env_files": ", ".join(all_files)}
    stats.warnings = warnings

    if args.dry_run:
        preflight.dry_run_checks(ctx, plan)
        if ctx.t2:
            try:
                print(f"Target tenant queue depth now: {ctx.t2.queue_depth(args.queue_count == 'running')} "
                      f"(threshold {args.queue_max})")
            except Exception as e:  # informational only
                print(f"Target tenant queue depth unavailable: {type(e).__name__}")
        print(preflight.format_plan(ctx, plan))
        return 0

    if mode.uses_t2:
        print(preflight.format_plan(ctx, plan))
        if args.ignore_duplicates and not args.yes_ignore_duplicates:
            if not _confirm("--ignore-duplicates will re-scan already-replicated sources. Continue?"):
                raise FatalError("--ignore-duplicates not confirmed (add --yes-ignore-duplicates)")
        if not args.yes and not _confirm("Proceed?"):
            raise FatalError("not confirmed (use --yes for non-interactive runs)")
    if not plan.to_run:
        _say(args, "Nothing to do.")

    if out_dir and mode == Mode.DOWNLOAD_ONLY:
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        ctx.manifest = ManifestWriter(out_dir)
    if args.temp_dir:
        os.makedirs(args.temp_dir, mode=0o700, exist_ok=True)
    if mode == Mode.DOWNLOAD_ONLY and args.no_save_zips:
        ctx.out_dir = None

    pipe = pipeline.Pipeline(ctx, plan)
    ui = StatusUI(stats, enabled=not args.no_ui, quiet=args.quiet, out_dir=out_dir if mode == Mode.DOWNLOAD_ONLY else None)

    def on_sigint(signum, frame):
        ctx.interrupts += 1
        if ctx.interrupts == 1:
            ctx.stop.set()
            print("\nInterrupt: finishing in-flight work (press Ctrl-C again to abort now)...",
                  file=sys.stderr)
        else:
            audit.event("run_end", interrupted=True, aborted=True)
            os._exit(130)

    old = None
    try:
        old = signal.signal(signal.SIGINT, on_sigint)
    except ValueError:
        pass            # not the main thread
    ui.start()
    try:
        result = pipe.run()
    finally:
        ui.stop()
        if old is not None:
            signal.signal(signal.SIGINT, old)

    pipeline.write_report(ctx, plan.jobs)
    counts = {}
    for j in plan.jobs:
        counts[j.status] = counts.get(j.status, 0) + 1
    state.finish_run(run_id, counts)
    audit.event("run_end", counts=counts, interrupted=result.interrupted, halted=result.halted)
    if args.compact_manifest and out_dir and mode == Mode.DOWNLOAD_ONLY:
        compact_manifest(out_dir)
    print(pipeline.format_summary(ctx, result, plan.jobs))
    state.close()

    if result.halted:
        print("ERROR: " + result.halted, file=sys.stderr)
        return 1
    if result.interrupted:
        return 130
    failures = counts.get(S.FAILED, 0)
    if failures:
        print(f"{failures} job(s) failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
