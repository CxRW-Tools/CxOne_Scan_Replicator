import glob
import os
import signal
import threading

import pytest

from src.model import JobFailure, S, ScanJob
from src.operations import tenant1
from src.operations.pipeline import Sequencer
from src.utils.auth import AuthManager
from src.utils.http import AdaptiveLimiter, TenantClient
from src.utils.state import StateDB
from tests.fakes import (T1_HOST, T1_IAM, T2_HOST, T2_IAM, FakeResp, FakeWorld, make_jwt, make_zip)


# ------------------------------------------------------------------ auth / http
def test_auth_thread_safe_single_refresh():
    w = FakeWorld()
    a = AuthManager(f"https://{T1_IAM}", "tenant1", "k", http=w)
    out = []
    ts = [threading.Thread(target=lambda: out.append(a.ensure_authenticated())) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(set(out)) == 1 and w.tok_n == 1


def test_401_refreshes_once_and_retries():
    w = FakeWorld()
    a = AuthManager(f"https://{T2_IAM}", "tenant2", "k", http=w)
    c = TenantClient("T2", f"https://{T2_HOST}", a, session=w, sleep=lambda s: None)
    c.request("GET", "/api/scans/summary")
    w.invalidate_tokens("t2")
    r = c.request("GET", "/api/scans/summary")
    assert r.status_code == 200 and w.tok_n == 2


def test_429_retry_after_and_aimd():
    w = FakeWorld()
    a = AuthManager(f"https://{T2_IAM}", "tenant2", "k", http=w)
    sleeps = []
    c = TenantClient("T2", f"https://{T2_HOST}", a, session=w, sleep=sleeps.append, max_concurrency=8)
    w.rate_limit_next = 4
    r = c.request("GET", "/api/projects", params={"names": "x"})
    assert r.status_code == 200 and len(sleeps) == 4
    assert c.limiter.limit < 8          # shrank after repeated 429s


def test_limiter_aimd_grow_back():
    lim = AdaptiveLimiter(8)
    lim.on_429()
    lim.on_429()
    assert lim.limit == 4
    for _ in range(50):
        lim.on_success()
    assert lim.limit == 5
    for _ in range(50 * 10):
        lim.on_success()
    assert lim.limit == 8


def test_post_not_retried_on_5xx():
    w = FakeWorld()
    a = AuthManager(f"https://{T2_IAM}", "tenant2", "k", http=w)
    c = TenantClient("T2", f"https://{T2_HOST}", a, session=w, sleep=lambda s: None)
    w.start_5xx_rate = 1.0
    body = {"project": {"id": "p"}, "handler": {"uploadUrl": "u"}, "config": [{"type": "sast", "value": {}}],
            "tags": {}}
    import json
    r = c.request("POST", "/api/scans", data=json.dumps(body), retry="post")
    assert r.status_code == 500 and len(w.t2_scans) == 1


# ------------------------------------------------------------------ sinks / memory budget
def test_spool_spills_when_budget_exhausted_and_cleans_up(tmp_path):
    budget = tenant1.MemoryBudget(100)
    s1 = tenant1.SpoolSink(budget, 1000, str(tmp_path))
    s1.write(b"a" * 80)
    assert budget.in_use == 80
    s2 = tenant1.SpoolSink(budget, 1000, str(tmp_path))
    s2.write(b"b" * 80)                         # would exceed the budget -> spill to a temp file
    assert budget.in_use == 80 and s2.path and os.path.exists(s2.path)
    p2 = s2.finish(80, "x")
    assert not p2.in_memory
    p1 = s1.finish(80, "y")
    assert p1.in_memory
    p1.release()
    assert budget.in_use == 0
    p2.release()
    assert not glob.glob(str(tmp_path / "cxrep-*"))


def test_spool_large_content_length_goes_to_disk(tmp_path):
    budget = tenant1.MemoryBudget(10 ** 9)
    s = tenant1.SpoolSink(budget, 10, str(tmp_path))
    s.hint_length(11)
    s.write(b"x" * 11)
    assert s.path and budget.in_use == 0
    s.abort()
    assert not glob.glob(str(tmp_path / "cxrep-*"))


def test_filesink_atomic(tmp_path):
    final = tmp_path / "d" / "a.zip"
    s = tenant1.FileSink(str(final))
    s.write(b"PK")
    assert not final.exists() and (tmp_path / "d" / "a.zip.part").exists()
    s.abort()
    assert not final.exists() and not (tmp_path / "d" / "a.zip.part").exists()
    s = tenant1.FileSink(str(final))
    s.write(b"PK")
    s.finish(2, "h")
    assert final.read_bytes() == b"PK" and not (tmp_path / "d" / "a.zip.part").exists()


def test_download_source_bad_signature_and_retry(tmp_path):
    w = FakeWorld()
    a = AuthManager(f"https://{T1_IAM}", "tenant1", "k", http=w)
    c = TenantClient("T1", f"https://{T1_HOST}", a, session=w, sleep=lambda s: None)
    sid = w.add_scan(source=b"not a zip at all")
    with pytest.raises(JobFailure) as e:
        tenant1.download_source(c, sid, tenant1.NullSink, sleep=lambda s: None)
    assert e.value.code == "bad_zip"
    sid2 = w.add_scan()
    w.dl_5xx_rate = 0.6
    p = tenant1.download_source(c, sid2, tenant1.NullSink, retries=40, sleep=lambda s: None)
    assert p.size == len(w.t1_sources[sid2])


# ------------------------------------------------------------------ sequencer
def mk(sid, proj):
    j = ScanJob(source_scan_id=sid)
    j.seq_key = proj
    return j


def test_sequencer_orders_per_project_and_unblocks_on_failure():
    a1, a2, a3, b1 = mk("a1", "A"), mk("a2", "A"), mk("a3", "A"), mk("b1", "B")
    s = Sequencer([a1, a2, a3, b1], True)
    assert s.ready(a2) == []                    # a1 not ready yet
    assert s.ready(b1) == [b1]                  # other project is independent
    assert s.ready(a3) == []
    assert s.finished(a1) == [a2]               # a1 failed upstream -> a2 released
    assert s.finished(a2) == [a3]
    assert s.finished(a3) == []
    assert Sequencer([a1], False).ready(a1) == [a1]


# ------------------------------------------------------------------ resume
def test_resume_with_different_scan_types(runner, world, tmp_path):
    a = world.add_scan()
    runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", "--max-zip-mb", "0")
    db = StateDB(str(tmp_path / "state.sqlite"))
    db.upsert("replicate", a, status=S.UPLOADED, scan_types="sast", t2_scan_id="")
    db.close()
    world.t2_scans.clear()
    assert runner.run("--scan-ids", a, "--scan-types", "sca,iac", "--yes", "--ignore-duplicates",
                      "--yes-ignore-duplicates") == 0
    assert [c["type"] for c in world.scan_bodies[-1]["config"]] == ["kics", "sca"]
    db = StateDB(str(tmp_path / "state.sqlite"))
    assert db.get("replicate", a)["scan_types"] == "iac,sca"
    db.close()


def test_resume_crash_in_starting_confirms_instead_of_restarting(runner, world, tmp_path):
    a = world.add_scan("crashproj")
    runner.run("--scan-ids", a, "--scan-types", "sast", "--yes")
    assert len(world.t2_scans) == 1
    db = StateDB(str(tmp_path / "state.sqlite"))
    row = db.get("replicate", a)
    db.upsert("replicate", a, status=S.STARTING, t2_scan_id="")       # simulate crash mid-start
    db.close()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", "--ignore-duplicates",
                      "--yes-ignore-duplicates") == 0
    # --ignore-duplicates re-scans by design; without it the tag index prevents any new scan:
    n = len(world.t2_scans)
    db = StateDB(str(tmp_path / "state.sqlite"))
    db.upsert("replicate", a, status=S.STARTING, t2_scan_id="", t2_project_id=row["t2_project_id"])
    db.close()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0
    assert len(world.t2_scans) == n


def test_metadata_batching_50_51(runner, world):
    ids = [world.add_scan(f"b{i}") for i in range(51)]
    runner.run("--download-only", "--no-save-zips", "--scan-ids", ",".join(ids), "--dry-run")
    calls = [r for r in world.calls(T1_HOST) if r[2] == "/api/scans"]
    assert len(calls) == 2
    world.requests.clear()
    runner.run("--download-only", "--no-save-zips", "--scan-ids", ",".join(ids[:50]), "--dry-run")
    assert len([r for r in world.calls(T1_HOST) if r[2] == "/api/scans"]) == 1


def test_max_zip_and_verify_zip(runner, world, tmp_path):
    big = world.add_scan("big", source=make_zip("b", size=2_000_000))
    bad = world.add_scan("bad", source=b"PK\x03\x04" + b"junk" * 50)
    out = tmp_path / "o"
    rc = runner.run("--download-only", "--output-dir", str(out), "--scan-ids", f"{big},{bad}",
                    "--max-zip-mb", "1", "--verify-zip")
    assert rc == 2
    import csv, io, pathlib
    rows = {r["source_scan_id"]: r["error_code"] for r in csv.DictReader(
        io.StringIO(pathlib.Path(next((tmp_path / "logs").glob("*.csv"))).read_text(encoding="utf-8")))}
    assert rows[big] == "too_large" and rows[bad] == "bad_zip"
    assert not list(out.glob("*.zip")) and not list(out.glob("*.part"))


def test_force_tenant_defaults(runner, world):
    a = world.add_scan()
    runner.run("--scan-ids", a, "--scan-types", "sast,sca", "--yes", "--force-tenant-defaults")
    cfg = world.scan_bodies[0]["config"]
    assert cfg[0] == {"type": "sast", "value": {"presetName": "Default", "incremental": "false"}}
    assert cfg[1] == {"type": "sca", "value": {}}


def test_same_tenant_guard(runner, world, tmp_path):
    f = tmp_path / ".env-same"
    key = make_jwt("tenant1", T1_IAM, T1_HOST)
    f.write_text(f"CXONE_T1_API_KEY={key}\nCXONE_T2_API_KEY={key}\n")
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", envs=False, extra_env=(str(f),)) == 1
    assert world.requests == []
    # guard bypassed: the run proceeds (the fake host has no project API, so the job fails with exit 2)
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", "--allow-same-tenant", envs=False,
                      extra_env=(str(f),)) == 2
    assert world.calls(T1_HOST)


# ------------------------------------------------------------------ Ctrl-C resume (every mode)
def _interrupt_on(world, nth, path_prefix, host=None):
    cnt = {"n": 0}

    def hook(method, h, path):
        if path.startswith(path_prefix) and (host is None or h == host):
            cnt["n"] += 1
            if cnt["n"] == nth:
                signal.raise_signal(signal.SIGINT)
    world.hook = hook


def test_ctrl_c_replicate_resume(runner, world):
    ids = [world.add_scan(f"i{i}", created=f"2024-01-01T00:00:{i:02d}Z") for i in range(12)]
    arg = ",".join(ids)
    _interrupt_on(world, 4, "/api/repostore/code/")
    rc = runner.run("--scan-ids", arg, "--scan-types", "sast", "--yes", "--download-workers", "1",
                    "--upload-workers", "1", "--start-workers", "1")
    assert rc == 130 and 0 < len(world.t2_scans) < 12
    world.hook = None
    assert runner.run("--scan-ids", arg, "--scan-types", "sast", "--yes") == 0
    srcs = [s["tags"]["cx-replicated-from-scan"] for s in world.t2_scans]
    assert sorted(srcs) == sorted(ids)


def test_ctrl_c_download_only_resume(runner, world, tmp_path):
    ids = [world.add_scan(f"i{i}") for i in range(10)]
    arg = ",".join(ids)
    out = tmp_path / "o"
    _interrupt_on(world, 3, "/api/repostore/code/")
    rc = runner.run("--download-only", "--output-dir", str(out), "--scan-ids", arg, "--download-workers", "1")
    assert rc == 130 and not list(out.rglob("*.part"))
    world.hook = None
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", arg) == 0
    assert len(list(out.glob("*.zip"))) == 10


def test_ctrl_c_from_manifest_resume(runner, world, tmp_path):
    ids = [world.add_scan(f"i{i}") for i in range(10)]
    out = tmp_path / "o"
    runner.run("--download-only", "--output-dir", str(out), "--scan-ids", ",".join(ids))
    _interrupt_on(world, 3, "/api/uploads", T2_HOST)
    rc = runner.run("--from-manifest", str(out), "--scan-types", "sast", "--yes", "--download-workers", "1",
                    "--upload-workers", "1", "--start-workers", "1")
    assert rc == 130
    world.hook = None
    assert runner.run("--from-manifest", str(out), "--scan-types", "sast", "--yes") == 0
    srcs = [s["tags"]["cx-replicated-from-scan"] for s in world.t2_scans]
    assert sorted(srcs) == sorted(ids) and len(list(out.glob("*.zip"))) == 10
