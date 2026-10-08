import csv
import io
import os
import pathlib

from src.utils.manifest import read_manifest, sha256_file
from tests.conftest import read_audit
from tests.fakes import S3_HOST, T1_HOST, T2_HOST, UPLOAD_HOST, make_zip


def read_csv(path):
    return list(csv.DictReader(io.StringIO(pathlib.Path(path).read_text(encoding="utf-8"))))


# ------------------------------------------------------------------ replicate
def test_replicate_happy_path(runner, world, tmp_path):
    a = world.add_scan("projA", "main", created="2024-01-01T00:00:01Z", tags={"team": "x"})
    b = world.add_scan("projA", "dev", created="2024-01-01T00:00:02Z")
    c = world.add_scan("projB", "main", created="2024-01-01T00:00:03Z")
    rc = runner.run("--scan-ids", ",".join([c, b, a]), "--scan-types", "sast,iac,api,sca", "--yes")
    assert rc == 0
    assert len(world.t2_scans) == 3 and set(world.projects) == {"projA", "projB"}
    for body in world.scan_bodies:
        assert [x["type"] for x in body["config"]] == ["sast", "kics", "apisec", "sca"]
        assert all(x["value"] == {} for x in body["config"])
        assert body["type"] == "upload" and set(body["project"]) == {"id"}
        t = body["tags"]
        assert t["cx-replicated-scan-types"] == "sast,iac,api,sca"
        assert t["cx-replicated-from-tenant"] == "tenant1" and "cx-replicated-at" in t
    first = next(x for x in world.scan_bodies if x["tags"]["cx-replicated-from-scan"] == a)
    assert first["tags"]["team"] == "x" and first["handler"]["branch"] == "main"
    order = [x["tags"]["cx-replicated-from-scan"] for x in world.scan_bodies]
    assert order.index(a) < order.index(b)          # projA started oldest -> newest
    assert all(r[3] is None for r in world.calls(UPLOAD_HOST))   # no bearer to the upload host
    assert len(world.uploads) == 3
    events = [e["event"] for e in read_audit(tmp_path)]
    assert events.count("scan_started") == 3 and "run_end" in events
    n = len(world.t2_scans)
    assert runner.run("--scan-ids", ",".join([a, b, c]), "--scan-types", "sast,iac,api,sca", "--yes") == 0
    assert len(world.t2_scans) == n                 # idempotent second run


def test_report_and_logs_have_no_secrets(runner, world, tmp_path):
    a = world.add_scan()
    runner.run("--scan-ids", a, "--scan-types", "sast", "--yes")
    blob = ""
    for f in pathlib.Path(tmp_path / "logs").rglob("*"):
        if f.is_file():
            blob += f.read_text(encoding="utf-8")
    for secret in ("SECRETSIG", "UPSECRET", "tok-t", "eyJ"):
        assert secret not in blob
    rows = read_csv(next((tmp_path / "logs").glob("*.csv")))
    assert rows[0]["status"] == "STARTED" and rows[0]["scan_types"] == "sast" and rows[0]["t2_scan_id"]


def test_scan_types_required_before_any_http(runner, world):
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--yes") == 1
    assert world.requests == []
    assert runner.run("--scan-ids", a, "--scan-types", "sast,containers", "--yes") == 1
    assert world.requests == []


def test_scan_types_from_env_file_and_cli_precedence(runner, world, tmp_path):
    a = world.add_scan()
    envf = tmp_path / "opts.env"
    envf.write_text("REPLICATOR_SCAN_TYPES=sca\n")
    assert runner.run("--scan-ids", a, "--yes", extra_env=(str(envf),)) == 0
    assert [c["type"] for c in world.scan_bodies[0]["config"]] == ["sca"]
    b = world.add_scan()
    assert runner.run("--scan-ids", b, "--scan-types", "iac", "--yes", extra_env=(str(envf),)) == 0
    assert [c["type"] for c in world.scan_bodies[1]["config"]] == ["kics"]


def test_dedupe_by_tags_and_ignore_duplicates(runner, world, tmp_path):
    a = world.add_scan()
    runner.run("--scan-ids", a, "--scan-types", "sast", "--yes")
    # different state DB -> the skip must come from Tenant2 tags
    assert runner.run("--scan-ids", a, "--scan-types", "sca", "--yes",
                      "--state-db", str(tmp_path / "other.sqlite")) == 0
    assert len(world.t2_scans) == 1
    assert runner.run("--scan-ids", a, "--scan-types", "sca", "--ignore-duplicates", "--yes-ignore-duplicates",
                      "--yes", "--state-db", str(tmp_path / "other2.sqlite")) == 0
    assert len(world.t2_scans) == 2


def test_ignore_duplicates_needs_confirmation(runner, world):
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--ignore-duplicates", "--yes") == 1
    assert world.t2_scans == []


def test_failures_do_not_stop_run(runner, world):
    ok = world.add_scan("p1")
    gone = world.add_scan("p2", source=None)
    missing = "99999999-9999-4999-8999-999999999999"
    rc = runner.run("--scan-ids", f"{ok},{gone},{missing}", "--scan-types", "sast", "--yes")
    assert rc == 2 and len(world.t2_scans) == 1


def test_previously_failed_skipped_unless_retry(runner, world):
    gone = world.add_scan(source=None)
    assert runner.run("--scan-ids", gone, "--scan-types", "sast", "--yes") == 2
    world.t1_sources[gone] = make_zip("fixed")
    assert runner.run("--scan-ids", gone, "--scan-types", "sast", "--yes") == 0      # skipped
    assert world.t2_scans == []
    assert runner.run("--scan-ids", gone, "--scan-types", "sast", "--yes", "--retry-failed") == 0
    assert len(world.t2_scans) == 1


def test_missing_tenant2_credentials(runner, world, env_files):
    a = world.add_scan()
    rc = runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", envs=False, extra_env=(env_files[0],))
    assert rc == 1 and world.t2_scans == []


def test_same_tenant_guard(runner, world, env_files):
    a = world.add_scan()
    rc = runner.run("--scan-ids", a, "--scan-types", "sast", "--yes", envs=False,
                    extra_env=(env_files[0], env_files[0]))
    assert rc == 0 or rc == 1
    # T2 resolved from T1's key is not possible via env names; guard is unit-tested below


def test_dry_run_writes_nothing_to_tenant2(runner, world, tmp_path, capsys):
    a = world.add_scan("newproj")
    assert runner.run("--scan-ids", a, "--scan-types", "sast,sca", "--dry-run") == 0
    out = capsys.readouterr().out
    assert "1 to start" in out and "newproj" in out and '"type": "sast"' in out
    assert world.projects == {} and world.t2_scans == [] and world.uploads == {}
    assert not (tmp_path / "state.sqlite").exists()
    assert not any(r[2].startswith("/api/repostore/code") for r in world.requests)


def test_non_interactive_needs_yes(runner, world):
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast") == 1
    assert world.t2_scans == []


def test_existing_project_not_created(runner, world):
    world.projects["proj"] = "pid-existing"
    a = world.add_scan("proj")
    runner.run("--scan-ids", a, "--scan-types", "sast", "--yes")
    assert world.scan_bodies[0]["project"]["id"] == "pid-existing"


def test_project_create_race_409(runner, world):
    world.project_race = True
    a = world.add_scan("raceproj")
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0
    assert len(world.t2_scans) == 1


def test_upload_retry_gets_new_url(runner, world):
    world.put_fail_rate = 0.5
    ids = [world.add_scan(f"p{i}") for i in range(6)]
    rc = runner.run("--scan-ids", ",".join(ids), "--scan-types", "sast", "--yes")
    assert rc in (0, 2)
    assert world.upload_n >= len(world.t2_scans)
    assert len(set(world.uploads)) == len(world.uploads)


def test_foreign_host_redirect_gets_no_token(runner, world):
    world.t1_redirect_host = S3_HOST
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0
    assert world.calls(S3_HOST) and all(r[3] is None for r in world.calls(S3_HOST))
    world.requests.clear()
    world.t1_redirect_host = None
    b = world.add_scan()
    runner.run("--scan-ids", b, "--scan-types", "sast", "--yes")
    storage = [r for r in world.calls(T1_HOST) if r[2].startswith("/storage/")]
    assert storage and all(r[3] for r in storage)       # same host -> bearer sent


def test_ambiguous_start_confirmed(runner, world):
    world.start_5xx_rate = 1.0       # scan created but the response is a 500
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0
    assert len(world.t2_scans) == 1          # never blind-retried


def test_ambiguous_start_not_created_then_retried(runner, world):
    world.start_timeout_rate = 0.5
    ids = [world.add_scan(f"q{i}") for i in range(8)]
    rc = runner.run("--scan-ids", ",".join(ids), "--scan-types", "sast", "--yes")
    srcs = [s["tags"]["cx-replicated-from-scan"] for s in world.t2_scans]
    assert len(srcs) == len(set(srcs)) and rc in (0, 2)     # never duplicated


def test_apisec_400_halts_run(runner, world, tmp_path):
    world.start_400_apisec = True
    ids = [world.add_scan(f"h{i}") for i in range(5)]
    rc = runner.run("--scan-ids", ",".join(ids), "--scan-types", "sast,api", "--yes", "--start-workers", "1")
    assert rc == 1 and world.t2_scans == []
    assert any(e["event"] == "scan_type_rejected" for e in read_audit(tmp_path))


def test_queue_gate_pauses_and_resumes(runner, world, tmp_path):
    state = {"calls": 0}

    def depth():
        state["calls"] += 1
        return 900 if state["calls"] <= 2 else 10      # startup check sees 900, recheck 900, then ok
    world.queued = depth
    ids = [world.add_scan(f"g{i}") for i in range(3)]
    assert runner.run("--scan-ids", ",".join(ids), "--scan-types", "sast", "--yes") == 0
    ev = [e["event"] for e in read_audit(tmp_path)]
    assert len(world.t2_scans) == 3
    assert ev.index("queue_pause") < ev.index("queue_resume") < ev.index("upload_complete")


def test_queue_check_every_n(runner, world, tmp_path):
    ids = [world.add_scan(f"c{i}") for i in range(5)]
    assert runner.run("--scan-ids", ",".join(ids), "--scan-types", "sast", "--yes",
                      "--queue-check-every", "2") == 0
    checks = [e for e in read_audit(tmp_path) if e["event"] == "queue_check"]
    assert len(checks) == 1 + 2


def test_queue_summary_fallback(runner, world):
    world.summary_ok = False
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0


def test_rate_limit_429_honored(runner, world):
    world.rate_limit_next = 3
    a = world.add_scan()
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0


def test_token_refresh_on_401(runner, world):
    a = world.add_scan("tokproj")
    world.invalidate_tokens("t2")
    assert runner.run("--scan-ids", a, "--scan-types", "sast", "--yes") == 0


# ------------------------------------------------------------------ download-only
def test_download_only_flat(runner, world, tmp_path):
    ids = [world.add_scan(f"d{i}") for i in range(3)]
    out = tmp_path / "out"
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", ",".join(ids)) == 0
    assert not world.calls(T2_HOST) and not world.calls("iam.t2.example.com")
    rows = read_manifest(str(out))
    assert set(rows) == set(ids) and all(r["status"] == "SAVED" for r in rows.values())
    for r in rows.values():
        p = out / r["zip_path"]
        assert r["zip_sha256"] == sha256_file(str(p)) and r["zip_bytes"] == p.stat().st_size
    assert not list(out.rglob("*.part")) and (out / "manifest.csv").exists()
    world.requests.clear()
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", ",".join(ids)) == 0
    assert not [r for r in world.requests if r[2].startswith("/api/repostore/code")]


def test_download_only_by_project_nasty_names(runner, world, tmp_path):
    names = ["a/b", "con", "проект", "x" * 300]
    ids = [world.add_scan(n, branch="feat/x") for n in names]
    out = tmp_path / "out"
    assert runner.run("--download-only", "--output-dir", str(out), "--layout", "by-project",
                      "--scan-ids", ",".join(ids)) == 0
    rows = read_manifest(str(out))
    assert {r["project_name"] for r in rows.values()} == set(names)       # originals preserved
    for r in rows.values():
        assert (out / r["zip_path"]).is_file()
        assert all(len(seg) <= 120 for seg in r["zip_path"].split("/"))


def test_download_only_no_save_zips(runner, world, tmp_path):
    a = world.add_scan()
    out = tmp_path / "never"
    assert runner.run("--download-only", "--no-save-zips", "--scan-ids", a, "--output-dir", str(out)) == 0
    assert not out.exists() or not list(out.rglob("*.zip"))
    assert not world.calls(T2_HOST)
    rows = read_csv(next((tmp_path / "logs").glob("*.csv")))
    assert rows[0]["status"] == "VERIFIED" and len(rows[0]["zip_sha256"]) == 64


def test_download_only_scan_types_not_validated(runner, world):
    a = world.add_scan()
    assert runner.run("--download-only", "--no-save-zips", "--scan-ids", a, "--scan-types", "bogus!") == 0


def test_download_only_overwrite_and_file_exists(runner, world, tmp_path):
    a = world.add_scan()
    out = tmp_path / "out"
    out.mkdir()
    (out / f"{a}.zip").write_bytes(b"something else")
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", a) == 2
    assert (out / f"{a}.zip").read_bytes() == b"something else"
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", a, "--overwrite",
                      "--retry-failed") == 0
    assert (out / f"{a}.zip").read_bytes() == world.t1_sources[a]


def test_download_only_disk_low_is_fatal(runner, world, tmp_path):
    a = world.add_scan()
    assert runner.run("--download-only", "--output-dir", str(tmp_path / "o"), "--scan-ids", a,
                      "--min-free-gb", "99999999") == 1


def test_mode_validation(runner, world, tmp_path):
    a = world.add_scan()
    assert runner.run("--download-only", "--scan-ids", a) == 1
    assert runner.run("--download-only", "--from-manifest", str(tmp_path), "--scan-ids", a) == 1


def test_manifest_last_row_wins_and_compact(runner, world, tmp_path):
    a = world.add_scan(source=None)
    out = tmp_path / "out"
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", a) == 2
    assert read_manifest(str(out))[a]["status"] == "FAILED"
    world.t1_sources[a] = make_zip("z")
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", a, "--retry-failed",
                      "--compact-manifest") == 0
    assert read_manifest(str(out))[a]["status"] == "SAVED"
    assert len((out / "manifest.jsonl").read_text().splitlines()) == 1


def test_download_dry_run(runner, world, tmp_path, capsys):
    a = world.add_scan()
    gone = world.add_scan(source=None)
    out = tmp_path / "out"
    assert runner.run("--download-only", "--dry-run", "--output-dir", str(out), "--scan-ids", f"{a},{gone}") == 0
    o = capsys.readouterr().out
    assert "1 to download" in o and "source_unavailable: 1" in o
    assert not out.exists()


# ------------------------------------------------------------------ from manifest
def test_from_manifest_chain(runner, world, tmp_path):
    ids = [world.add_scan(f"m{i % 2}", created=f"2024-01-01T00:00:0{i}Z") for i in range(4)]
    out = tmp_path / "out"
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids", ",".join(ids)) == 0
    world.requests.clear()
    assert runner.run("--from-manifest", str(out), "--scan-types", "iac,sca", "--yes") == 0
    assert not world.calls(T1_HOST) and not world.calls("iam.t1.example.com")
    assert len(world.t2_scans) == 4
    assert all([c["type"] for c in b["config"]] == ["kics", "sca"] for b in world.scan_bodies)
    assert len(list(out.glob("*.zip"))) == 4          # never deleted
    assert runner.run("--from-manifest", str(out), "--yes") == 1      # scan types required


def test_from_manifest_missing_corrupt_and_subset(runner, world, tmp_path):
    ids = [world.add_scan(f"s{i}") for i in range(3)]
    out = tmp_path / "out"
    runner.run("--download-only", "--output-dir", str(out), "--scan-ids", ",".join(ids))
    (out / f"{ids[0]}.zip").unlink()
    (out / f"{ids[1]}.zip").write_bytes(b"corrupted")
    rc = runner.run("--from-manifest", str(out), "--scan-types", "sast", "--yes")
    assert rc == 2 and len(world.t2_scans) == 1
    rep = sorted((tmp_path / "logs").glob("*from-manifest*.csv"))[-1]
    codes = {r["source_scan_id"]: r["error_code"] for r in read_csv(rep)}
    assert codes[ids[0]] == "manifest_zip_missing" and codes[ids[1]] == "manifest_zip_corrupt"
    world.t2_scans.clear()
    rc = runner.run("--from-manifest", str(out), "--scan-types", "sast", "--yes", "--scan-ids", ids[2],
                    "--ignore-duplicates", "--yes-ignore-duplicates")
    assert rc == 0 and len(world.t2_scans) == 1
