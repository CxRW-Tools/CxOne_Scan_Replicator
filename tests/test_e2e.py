"""2,000 fake scans with random failures."""
import csv
import glob
import io
import pathlib
from collections import Counter

from src.operations import tenant1
from tests.fakes import make_zip

N = 2000


def populate(world, n=N, unavailable=0.05, zip_bytes=300_000):
    shared = make_zip("shared", size=zip_bytes)
    ids, bad = [], set()
    for i in range(n):
        proj = f"proj-{i % 150}"
        ok = world.rng.random() >= unavailable
        sid = world.add_scan(proj, "main", created=f"2024-{1 + i // 28 % 12:02d}-{1 + i % 28:02d}T00:00:00Z",
                             source=shared if ok else None)
        ids.append(sid)
        if not ok:
            bad.add(sid)
    return ids, bad


def write_ids(tmp_path, ids):
    p = tmp_path / "ids.txt"
    p.write_text("\n".join(ids))
    return str(p)


def report_counts(tmp_path, pattern):
    rep = sorted((tmp_path / "logs").glob(pattern))[-1]
    rows = list(csv.DictReader(io.StringIO(pathlib.Path(rep).read_text(encoding="utf-8"))))
    return Counter(r["status"] for r in rows), rows


def test_replicate_2000_bounded_memory_and_idempotent(runner, world, tmp_path, monkeypatch):
    ids, bad = populate(world)
    world.dl_5xx_rate = 0.02
    world.put_fail_rate = 0.02
    world.start_5xx_rate = 0.02
    world.start_timeout_rate = 0.02
    budgets = []

    class Tracked(tenant1.MemoryBudget):
        def __init__(self, cap):
            super().__init__(cap)
            budgets.append(self)
    monkeypatch.setattr(tenant1, "MemoryBudget", Tracked)
    temp = tmp_path / "tmp"
    args = ["--scan-ids-file", write_ids(tmp_path, ids), "--scan-types", "sast,sca", "--yes",
            "--memory-budget-mb", "1", "--memory-zip-max-mb", "1", "--temp-dir", str(temp),
            "--download-workers", "6", "--upload-workers", "4", "--start-workers", "3"]
    rc = runner.run(*args)
    counts, rows = report_counts(tmp_path, "*replicate*.csv")
    assert rc == 2 and sum(counts.values()) == N
    assert counts["STARTED"] + counts["FAILED"] == N
    assert counts["FAILED"] >= len(bad)
    # every request had exactly the two selected engines; no source scanned twice
    assert all([c["type"] for c in b["config"]] == ["sast", "sca"] for b in world.scan_bodies)
    srcs = [s["tags"]["cx-replicated-from-scan"] for s in world.t2_scans]
    assert len(srcs) == len(set(srcs))
    assert counts["STARTED"] <= len(world.t2_scans) <= counts["STARTED"] + 40
    # memory stayed within the budget; temp files all removed
    assert budgets and budgets[0].peak <= budgets[0].capacity
    assert not glob.glob(str(temp / "cxrep-*"))
    # idempotent: second run starts nothing new
    n = len(world.t2_scans)
    world.dl_5xx_rate = world.put_fail_rate = world.start_5xx_rate = world.start_timeout_rate = 0
    runner.run(*args)
    assert len(world.t2_scans) == n


def test_chain_matches_direct_replicate(runner, world, tmp_path):
    ids, bad = populate(world, zip_bytes=2000)
    world.dl_5xx_rate = 0.03
    ids_file = write_ids(tmp_path, ids)
    out = tmp_path / "export"
    assert runner.run("--download-only", "--output-dir", str(out), "--scan-ids-file", ids_file) == 2
    dl_counts, _ = report_counts(tmp_path, "*download-only*.csv")
    assert dl_counts["SAVED"] == N - len(bad) and dl_counts["FAILED"] == len(bad)
    assert runner.run("--from-manifest", str(out), "--scan-types", "iac,sca", "--yes",
                      "--state-db", str(tmp_path / "manifest.sqlite")) == 2
    chain_counts, _ = report_counts(tmp_path, "*from-manifest*.csv")
    started_chain = len(world.t2_scans)
    # direct replicate into a "fresh" Tenant2 (new world state)
    world.t2_scans.clear()
    world.projects.clear()
    world.scan_bodies.clear()
    assert runner.run("--scan-ids-file", ids_file, "--scan-types", "iac,sca", "--yes",
                      "--state-db", str(tmp_path / "direct.sqlite")) == 2
    direct_counts, _ = report_counts(tmp_path, "*replicate*.csv")
    assert chain_counts["STARTED"] == direct_counts["STARTED"] == started_chain == N - len(bad)
    assert chain_counts["FAILED"] == direct_counts["FAILED"] == len(bad)
