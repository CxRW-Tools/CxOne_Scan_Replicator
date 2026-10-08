import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fakes import (T1_HOST, T1_IAM, T2_HOST, T2_IAM, FakeWorld, make_jwt)  # noqa: E402

import main as cli  # noqa: E402


@pytest.fixture
def world():
    return FakeWorld()


@pytest.fixture
def env_files(tmp_path):
    t1 = tmp_path / ".env-t1"
    t2 = tmp_path / ".env-t2"
    t1.write_text(f"CXONE_T1_API_KEY={make_jwt('tenant1', T1_IAM, T1_HOST)}\n")
    t2.write_text(f"CXONE_T2_API_KEY={make_jwt('tenant2', T2_IAM, T2_HOST)}\n")
    return str(t1), str(t2)


class Runner:
    def __init__(self, world, tmp_path, env_files):
        self.world, self.tmp, self.env = world, tmp_path, env_files

    def run(self, *args, envs=True, extra_env=()):
        argv = []
        for e in ((*self.env, *extra_env) if envs else extra_env):
            argv += ["--env-file", e]
        argv += ["--state-db", str(self.tmp / "state.sqlite"), "--log-dir", str(self.tmp / "logs"),
                 "--no-ui", "--quiet", "--queue-pause-seconds", "0.2"]
        argv += list(args)
        return cli.main(argv, session_factory=lambda label: self.world, sleep=lambda s: None)


@pytest.fixture
def runner(world, tmp_path, env_files):
    return Runner(world, tmp_path, env_files)


def read_audit(tmp_path):
    import glob
    import json
    out = []
    for f in sorted(glob.glob(str(tmp_path / "logs" / "*.audit.jsonl"))):
        with open(f, encoding="utf-8") as fh:
            out += [json.loads(line) for line in fh if line.strip()]
    return out
