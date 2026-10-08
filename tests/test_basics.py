import json

import pytest

from src.model import FatalError
from src.operations import inputs
from src.utils import scan_types as st
from src.utils.config import (EnvSources, apply_option_env, load_env_files, preparse_env_files,
                              resolve_tenant)
from src.utils.http import redact_text, redact_url
from src.utils.manifest import sanitize_segment, zip_relpath
from tests.conftest import read_audit
from tests.fakes import T1_HOST, T1_IAM, make_jwt


# ------------------------------------------------------------------ scan types
@pytest.mark.parametrize("raw,expected", [
    ("sast", ["sast"]), ("SAST , Sca", ["sast", "sca"]), ("sca,SAST", ["sast", "sca"]),
    ("kics", ["iac"]), ("iac,kics", ["iac"]), ("apisec", ["api"]), ("api,iac,sca,sast", ["sast", "iac", "api", "sca"]),
    ("sast,,sca,", ["sast", "sca"]),
])
def test_parse_ok(raw, expected):
    assert st.parse_scan_types(raw) == expected


def test_aliases_map_to_api_names():
    cfg = st.config_payload(st.build_config(st.parse_scan_types("sast,iac,api,sca")))
    assert cfg == [{"type": "sast", "value": {}}, {"type": "kics", "value": {}},
                   {"type": "apisec", "value": {}}, {"type": "sca", "value": {}}]
    cfg = st.config_payload(st.build_config(["sast", "sca"]))
    assert [c["type"] for c in cfg] == ["sast", "sca"]


@pytest.mark.parametrize("bad", [None, "", " ", ",", ", ,"])
def test_missing_or_empty(bad):
    with pytest.raises(FatalError):
        st.parse_scan_types(bad)


def test_missing_message_exact():
    with pytest.raises(FatalError) as e:
        st.parse_scan_types(None)
    assert str(e.value) == ("--scan-types is required (choose from: sast, iac, api, sca), "
                            "e.g. --scan-types sast,iac,api,sca")


@pytest.mark.parametrize("bad", ["containers", "secrets", "microengines", "fusion", "2ms", "aisc", "cisec",
                                 "scorecard", "container"])
def test_disallowed(bad):
    with pytest.raises(FatalError) as e:
        st.parse_scan_types("sast," + bad)
    assert f"'{bad}' is not supported by this tool; allowed: sast, iac, api, sca" in str(e.value)


def test_unknown():
    with pytest.raises(FatalError) as e:
        st.parse_scan_types("sast,bogus")
    assert "bogus" in str(e.value) and "sast, iac, api, sca" in str(e.value)


def test_api_without_sast_warning_and_tag():
    assert st.warnings_for(["api", "sca"]) and not st.warnings_for(["sast", "api"])
    assert st.tag_value(["sast", "iac"]) == "sast,iac"


def test_config_never_empty():
    with pytest.raises(FatalError):
        st.build_config([])


# ------------------------------------------------------------------ env files / config
def test_env_precedence(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_text("CXONE_T1_TENANT=from-a\nCXONE_T1_BASE_URL=https://a.example\nCXONE_T1_IAM_URL=https://iam.a\n"
                 "CXONE_T1_API_KEY=k\nREPLICATOR_SCAN_TYPES=sast\n")
    b.write_text("CXONE_T1_TENANT=from-b\nREPLICATOR_SCAN_TYPES=iac\n")

    class A:
        t1_base_url = t1_iam_url = t1_api_key = None
        t1_tenant = None
        scan_types = None
        output_dir = state_db = log_dir = download_workers = upload_workers = queue_max = None

    env = load_env_files([str(a), str(b)], environ={"CXONE_T1_TENANT": "from-process"})
    cfg = resolve_tenant("T1", A, env)
    assert cfg.tenant == "from-b" and cfg.sources["tenant"] == f"env-file:{b}"      # later file wins
    A.t1_tenant = "cli"
    assert resolve_tenant("T1", A, env).tenant == "cli"                              # CLI wins
    A.t1_tenant = None
    env2 = load_env_files([str(a)], environ={"CXONE_T1_TENANT": "from-process"})
    assert resolve_tenant("T1", A, env2).tenant == "from-a"                          # file beats process env
    env3 = load_env_files([str(tmp_path / "a")], environ={})
    assert env3.get("REPLICATOR_SCAN_TYPES")[0] == "sast"
    A.scan_types = "sca"
    srcs = apply_option_env(A, env)
    assert A.scan_types == "sca" and srcs["scan_types"] == "cli"


def test_process_env_fallback_and_secret_not_in_describe(tmp_path):
    class A:
        t1_base_url = t1_iam_url = t1_tenant = t1_api_key = None
    env = EnvSources(environ={"CXONE_T1_API_KEY": make_jwt("tn", T1_IAM, T1_HOST)})
    cfg = resolve_tenant("T1", A, env)
    assert (cfg.tenant, cfg.sources["tenant"]) == ("tn", "jwt")
    assert cfg.base_url == f"https://{T1_HOST}" and cfg.iam_url == f"https://{T1_IAM}"
    assert cfg.api_key not in cfg.describe() and "api_key=***" in cfg.describe()


def test_missing_env_file_fatal(tmp_path):
    with pytest.raises(FatalError) as e:
        load_env_files([str(tmp_path / "nope")])
    assert "nope" in str(e.value)


def test_dotenv_default_only_without_env_file(tmp_path):
    (tmp_path / ".env").write_text("X=1\n")
    assert load_env_files([], cwd=str(tmp_path), environ={}).get("X")[0] == "1"
    other = tmp_path / "other"
    other.write_text("Y=2\n")
    env = load_env_files([str(other)], cwd=str(tmp_path), environ={})
    assert env.get("X") == (None, None) and env.get("Y")[0] == "2"


def test_preparse_env_files():
    assert preparse_env_files(["--env-file", "a", "--scan-ids", "x", "--env-file", "b"]) == ["a", "b"]


# ------------------------------------------------------------------ inputs
def test_ids_formats(tmp_path):
    a, b, c = ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
               "33333333-3333-4333-8333-333333333333")
    (tmp_path / "i.txt").write_text(f"# c\n{a}\n\n{b} # trailing\n{a}\nnot-an-id\n")
    r = inputs.collect_ids(None, str(tmp_path / "i.txt"))
    assert r.ids == [a, b] and r.given == 4 and r.invalid == ["not-an-id"] and r.unique == 2
    (tmp_path / "i.csv").write_text(f"name,scanId\nx,{c}\ny,{a}\n")
    assert inputs.collect_ids(None, str(tmp_path / "i.csv")).ids == [c, a]
    (tmp_path / "j.csv").write_text(f"{a}\n{b}\n")
    assert inputs.collect_ids(None, str(tmp_path / "j.csv")).ids == [a, b]
    (tmp_path / "i.json").write_text(json.dumps([{"id": a}, {"scanId": b}, c]))
    assert inputs.collect_ids(None, str(tmp_path / "i.json")).ids == [a, b, c]
    assert inputs.collect_ids(f"{a},{b}", None).ids == [a, b]


def test_ids_stdin(monkeypatch):
    import io
    a = "11111111-1111-4111-8111-111111111111"
    monkeypatch.setattr("sys.stdin", io.StringIO(a + "\n"))
    assert inputs.collect_ids(None, "-").ids == [a]


# ------------------------------------------------------------------ redaction
def test_redaction():
    assert redact_url("https://h.example/put/1?X-Amz-Signature=SECRET&a=b") == "https://h.example/put/1"
    s = redact_text("GET https://h/x?X-Amz-Signature=SECRET failed; Authorization: Bearer abc.def.ghi "
                    "refresh_token=RTOKEN eyJhbGciOi12345.eyJzdWIiOiJ4In0.sigsig")
    for secret in ("SECRET", "abc.def.ghi", "RTOKEN", "eyJhbGciOi12345"):
        assert secret not in s


# ------------------------------------------------------------------ manifest paths
def test_sanitize_segments():
    assert sanitize_segment("plain") == "plain"
    a = sanitize_segment("a/b")
    assert "/" not in a and a != sanitize_segment("a_b") and len(a) <= 120
    assert sanitize_segment("con").upper().startswith("_CON")
    long = sanitize_segment("x" * 300)
    assert len(long) <= 120
    assert sanitize_segment("x" * 300) == long and sanitize_segment("x" * 299 + "y") != long
    assert sanitize_segment("проект-é") == "проект-é"
    assert zip_relpath("id", "a/b", "feat/x", "by-project").count("/") == 2
    assert zip_relpath("id", "p", "b", "flat") == "id.zip"


def test_iam_url_derived_from_base_url_before_jwt():
    class A:
        t1_base_url = "https://ast.checkmarx.net"
        t1_iam_url = t1_api_key = t1_tenant = None
    A.t1_api_key = make_jwt("rw_demo", "deu.iam.checkmarx.net", "deu.ast.checkmarx.net")
    cfg = resolve_tenant("T1", A, EnvSources(environ={}))
    assert cfg.iam_url == "https://iam.checkmarx.net" and cfg.sources["iam_url"] == "derived-from-base-url"
    assert cfg.tenant == "rw_demo" and cfg.base_url == "https://ast.checkmarx.net"
    A.t1_iam_url = "https://custom.iam.example"
    assert resolve_tenant("T1", A, EnvSources(environ={})).iam_url == "https://custom.iam.example"


def test_jwt_validation():
    import time as _t
    from tests.fakes import make_jwt as mj

    class A:
        t1_base_url = "https://ast.checkmarx.net"
        t1_iam_url = t1_tenant = t1_api_key = None
    A.t1_api_key = mj("rw_demo", "deu.iam.checkmarx.net", "deu.ast.checkmarx.net")
    A.t1_tenant = "someone_else"
    with pytest.raises(FatalError) as e:                       # key belongs to another tenant
        resolve_tenant("T1", A, EnvSources(environ={}))
    assert "does not match" in str(e.value)
    A.t1_tenant = "RW_Demo"                                    # case-insensitive match; region differs -> warnings
    cfg = resolve_tenant("T1", A, EnvSources(environ={}))
    assert any("issuer" in w for w in cfg.warnings) and any("base URL host" in w for w in cfg.warnings)
    A.t1_base_url = "https://deu.ast.checkmarx.net"            # consistent -> clean
    assert resolve_tenant("T1", A, EnvSources(environ={})).warnings == []
    import base64, json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    A.t1_api_key = f"{b64({'a': 1})}.{b64({'iss': 'https://x/auth/realms/rw_demo', 'exp': int(_t.time()) - 5})}.s"
    with pytest.raises(FatalError) as e:
        resolve_tenant("T1", A, EnvSources(environ={}))
    assert "expired" in str(e.value)
