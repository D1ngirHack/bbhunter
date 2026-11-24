"""Fallos visibles, auditoria, enmascarado de secretos y cabeceras/proxy. Sin red ni binarios."""
import json

import pytest
from pydantic import ValidationError

from bbhunter import llm, recon, scan, tools
from bbhunter.audit import Auditor, read_entries
from bbhunter.config import Settings
from bbhunter.db import DB
from bbhunter.redact import redact_obj, redact_text
from bbhunter.scope import Scope, ScopeRules

HEADERS = {"X-Bug-Bounty": "jonay-h1"}


def _scope(**kw) -> Scope:
    return Scope(program="p", in_scope=["*.example.test", "example.test"], rules=ScopeRules(), **kw)


@pytest.fixture
def db(tmp_path):
    d = DB(tmp_path / "t.sqlite")
    yield d
    d.close()


@pytest.fixture
def fake_tools(monkeypatch):
    """Simula binarios. `behaviour[tool] = (code, stdout, stderr)`; registra argv."""
    calls: list[list[str]] = []
    behaviour: dict[str, tuple[int, str, str]] = {}

    def fake_run(cmd, timeout=0, input_text=None):
        calls.append(list(cmd))
        return behaviour.get(cmd[0], (0, "", ""))

    monkeypatch.setattr(tools, "run", fake_run)
    monkeypatch.setattr(tools, "tool_available", lambda name: True)
    return calls, behaviour


# ------------------------------------------------------------------- enmascarado
def test_redact_common_secrets_and_keeps_prefix():
    text = ("DB_PASSWORD=supersecret123\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "Authorization: Bearer abcdefghijklmnop\nurl=https://admin:hunter22@db.local/\n"
            '{"api_key": "sk_test_1234567890"}\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n'
            "-----END RSA PRIVATE KEY-----\nnormal password text")
    out, n = redact_text(text)
    assert n == 6
    for secret in ("supersecret123", "IOSFODNN7EXAMPLE", "abcdefghijklmnop", "hunter22",
                   "1234567890", "MIIabc"):
        assert secret not in out
    assert "supe...[REDACTADO:key_value]" in out
    assert "normal password text" in out          # sin '=' o ':' no se toca
    assert redact_text(out) == (out, 0)            # idempotente


def test_redact_obj_recursive():
    obj, n = redact_obj({"a": ["token=abcdef123456"], "b": {"c": "x"}, "d": 3})
    assert n == 1 and "abcdef123456" not in json.dumps(obj) and obj["d"] == 3


def test_store_redacts_evidence(db):
    s, st = _scope(), Settings(dry_run=True)
    scan._store(db, s, st, "exposure", "env", "t", "https://a.example.test/.env", "",
                {"response": "DB_PASSWORD=supersecret123"})
    ev = json.loads(db.findings("p")[0]["evidence"])
    assert "supersecret123" not in ev["response"] and ev["_redacted_secrets"] == 1


def test_store_can_keep_raw_when_disabled(db):
    s, st = _scope(), Settings(dry_run=True, redact_evidence=False)
    scan._store(db, s, st, "exposure", "env", "t", "https://a.example.test/.env", "",
                {"response": "DB_PASSWORD=supersecret123"})
    assert "supersecret123" in db.findings("p")[0]["evidence"]


def test_llm_evidence_never_raw():
    ev = {"response": "DB_PASSWORD=supersecret123"}
    redacted = llm.evidence_for_prompt(ev, Settings(llm_evidence="redacted"))
    assert "supersecret123" not in redacted and "REDACTADO" in redacted
    none = llm.evidence_for_prompt(ev, Settings(llm_evidence="none"))
    assert "supe" not in none and "omitida" in none


# ---------------------------------------------------------- auditoria y fallos
def test_auditor_logs_success_and_failure(tmp_path, fake_tools):
    _, behaviour = fake_tools
    behaviour["nuclei"] = (1, "", "error: templates not found\ntoken=abcdef123456")
    aud = Auditor(tmp_path / "a.jsonl", "p")
    ok = aud.run("httpx", ["httpx", "-H", "Authorization: Bearer abcdefghijklmnop"],
                 phase="recon", targets=["a.example.test"], rate_limit=5)
    bad = aud.run("nuclei", ["nuclei"], phase="scan", targets=["https://a.example.test"])
    assert ok.ok and not bad.ok
    assert aud.failures == ["nuclei (fase scan, codigo 1)"]
    assert aud.summary("scan") is False
    entries = read_entries(tmp_path / "a.jsonl", last=10)
    assert [e["ok"] for e in entries] == [True, False]
    assert entries[0]["targets"] == ["a.example.test"] and entries[0]["rate_limit_rps"] == 5
    assert "abcdefghijklmnop" not in json.dumps(entries)   # argv enmascarado
    assert "abcdef123456" not in entries[1]["stderr_tail"]  # stderr enmascarado
    assert read_entries(tmp_path / "a.jsonl", failed_only=True)[0]["tool"] == "nuclei"


def test_scan_reports_incomplete_when_tool_fails(db, fake_tools, _audit_to_tmp, capsys):
    _, behaviour = fake_tools
    behaviour["nuclei"] = (2, "", "fatal: could not load templates")
    db.upsert_asset("p", url="https://a.example.test", host="a.example.test", source="httpx")
    assert scan.run_scan(_scope(), Settings(dry_run=False), db) == 0
    out = capsys.readouterr().out
    assert "FALLO" in out and "INCOMPLETO" in out
    failed = read_entries(_audit_to_tmp, failed_only=True)
    assert failed and failed[0]["tool"] == "nuclei" and failed[0]["exit_code"] == 2


def test_missing_tool_is_logged_as_skipped(db, monkeypatch, _audit_to_tmp):
    monkeypatch.setattr(tools, "tool_available", lambda name: False)
    db.upsert_asset("p", url="https://a.example.test", host="a.example.test", source="httpx")
    scan.run_scan(_scope(), Settings(dry_run=False), db)
    skipped = {e["tool"] for e in read_entries(_audit_to_tmp) if e["event"] == "tool_skipped"}
    assert skipped == {"nuclei", "dalfox"}


def test_failed_subfinder_still_continues_with_seeds(db, fake_tools):
    _, behaviour = fake_tools
    behaviour["subfinder"] = (1, "", "rate limited")
    behaviour["httpx"] = (0, json.dumps({"url": "https://example.test", "input": "example.test"}), "")
    live = recon.run_recon(_scope(), Settings(dry_run=False), db)
    assert [a["url"] for a in live] == ["https://example.test"]


# ------------------------------------------------------- cabeceras y proxy
def test_headers_and_proxy_reach_every_target_tool(db, fake_tools):
    calls, behaviour = fake_tools
    behaviour["httpx"] = (0, json.dumps({"url": "https://www.example.test/?q=1",
                                         "input": "www.example.test"}), "")
    s = _scope(request_headers=HEADERS)
    st = Settings(dry_run=False, proxy="http://127.0.0.1:8080")
    recon.run_recon(s, st, db)
    scan.run_scan(s, st, db)
    by_tool = {c[0]: c for c in calls}
    assert set(by_tool) == {"subfinder", "httpx", "nuclei", "dalfox"}
    for tool, proxy_flag in (("httpx", "-http-proxy"), ("nuclei", "-proxy"), ("dalfox", "--proxy")):
        argv = by_tool[tool]
        assert "X-Bug-Bounty: jonay-h1" in argv
        assert argv[argv.index(proxy_flag) + 1] == "http://127.0.0.1:8080"
    # subfinder consulta fuentes pasivas de terceros: ni cabeceras ni proxy
    assert "X-Bug-Bounty: jonay-h1" not in by_tool["subfinder"]


@pytest.mark.parametrize("headers", [
    {"X-Bug-Bounty": "a\r\nInjected: 1"},
    {"Bad Name": "x"},
    {"X-Long": "a" * 600},
])
def test_invalid_headers_rejected(headers):
    with pytest.raises(ValidationError):
        _scope(request_headers=headers)


@pytest.mark.parametrize("proxy", ["127.0.0.1:8080", "ftp://x:1", "http://a b:1", "http://h\r\nX: 1:8080"])
def test_invalid_proxy_rejected(proxy):
    with pytest.raises(ValidationError):
        Settings(proxy=proxy)


def test_valid_proxy_accepted():
    assert Settings(proxy="socks5://127.0.0.1:9050").proxy == "socks5://127.0.0.1:9050"
    assert Settings(proxy=" ").proxy == ""
