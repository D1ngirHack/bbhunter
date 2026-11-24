"""Tests de los puntos 'importantes': scope por puerto/ruta/IP, allowlist de
nuclei, dashboard protegido, directorio por programa y recursos empaquetados."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from bbhunter import cli, knowledge, recon, report, scan
from bbhunter import scope as scope_mod
from bbhunter.config import RESOURCES, Settings
from bbhunter.db import DB
from bbhunter.scope import NucleiPolicy, Scope, ScopeRules, load_scope


def S(in_scope, out_of_scope=(), **rules) -> Scope:
    return Scope(program="t", in_scope=list(in_scope), out_of_scope=list(out_of_scope),
                 rules=ScopeRules(**rules))


# ------------------------------------------------------------------ scope v2
def test_wildcard_excludes_apex_by_default():
    s = S(["*.ejemplo.com"])
    assert s.is_allowed("https://www.ejemplo.com")
    assert not s.is_allowed("https://ejemplo.com")
    assert "wildcard_includes_apex" in s.reason("https://ejemplo.com")
    assert S(["*.ejemplo.com"], wildcard_includes_apex=True).is_allowed("https://ejemplo.com")


def test_port_restricted_pattern():
    s = S(["app.ejemplo.com:8443"])
    assert s.is_allowed("https://app.ejemplo.com:8443/x")
    assert not s.is_allowed("https://app.ejemplo.com/x")        # 443
    assert not s.is_allowed("http://app.ejemplo.com:8080")
    assert not s.is_allowed("app.ejemplo.com")                  # puerto desconocido
    assert "solo esta autorizado con limites" in s.reason("https://app.ejemplo.com")


def test_path_restricted_pattern_and_traversal():
    s = S(["https://app.ejemplo.com/portal/"])
    assert s.is_allowed("https://app.ejemplo.com/portal")
    assert s.is_allowed("https://app.ejemplo.com/portal/login?x=1")
    assert not s.is_allowed("https://app.ejemplo.com/portalx")
    assert not s.is_allowed("https://app.ejemplo.com/admin")
    assert not s.is_allowed("https://app.ejemplo.com/portal/../admin")
    assert not s.is_allowed("https://app.ejemplo.com/portal/%2e%2e/admin")
    assert not s.is_allowed("http://app.ejemplo.com/portal/")    # el esquema fija el puerto 443
    assert s.has_path_patterns() and s.has_restricted_patterns()


def test_out_of_scope_path_only_excludes_that_path():
    s = S(["app.ejemplo.com"], ["https://app.ejemplo.com/admin"])
    assert s.is_allowed("https://app.ejemplo.com/")
    assert not s.is_allowed("https://app.ejemplo.com/admin/users")
    assert s.host_candidate("app.ejemplo.com")   # la exclusion por ruta no quita el host


def test_ip_and_cidr_patterns_never_resolve_hostnames():
    s = S(["203.0.113.0/24", "198.51.100.7", "[2001:db8::1]:8080"])
    assert s.is_allowed("http://203.0.113.55/")
    assert not s.is_allowed("http://203.0.114.1/")
    assert s.is_allowed("198.51.100.7")
    assert s.is_allowed("http://[2001:db8::1]:8080/")
    assert not s.is_allowed("http://[2001:db8::1]/")
    assert not s.is_allowed("https://host-que-resuelve-a-esa-ip.example")
    assert "no se resuelve DNS" in s.reason("https://otro.example")
    assert s.seed_domains() == []
    assert s.seed_ips() == ["198.51.100.7", "2001:db8::1"]   # el /24 no se expande
    assert s.host_candidate("2001:db8::1")
    assert s.probe_targets("2001:db8::1") == ["[2001:db8::1]:8080"]
    assert s.is_allowed("https://[2001:db8::1]:8080")


def test_out_of_scope_cidr():
    s = S(["10.0.0.0/16"], ["10.0.5.0/24"])
    assert s.is_allowed("10.0.4.1")
    assert not s.is_allowed("10.0.5.9")


@pytest.mark.parametrize("bad", ["*.", "a.*.ejemplo.com", "http://", "*.10.0.0.1", "host:99999"])
def test_invalid_patterns_rejected(bad):
    with pytest.raises(ValidationError):
        S([bad])


def test_probe_targets_follow_pattern_limits():
    s = S(["*.ejemplo.com", "pay.ejemplo.com:8443", "https://app.ejemplo.com/portal/"])
    assert s.probe_targets("www.ejemplo.com") == ["www.ejemplo.com"]
    assert s.probe_targets("pay.ejemplo.com") == ["pay.ejemplo.com", "pay.ejemplo.com:8443"]
    assert "https://app.ejemplo.com/portal/" in s.probe_targets("app.ejemplo.com")
    only_path = S(["https://app.ejemplo.com/portal/"])
    assert only_path.probe_targets("app.ejemplo.com") == ["https://app.ejemplo.com/portal/"]


def test_recon_dry_run_respects_ports_and_paths():
    s = S(["https://app.ejemplo.com/portal/", "pay.ejemplo.com:8443"])
    live = recon.probe_live(["app.ejemplo.com", "pay.ejemplo.com"], s, Settings(dry_run=True))
    urls = sorted(r["url"] for r in live)
    assert urls == ["https://app.ejemplo.com/portal/", "https://pay.ejemplo.com:8443"]
    assert all(s.is_allowed(u) for u in urls)


def test_seed_domains_strip_ports_paths_and_wildcards():
    s = S(["*.a.com", "b.com:8443", "https://c.com/x/", "10.0.0.1"])
    assert s.seed_domains() == ["a.com", "b.com", "c.com"]


# ------------------------------------------------------------- nuclei policy
def test_nuclei_policy_args_default_blocks_interactsh_and_intrusive():
    args = NucleiPolicy().args()
    assert "-no-interactsh" in args
    assert args[args.index("-etags") + 1].split(",")[:3] == ["dos", "fuzz", "intrusive"]
    assert args[args.index("-severity") + 1] == "low,medium,high,critical"
    assert "-t" not in args and not NucleiPolicy().is_allowlist()


def test_nuclei_allowlist_args():
    p = NucleiPolicy(templates=["http/exposures/configs/"], template_ids=["git-config", "env-file"],
                     tags=["exposure"], allow_interactsh=True)
    args = p.args()
    assert args[:2] == ["-t", "http/exposures/configs/"]
    assert ["-id", "git-config,env-file"] == args[2:4]
    assert "-tags" in args and "-no-interactsh" not in args and p.is_allowlist()


@pytest.mark.parametrize("bad", ["-u", "a b", "../../etc", "x;rm", ""])
def test_nuclei_policy_rejects_argument_injection(bad):
    with pytest.raises(ValidationError):
        NucleiPolicy(templates=[bad])


def test_nuclei_policy_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        NucleiPolicy(severity=["urgent"])


@pytest.fixture
def fake_nuclei(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, timeout=1800, input_text=None):
        calls.append(cmd)
        return 0, "", ""

    monkeypatch.setattr(scan.tools, "tool_available", lambda b: True)
    monkeypatch.setattr(scan.tools, "run", fake_run)
    db = DB(tmp_path / "t.sqlite")
    yield calls, db
    db.close()


def test_scan_passes_nuclei_policy(fake_nuclei):
    calls, db = fake_nuclei
    s = Scope(program="t", in_scope=["app.ejemplo.com"],
              nuclei=NucleiPolicy(template_ids=["git-config"]))
    scan.run_nuclei(db, s, Settings(), ["https://app.ejemplo.com"])
    cmd = calls[0]
    assert cmd[cmd.index("-id") + 1] == "git-config"
    assert "-no-interactsh" in cmd


def test_scan_skips_nuclei_for_path_scope_without_allowlist(fake_nuclei, _audit_to_tmp):
    calls, db = fake_nuclei
    s = Scope(program="t", in_scope=["https://app.ejemplo.com/portal/"])
    assert scan.run_nuclei(db, s, Settings(), ["https://app.ejemplo.com/portal/"]) == 0
    assert calls == []
    entry = json.loads(_audit_to_tmp.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["event"] == "tool_skipped" and "allowlist" in entry["reason"]
    s2 = s.model_copy(update={"nuclei": NucleiPolicy(tags=["exposure"])})
    scan.run_nuclei(db, s2, Settings(), ["https://app.ejemplo.com/portal/"])
    assert len(calls) == 1


# ------------------------------------------------------------------ dashboard
@pytest.fixture
def client(tmp_path, monkeypatch):
    from bbhunter.dashboard import app as dash

    db_path = tmp_path / "d.sqlite"
    st = Settings(db_path=str(db_path), reports_dir=str(tmp_path / "rep"))
    sc = Scope(program="t", in_scope=["ejemplo.com"])
    monkeypatch.setattr(dash, "_ctx", lambda: (st, sc, DB(db_path)))
    db = DB(db_path)
    db.insert_finding("t", "h1", name="X", vuln_class="exposure", url="https://ejemplo.com/.env",
                      status="new", evidence={}, refs=[])
    db.insert_finding("otro", "h2", name="Y", vuln_class="exposure", url="https://otro.com",
                      status="new", evidence={}, refs=[])
    db.close()
    c = TestClient(dash.app, base_url="http://127.0.0.1:8000")
    return c, dash, db_path


def _status(db_path, fid):
    db = DB(db_path)
    try:
        return db.finding(fid)["status"]
    finally:
        db.close()


ORIGIN = {"Origin": "http://127.0.0.1:8000"}


def test_dashboard_rejects_foreign_host(client):
    c, _, _ = client
    assert c.get("/", headers={"Host": "attacker.example"}).status_code == 403
    r = c.get("/")
    assert r.status_code == 200
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_dashboard_post_requires_csrf_and_origin(client):
    c, dash, db_path = client
    ok = {"status": "validated", "csrf": dash.CSRF_TOKEN}
    # sin token
    assert c.post("/finding/1/status", data={"status": "validated"}, headers=ORIGIN).status_code == 403
    # token correcto pero desde otra web
    r = c.post("/finding/1/status", data=ok, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    # sin Origin ni Referer
    assert c.post("/finding/1/status", data=ok).status_code == 403
    assert _status(db_path, 1) == "new"
    r = c.post("/finding/1/status", data=ok, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and _status(db_path, 1) == "validated"


def test_dashboard_page_embeds_token_and_hides_other_programs(client):
    c, dash, db_path = client
    assert dash.CSRF_TOKEN in c.get("/finding/1").text
    assert c.get("/finding/2").status_code == 404
    c.post("/finding/2/status", data={"status": "ready", "csrf": dash.CSRF_TOKEN}, headers=ORIGIN)
    assert _status(db_path, 2) == "new"


def test_dashboard_report_requires_csrf(client, tmp_path):
    c, dash, _ = client
    assert c.post("/finding/1/report", headers=ORIGIN).status_code == 403
    r = c.post("/finding/1/report", data={"csrf": dash.CSRF_TOKEN}, headers=ORIGIN,
               follow_redirects=False)
    assert r.status_code == 303
    assert list((tmp_path / "rep").rglob("*.html"))


def test_dashboard_extra_host_only_when_configured(monkeypatch):
    from bbhunter.dashboard import app as dash

    monkeypatch.setenv("BBHUNTER_DASHBOARD_HOST", "0.0.0.0")
    assert "0.0.0.0" not in dash.allowed_hosts()
    monkeypatch.setenv("BBHUNTER_DASHBOARD_HOST", "192.168.1.20")
    assert "192.168.1.20" in dash.allowed_hosts()


# ------------------------------------------------------------------ programas
@pytest.fixture
def home(tmp_path, monkeypatch):
    for mod in (scope_mod, cli):
        monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(Settings, "abs_db_path", lambda self: tmp_path / "data" / "db.sqlite")
    monkeypatch.delenv("BBHUNTER_PROGRAM", raising=False)
    cli._STATE["program"] = None
    yield tmp_path
    cli._STATE["program"] = None


runner = CliRunner()


def test_init_program_and_use_it(home):
    r = runner.invoke(cli.app, ["init", "--program", "acme"])
    assert r.exit_code == 0, r.output
    path = home / "programs" / "acme" / "scope.yaml"
    assert path.exists() and 'program: "acme"' in path.read_text(encoding="utf-8")
    assert (home / "config" / "settings.yaml").exists()
    assert load_scope(program="acme").program == "acme"
    r = runner.invoke(cli.app, ["programs"])
    assert "acme" in r.output
    r = runner.invoke(cli.app, ["-p", "acme", "scope-check", "https://api.ejemplo.com"])
    assert r.exit_code == 0 and "EN SCOPE" in r.output
    r = runner.invoke(cli.app, ["-p", "acme", "scope-check", "https://evil.example"])
    assert r.exit_code == 1 and "FUERA DE SCOPE" in r.output


def test_program_name_validation_and_mismatch(home):
    assert runner.invoke(cli.app, ["-p", "../etc", "list"]).exit_code == 1
    r = runner.invoke(cli.app, ["-p", "nope", "list"])
    assert r.exit_code == 1 and "init --program nope" in r.output
    d = home / "programs" / "beta"
    d.mkdir(parents=True)
    (d / "scope.yaml").write_text('program: "gamma"\nin_scope: ["a.com"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="no coincide"):
        load_scope(program="beta")


def test_program_settings_override(home):
    runner.invoke(cli.app, ["init", "--program", "acme"])
    (home / "programs" / "acme" / "settings.yaml").write_text("dry_run: true\nllm_enabled: false\n",
                                                             encoding="utf-8")
    cli._STATE["program"] = "acme"
    assert cli._settings().dry_run is True


def test_gate_shows_limits_and_nuclei_policy():
    s = Scope(program="t", in_scope=["*.a.com", "https://b.com/x/", "10.0.0.0/8"],
              nuclei=NucleiPolicy(tags=["exposure"]))
    text = "\n".join(cli._scope_limits(s))
    assert "https://b.com/x/" in text and "10.0.0.0/8" in text
    assert "NO incluyen el apex" in text and "-tags exposure" in text
    assert "interactsh: desactivado" in text


# --------------------------------------------------------------- empaquetado
def test_resources_live_inside_the_package():
    import bbhunter

    pkg = __import__("pathlib").Path(bbhunter.__file__).parent
    assert RESOURCES == pkg / "resources"
    for rel in ("config/scope.example.yaml", "config/settings.example.yaml",
                "knowledge/vuln_kb.yaml", "knowledge/vrt_mapping.yaml",
                "templates/report.md.j2", "templates/report_html.j2"):
        assert (RESOURCES / rel).is_file(), rel
    assert knowledge.vuln_kb()["classes"]
    assert report._env.get_template("report_html.j2")


def test_example_scope_is_valid():
    s = load_scope(RESOURCES / "config" / "scope.example.yaml")
    assert s.in_scope and not s.rules.wildcard_includes_apex
    assert "-no-interactsh" in s.nuclei.args()
