"""Bloqueos de politica (allow_*) y escape del informe HTML. Sin red ni binarios."""
import pytest

from bbhunter import recon, report, scan, tools
from bbhunter.config import Settings
from bbhunter.db import DB
from bbhunter.scope import PhaseNotAllowed, Scope, ScopeRules


def _scope(**rules) -> Scope:
    return Scope(program="p", in_scope=["*.example.test"], rules=ScopeRules(**rules))


@pytest.fixture
def calls(monkeypatch):
    """Registra cada herramienta 'ejecutada'. subfinder devuelve un subdominio."""
    seen: list[str] = []

    def fake_run(cmd, timeout=0, input_text=None):
        seen.append(cmd[0])
        return 0, "www.example.test\n" if cmd[0] == "subfinder" else "", ""

    monkeypatch.setattr(tools, "run", fake_run)
    monkeypatch.setattr(tools, "tool_available", lambda name: True)
    return seen


@pytest.fixture
def db(tmp_path):
    d = DB(tmp_path / "t.sqlite")
    yield d
    d.close()


def test_check_phase_rules():
    _scope().check_phase("recon")
    _scope().check_phase("scan")
    _scope(allow_active_scan=False).check_phase("recon")
    with pytest.raises(PhaseNotAllowed):
        _scope(allow_active_scan=False).check_phase("scan")
    for phase in ("recon", "scan"):
        with pytest.raises(PhaseNotAllowed):
            _scope(allow_automated_tools=False).check_phase(phase)


def test_no_automated_tools_blocks_everything(calls, db):
    s, st = _scope(allow_automated_tools=False), Settings(dry_run=False)
    with pytest.raises(PhaseNotAllowed):
        recon.run_recon(s, st, db)
    with pytest.raises(PhaseNotAllowed):
        scan.run_scan(s, st, db)
    assert calls == []


def test_no_active_scan_recon_is_passive(calls, db):
    s, st = _scope(allow_active_scan=False), Settings(dry_run=False)
    assert recon.run_recon(s, st, db) == []
    assert calls == ["subfinder"]  # httpx NO se ejecuta
    assets = db.assets("p")
    assert assets and all(a["source"] == "pasivo-sin-sondeo" for a in assets)
    with pytest.raises(PhaseNotAllowed):
        scan.run_scan(s, st, db)
    assert calls == ["subfinder"]  # ni nuclei ni dalfox


def test_dalfox_respects_active_scan(calls, db):
    n = scan.run_dalfox(db, _scope(allow_active_scan=False), Settings(dry_run=False),
                        ["https://www.example.test/?q=1"])
    assert n == 0 and calls == []


def test_dry_run_still_works_with_restrictive_rules(calls, db):
    s, st = _scope(allow_automated_tools=False), Settings(dry_run=True)
    recon.run_recon(s, st, db)
    assert scan.run_scan(s, st, db) > 0
    assert calls == []


def test_html_report_escapes_untrusted_evidence():
    f = {"id": 1, "name": "<b>n</b>", "vuln_class": "xss_reflected", "url": "https://a.test/",
         "param": "q", "severity": "Medium", "cvss_score": 6.1, "cvss_vector": "", "vrt_tier": "P3",
         "evidence": '{"response": "<script>alert(1)</script>"}', "refs": "[]",
         "explanation": "linea1\n<img src=x onerror=alert(2)>", "reproduction": "",
         "impact": "", "remediation": "", "status": "new"}
    html = report._env.get_template("report_html.j2").render(**report._context(f, Scope()))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html and "<b>n</b>" not in html
    assert "linea1<br>" in html  # los saltos de linea siguen funcionando
    # El Markdown no se escapa (no es HTML)
    assert "<b>n</b>" in report.render_markdown(f, Scope())
