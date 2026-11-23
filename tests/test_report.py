"""Tests de severidad y de renderizado de informes."""
from bbhunter import knowledge
from bbhunter.report import render_markdown, render_html
from bbhunter.scope import Scope


def test_cvss_grade_high():
    g = knowledge.grade("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert g["cvss_score"] == 7.5
    assert g["severity"] == "High"
    assert g["vrt_tier"] == "P2"


def test_cvss_grade_medium_xss():
    g = knowledge.grade("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert g["severity"] == "Medium"
    assert g["vrt_tier"] == "P3"


def test_classify_tags():
    assert knowledge.classify(["xss", "rxss"]) == "xss_reflected"
    assert knowledge.classify(["exposure", "config"]) == "exposure"
    assert knowledge.classify(["weird-unknown-tag"]) == "generic"


def _sample_finding():
    g = knowledge.grade("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    return {
        "id": 1, "name": "Fichero .env expuesto", "vuln_class": "exposure",
        "url": "https://www.ejemplo.com/.env", "param": "",
        "severity": g["severity"], "cvss_score": g["cvss_score"],
        "cvss_vector": g["cvss_vector"], "vrt_tier": g["vrt_tier"],
        "evidence": {"request": "GET /.env", "response": "DB_PASSWORD=secret"},
        "explanation": "exp", "reproduction": "1. paso", "impact": "imp",
        "remediation": "rem", "refs": ["https://owasp.org"],
    }


def test_render_markdown_contains_key_sections():
    scope = Scope(program="t", in_scope=["ejemplo.com"])
    md = render_markdown(_sample_finding(), scope)
    for section in ("Resumen", "Pasos para reproducir", "Impacto", "Remediación", "CVSS"):
        assert section in md
    assert ".env" in md


def test_render_html_ok():
    scope = Scope(program="t", in_scope=["ejemplo.com"])
    html = render_html(_sample_finding(), scope)
    assert "<html" in html.lower()
    assert "Remediación" in html
