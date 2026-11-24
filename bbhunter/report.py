"""Generacion de informes por hallazgo: Markdown (siempre) + HTML + PDF (opcional)."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape
from rich.console import Console

from . import knowledge
from .config import ROOT, Settings
from .db import DB
from .scope import Scope

console = Console()

def _autoescape(template_name: str | None) -> bool:
    """Escapa toda plantilla HTML (report_html.j2, *.html, *.html.j2). La evidencia
    viene de respuestas de terceros: sin escape, abrir el informe ejecutaria su HTML/JS."""
    name = (template_name or "").lower()
    return name.endswith((".html", ".htm", ".html.j2", "_html.j2"))


def _nl2br(value: object) -> Markup:
    """Escapa el texto y convierte saltos de linea en <br> (seguro con autoescape)."""
    text = "" if value is None else str(value)
    return Markup("<br>\n").join(escape(line) for line in text.split("\n"))


_env = Environment(
    loader=FileSystemLoader(str(ROOT / "templates")),
    autoescape=_autoescape,
    trim_blocks=False,
    lstrip_blocks=False,
)
_env.filters["nl2br"] = _nl2br


def _slug(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return text[:60] or "hallazgo"


def _context(finding: dict, scope: Scope) -> dict:
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {"raw": evidence}
    refs = finding.get("refs") or []
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except json.JSONDecodeError:
            refs = [refs]
    kb = knowledge.kb_for(finding.get("vuln_class", "generic"))
    tier_info = knowledge.tier_info(finding.get("vrt_tier", ""))
    return {
        "f": finding,
        "scope": scope,
        "evidence": evidence,
        "refs": refs,
        "kb": kb,
        "tier_info": tier_info,
        "now": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "llm_source": finding.get("_source", "BBHunter"),
    }


def render_markdown(finding: dict, scope: Scope) -> str:
    return _env.get_template("report.md.j2").render(**_context(finding, scope))


def render_html(finding: dict, scope: Scope) -> str:
    return _env.get_template("report_html.j2").render(**_context(finding, scope))


def write_report(finding: dict, scope: Scope, settings: Settings, pdf: bool = False) -> dict:
    out_dir = settings.abs_reports_dir() / _slug(scope.program)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{finding['id']:03d}-{finding.get('vrt_tier','P5')}-{_slug(finding.get('name',''))}"

    md_path = out_dir / f"{base}.md"
    md_path.write_text(render_markdown(finding, scope), encoding="utf-8")
    result = {"markdown": str(md_path)}

    html = render_html(finding, scope)
    html_path = out_dir / f"{base}.html"
    html_path.write_text(html, encoding="utf-8")
    result["html"] = str(html_path)

    if pdf:
        try:
            from weasyprint import HTML

            pdf_path = out_dir / f"{base}.pdf"
            HTML(string=html).write_pdf(str(pdf_path))
            result["pdf"] = str(pdf_path)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]PDF no generado ({type(exc).__name__}): instala weasyprint.[/yellow]")
    return result


def generate_reports(scope: Scope, settings: Settings, db: DB, status: str | None = None,
                     finding_id: int | None = None, pdf: bool = False) -> list[dict]:
    if finding_id is not None:
        rows = [r for r in [db.finding(finding_id)] if r]
    else:
        rows = db.findings(program=scope.program, status=status)
    outputs = []
    for row in rows:
        out = write_report(row, scope, settings, pdf=pdf)
        outputs.append({"id": row["id"], "name": row.get("name"), **out})
        console.print(f"  Informe #{row['id']} -> [cyan]{out['markdown']}[/cyan]")
    return outputs
