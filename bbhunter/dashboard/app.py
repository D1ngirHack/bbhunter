"""Dashboard web local (FastAPI) para triar hallazgos y exportar informes.

Solo escucha en localhost por defecto. No expone ninguna accion de escaneo ni de
envio a plataformas: sirve para revisar, validar y generar informes.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import ROOT, load_settings
from .. import references
from ..db import DB
from ..report import render_markdown, write_report
from ..scope import load_scope

app = FastAPI(title="BBHunter Dashboard")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

STATUSES = ["new", "validated", "false_positive", "duplicate", "ready", "reported"]


def _ctx():
    settings = load_settings()
    scope = load_scope()
    db = DB(settings.abs_db_path())
    return settings, scope, db


@app.get("/", response_class=HTMLResponse)
def index(request: Request, status: str | None = None):
    settings, scope, db = _ctx()
    rows = db.findings(program=scope.program, status=status)
    counts = {s: len(db.findings(program=scope.program, status=s)) for s in STATUSES}
    db.close()
    return templates.TemplateResponse(request, "index.html", {
        "rows": rows, "scope": scope,
        "statuses": STATUSES, "counts": counts, "active": status,
    })


@app.get("/finding/{fid}", response_class=HTMLResponse)
def finding_detail(request: Request, fid: int):
    settings, scope, db = _ctx()
    f = db.finding(fid)
    related = references.for_finding(db.conn, f, limit=6) if f else {}
    db.close()
    if not f:
        return HTMLResponse("Hallazgo no encontrado", status_code=404)
    bounty = references.bounty_summary(related.get("hackerone", []))
    evidence = f.get("evidence") or "{}"
    try:
        evidence = json.dumps(json.loads(evidence), indent=2, ensure_ascii=False)
    except Exception:
        pass
    markdown = render_markdown(f, scope)
    return templates.TemplateResponse(request, "finding.html", {
        "f": f, "scope": scope, "statuses": STATUSES,
        "evidence": evidence, "markdown": markdown,
        "related": related, "bounty": bounty,
    })


@app.post("/finding/{fid}/status")
def change_status(fid: int, status: str = Form(...)):
    _, _, db = _ctx()
    if status in STATUSES:
        db.set_status(fid, status)
    db.close()
    return RedirectResponse(f"/finding/{fid}", status_code=303)


@app.post("/finding/{fid}/report")
def make_report(fid: int):
    settings, scope, db = _ctx()
    f = db.finding(fid)
    if f:
        write_report(f, scope, settings, pdf=False)
    db.close()
    return RedirectResponse(f"/finding/{fid}?reported=1", status_code=303)
