"""Dashboard web local (FastAPI) para triar hallazgos y exportar informes.

Solo escucha en localhost por defecto. No expone ninguna accion de escaneo ni de
envio a plataformas: sirve para revisar, validar y generar informes.

Protecciones (el panel no tiene usuarios, asi que no debe ser accesible por otros):
- Host permitido: solo loopback (o el host con el que se lanzo). Bloquea DNS
  rebinding: una web maliciosa no puede leer el panel apuntando su dominio a 127.0.0.1.
- POST con token CSRF por proceso y Origin/Referer del mismo origen: otra web
  abierta en tu navegador no puede cambiar estados ni generar informes.
- Cabeceras: CSP estricta, sin iframes, nosniff y sin Referer hacia enlaces externos.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import references
from ..config import load_settings
from ..db import DB
from ..report import render_markdown, write_report
from ..scope import load_scope, program_scope_path

app = FastAPI(title="BBHunter Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

STATUSES = ["new", "validated", "false_positive", "duplicate", "ready", "reported"]
CSRF_TOKEN = secrets.token_urlsafe(32)
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def allowed_hosts() -> set[str]:
    extra = os.environ.get("BBHUNTER_DASHBOARD_HOST", "").strip().lower()
    return _LOOPBACK | ({extra} if extra and extra not in ("0.0.0.0", "::") else set())


def _hostname(value: str) -> str:
    """Hostname de una cabecera Host ('127.0.0.1:8000', '[::1]:8000')."""
    try:
        return (urlparse("//" + value).hostname or "").lower()
    except ValueError:
        return ""


def _same_origin(request: Request) -> bool:
    """Origin (o Referer si no hay Origin) debe coincidir con el Host de la peticion."""
    host = request.headers.get("host", "").lower()
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return False  # los navegadores envian Origin en POST de formularios
    if source == "null":
        return False
    parsed = urlparse(source)
    return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host


@app.middleware("http")
async def _guard(request: Request, call_next):
    if _hostname(request.headers.get("host", "")) not in allowed_hosts():
        return PlainTextResponse("Host no permitido", status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not _same_origin(request):
            return PlainTextResponse("Origen no permitido", status_code=403)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def _check_csrf(token: str) -> bool:
    return hmac.compare_digest(token or "", CSRF_TOKEN)


def _ctx():
    program = os.environ.get("BBHUNTER_PROGRAM", "").strip() or None
    settings = None
    if program:
        override = program_scope_path(program).with_name("settings.yaml")
        if override.exists():
            settings = load_settings(override)
    settings = settings or load_settings()
    scope = load_scope(program=program)
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
    if f and f.get("program") != scope.program:
        f = None  # no mostrar hallazgos de otro programa
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
        "related": related, "bounty": bounty, "csrf": CSRF_TOKEN,
    })


@app.post("/finding/{fid}/status")
def change_status(fid: int, status: str = Form(...), csrf: str = Form("")):
    if not _check_csrf(csrf):
        return PlainTextResponse("Token CSRF no valido", status_code=403)
    _, scope, db = _ctx()
    f = db.finding(fid)
    if f and f.get("program") == scope.program and status in STATUSES:
        db.set_status(fid, status)
    db.close()
    return RedirectResponse(f"/finding/{fid}", status_code=303)


@app.post("/finding/{fid}/report")
def make_report(fid: int, csrf: str = Form("")):
    if not _check_csrf(csrf):
        return PlainTextResponse("Token CSRF no valido", status_code=403)
    settings, scope, db = _ctx()
    f = db.finding(fid)
    if f and f.get("program") == scope.program:
        write_report(f, scope, settings, pdf=False)
    db.close()
    return RedirectResponse(f"/finding/{fid}?reported=1", status_code=303)
