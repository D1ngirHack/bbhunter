"""Escaneo de vulnerabilidades: nuclei (general) + dalfox (XSS reflejado).

Todo se ejecuta SOLO contra assets in-scope y respetando el rate limit. Cada
hallazgo se clasifica, se puntua (CVSS/VRT) y se deduplica antes de guardarse.

- nuclei usa la politica de plantillas del programa (scope.nuclei): allowlist,
  tags excluidas, severidades y -no-interactsh salvo que se permita.
- El trafico lleva las cabeceras del programa (scope.request_headers) y, si se
  configura, pasa por settings.proxy (p.ej. Burp).
- Cada ejecucion queda en el registro de auditoria y los fallos se notifican.
- La evidencia se guarda con los secretos enmascarados (settings.redact_evidence).
"""
from __future__ import annotations

from rich.console import Console

from . import knowledge, tools
from .audit import Auditor
from .config import Settings
from .db import DB
from .findings import dedup_hash
from .redact import redact_obj
from .scope import Scope

console = Console()


def _auditor(scope: Scope, settings: Settings) -> Auditor:
    return Auditor(settings.abs_audit_path(), scope.program)


def _store(db: DB, scope: Scope, settings: Settings, vuln_class: str, name: str,
           template_id: str, url: str, param: str, evidence: dict) -> bool:
    if settings.redact_evidence:
        evidence, n = redact_obj(evidence)
        if n:
            evidence["_redacted_secrets"] = n
    spec = knowledge.kb_for(vuln_class)
    grade = knowledge.grade(spec["default_cvss_vector"])
    h = dedup_hash(scope.program, vuln_class, template_id, url, param)
    return db.insert_finding(
        scope.program, h,
        vuln_class=vuln_class,
        name=name,
        template_id=template_id,
        url=url,
        param=param,
        severity=grade["severity"],
        cvss_score=grade["cvss_score"],
        cvss_vector=grade["cvss_vector"],
        vrt_tier=grade["vrt_tier"],
        evidence=evidence,
        refs=spec.get("references", []),
        status="new",
    )


def _dry_run_findings(db: DB, scope: Scope, settings: Settings, urls: list[str]) -> int:
    """Genera hallazgos de ejemplo para probar el pipeline sin herramientas."""
    if not urls:
        return 0
    n = 0
    target = urls[0]
    samples = [
        ("exposure", "Fichero .env expuesto", "exposed-env-file",
         target.rstrip("/") + "/.env", "",
         {"request": f"GET /.env HTTP/1.1\nHost: {target}",
          "response": "DB_PASSWORD=supersecret123\nAWS_SECRET_ACCESS_KEY=AKIA..."}),
        ("exposure", "Repositorio .git accesible", "exposed-git-config",
         target.rstrip("/") + "/.git/config", "",
         {"request": f"GET /.git/config HTTP/1.1\nHost: {target}",
          "response": "[core]\n repositoryformatversion = 0\n[remote \"origin\"]..."}),
        ("xss_reflected", "Reflected XSS en parametro de busqueda", "reflected-xss",
         target.rstrip("/") + "/search?q=FUZZ", "q",
         {"payload": "<script>alert(document.domain)</script>",
          "request": f"GET /search?q=<script>alert(document.domain)</script> HTTP/1.1\nHost: {target}",
          "response": "...<div>Resultados para <script>alert(document.domain)</script></div>..."}),
    ]
    for vuln_class, name, tid, url, param, ev in samples:
        if not scope.is_allowed(url):
            continue
        if _store(db, scope, settings, vuln_class, name, tid, url, param, ev):
            n += 1
    return n


def _active_allowed(scope: Scope) -> bool:
    return scope.rules.allow_active_scan and scope.rules.allow_automated_tools


def run_nuclei(db: DB, scope: Scope, settings: Settings, urls: list[str],
               aud: Auditor | None = None) -> int:
    aud = aud or _auditor(scope, settings)
    if not tools.tool_available(settings.tools.nuclei):
        console.print("[yellow]nuclei no disponible: se omite el escaneo nuclei.[/yellow]")
        aud.skip("nuclei", phase="scan", reason="binario no encontrado")
        return 0
    if not _active_allowed(scope):
        console.print("[red]El scope no permite escaneo activo: se omite nuclei.[/red]")
        aud.skip("nuclei", phase="scan", reason="politica del scope")
        return 0
    if scope.has_path_patterns() and not scope.nuclei.is_allowlist():
        console.print("[red]El scope limita rutas y no hay allowlist de plantillas "
                      "(nuclei.templates / template_ids / tags): se omite nuclei.[/red]")
        aud.skip("nuclei", phase="scan",
                 reason="scope limitado por ruta sin allowlist de plantillas")
        return 0
    rps = scope.effective_rate_limit(settings.limits.global_rate_limit_rps)
    cmd = [
        settings.tools.nuclei, "-silent", "-jsonl",
        "-rate-limit", str(rps),
        "-concurrency", str(settings.limits.nuclei_concurrency),
        *scope.nuclei.args(),   # allowlist/exclusiones/severidad/-no-interactsh del programa
        *tools.traffic_args("nuclei", scope.request_headers, settings.proxy),
    ]
    res = aud.run("nuclei", cmd, phase="scan", targets=urls, rate_limit=rps,
                  timeout=3600, input_text="\n".join(urls))
    n = 0
    for obj in tools.iter_jsonl(res.stdout):
        info = obj.get("info", {})
        tags = info.get("tags", [])
        name = info.get("name", obj.get("template-id", "hallazgo"))
        template_id = obj.get("template-id", "")
        url = obj.get("matched-at") or obj.get("host") or ""
        if not url or not scope.is_allowed(url):
            continue
        vuln_class = knowledge.classify(tags, name)
        evidence = {
            "matched_at": obj.get("matched-at", ""),
            "extracted": obj.get("extracted-results", []),
            "nuclei_severity": info.get("severity", ""),
            "request": obj.get("request", ""),
            "response": (obj.get("response", "") or "")[:4000],
        }
        if _store(db, scope, settings, vuln_class, name, template_id, url, "", evidence):
            n += 1
    return n


def run_dalfox(db: DB, scope: Scope, settings: Settings, urls: list[str],
               aud: Auditor | None = None) -> int:
    aud = aud or _auditor(scope, settings)
    if not tools.tool_available(settings.tools.dalfox):
        aud.skip("dalfox", phase="scan", reason="binario no encontrado")
        return 0
    if not _active_allowed(scope):
        console.print("[red]El scope no permite escaneo activo: se omite dalfox.[/red]")
        aud.skip("dalfox", phase="scan", reason="politica del scope")
        return 0
    # Solo URLs con parametros son candidatas a XSS reflejado.
    candidates = [u for u in urls if "?" in u and scope.is_allowed(u)]
    if not candidates:
        return 0
    n = 0
    rps = scope.effective_rate_limit(settings.limits.global_rate_limit_rps)
    for url in candidates:
        cmd = [settings.tools.dalfox, "url", url, "--silence", "--format", "json",
               "--delay", str(int(1000 / max(1, rps))),
               *tools.traffic_args("dalfox", scope.request_headers, settings.proxy)]
        res = aud.run("dalfox", cmd, phase="scan", targets=[url], rate_limit=rps, timeout=600)
        for obj in tools.iter_jsonl(res.stdout):
            param = obj.get("param", "")
            evidence = {"payload": obj.get("data", ""), "cwe": obj.get("cwe", ""),
                        "request": obj.get("message_str", "")}
            if _store(db, scope, settings, "xss_reflected", "Reflected XSS (dalfox)",
                      "dalfox", url, param, evidence):
                n += 1
    return n


def run_scan(scope: Scope, settings: Settings, db: DB) -> int:
    if not settings.dry_run:
        scope.check_phase("scan")  # lanza PhaseNotAllowed si la politica lo prohibe
    urls = db.live_urls(scope.program)
    if not urls:
        console.print("[yellow]No hay assets. Ejecuta primero el recon.[/yellow]")
        return 0
    # Doble verificacion de scope antes de escanear.
    urls, rejected = scope.filter_allowed(urls)
    if rejected:
        console.print(f"[dim]{len(rejected)} assets descartados por scope antes de escanear.[/dim]")

    console.print(f"[bold]Escaneo[/bold] sobre [green]{len(urls)}[/green] assets in-scope")
    total = 0
    if settings.dry_run:
        total += _dry_run_findings(db, scope, settings, urls)
        console.print(f"  Nuevos hallazgos (sin duplicados): [green]{total}[/green]")
        return total
    aud = _auditor(scope, settings)
    total += run_nuclei(db, scope, settings, urls, aud)
    total += run_dalfox(db, scope, settings, urls, aud)
    complete = aud.summary("scan")
    label = "" if complete else " [bold red](INCOMPLETO)[/bold red]"
    console.print(f"  Nuevos hallazgos (sin duplicados): [green]{total}[/green]{label}")
    return total
