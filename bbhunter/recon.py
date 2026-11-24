"""Recon: enumeracion de subdominios (subfinder) y deteccion de hosts vivos +
fingerprint de tecnologia (httpx). Todo filtrado por el gate de scope.

Cada ejecucion queda en el registro de auditoria y los fallos se notifican
(ver audit.py): un recuento bajo puede deberse a una herramienta que fallo.
"""
from __future__ import annotations

from rich.console import Console

from . import tools
from .audit import Auditor
from .config import Settings
from .db import DB
from .scope import Scope

console = Console()


def _auditor(scope: Scope, settings: Settings) -> Auditor:
    return Auditor(settings.abs_audit_path(), scope.program)


def _seed_domains(scope: Scope) -> list[str]:
    """Dominios base del scope para arrancar (quita el '*.' de los wildcard)."""
    seeds = []
    for pat in scope.in_scope:
        pat = pat.strip().lower()
        seeds.append(pat[2:] if pat.startswith("*.") else pat)
    return sorted(set(seeds))


def enumerate_subdomains(scope: Scope, settings: Settings, aud: Auditor | None = None) -> list[str]:
    aud = aud or _auditor(scope, settings)
    seeds = _seed_domains(scope)
    found: set[str] = set(seeds)

    if settings.dry_run:
        # En dry_run simulamos un par de subdominios plausibles.
        for s in seeds:
            found.update({f"www.{s}", f"api.{s}", f"dev.{s}"})
    elif not tools.tool_available(settings.tools.subfinder):
        console.print("[yellow]subfinder no disponible: uso solo los dominios semilla del scope.[/yellow]")
        aud.skip("subfinder", phase="recon", reason="binario no encontrado")
    else:
        for seed in seeds:
            # subfinder consulta fuentes pasivas de terceros: no envia trafico al objetivo,
            # por eso no lleva cabeceras del programa ni proxy.
            res = aud.run("subfinder", [settings.tools.subfinder, "-silent", "-d", seed],
                          phase="recon", targets=[seed], timeout=600)
            found.update(tools.lines(res.stdout))  # aun con fallo, se usa lo que devolvio

    # Filtro de scope DURO
    allowed, rejected = scope.filter_allowed(sorted(found))
    if rejected:
        console.print(f"[dim]Descartados {len(rejected)} subdominios fuera de scope.[/dim]")
    return allowed


def probe_live(subdomains: list[str], scope: Scope, settings: Settings,
               aud: Auditor | None = None) -> list[dict]:
    """httpx sobre los subdominios -> lista de dicts {url, host, ip, tech, ...}."""
    aud = aud or _auditor(scope, settings)
    results: list[dict] = []

    if settings.dry_run or not tools.tool_available(settings.tools.httpx):
        for sd in subdomains:
            results.append({
                "url": f"https://{sd}",
                "host": sd,
                "ip": "203.0.113.10" if settings.dry_run else "",
                "port": 443,
                "tech": "nginx, React" if settings.dry_run else "",
                "source": "dry_run" if settings.dry_run else "no-httpx",
            })
        if not settings.dry_run:
            console.print("[yellow]httpx no disponible: asumo https:// sin comprobar que respondan.[/yellow]")
            aud.skip("httpx", phase="recon", reason="binario no encontrado; URLs supuestas (no-httpx)")
        return [r for r in results if scope.is_allowed(r["url"])]

    if not subdomains:
        return []
    rps = scope.effective_rate_limit(settings.limits.global_rate_limit_rps)
    cmd = [
        settings.tools.httpx, "-silent", "-json",
        "-rate-limit", str(rps),
        "-timeout", str(settings.limits.http_timeout_s),
        "-tech-detect", "-status-code", "-title",
        *tools.traffic_args("httpx", scope.request_headers, settings.proxy),
    ]
    res = aud.run("httpx", cmd, phase="recon", targets=subdomains, rate_limit=rps,
                  timeout=900, input_text="\n".join(subdomains))
    for obj in tools.iter_jsonl(res.stdout):
        url = obj.get("url") or obj.get("input") or ""
        if not url or not scope.is_allowed(url):
            continue
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, list):
            tech = ", ".join(tech)
        results.append({
            "url": url,
            "host": obj.get("host") or obj.get("input") or "",
            "ip": (obj.get("a") or [""])[0] if isinstance(obj.get("a"), list) else obj.get("ip", ""),
            "port": int(obj.get("port") or 0) or None,
            "tech": tech,
            "source": "httpx",
        })
    return results


def run_recon(scope: Scope, settings: Settings, db: DB) -> list[dict]:
    if not settings.dry_run:
        scope.check_phase("recon")  # lanza PhaseNotAllowed si la politica lo prohibe
    aud = _auditor(scope, settings)
    console.print(f"[bold]Recon[/bold] para programa [cyan]{scope.program}[/cyan]")
    subs = enumerate_subdomains(scope, settings, aud)
    console.print(f"  Subdominios en scope: [green]{len(subs)}[/green]")
    if not scope.rules.allow_active_scan and not settings.dry_run:
        # Modo pasivo: no se envia ninguna peticion a los hosts. Se guardan como
        # candidatos sin sondear (source='pasivo-sin-sondeo'); no son "hosts vivos".
        console.print("  [yellow]allow_active_scan=false: sin sondeo httpx. "
                      "Los subdominios se guardan como candidatos NO verificados.[/yellow]")
        aud.skip("httpx", phase="recon", reason="allow_active_scan=false (modo pasivo)")
        for sd in subs:
            db.upsert_asset(scope.program, url=f"https://{sd}", host=sd,
                            source="pasivo-sin-sondeo")
        aud.summary("recon")
        return []
    live = probe_live(subs, scope, settings, aud)
    console.print(f"  Hosts vivos: [green]{len(live)}[/green]")
    for asset in live:
        db.upsert_asset(scope.program, **asset)
    aud.summary("recon")
    return live
