"""Recon: enumeracion de subdominios (subfinder) y deteccion de hosts vivos +
fingerprint de tecnologia (httpx). Todo filtrado por el gate de scope.
"""
from __future__ import annotations

from rich.console import Console

from .config import Settings
from .db import DB
from .scope import Scope
from . import tools

console = Console()


def _seed_domains(scope: Scope) -> list[str]:
    """Dominios base del scope para arrancar (quita el '*.' de los wildcard)."""
    seeds = []
    for pat in scope.in_scope:
        pat = pat.strip().lower()
        seeds.append(pat[2:] if pat.startswith("*.") else pat)
    return sorted(set(seeds))


def enumerate_subdomains(scope: Scope, settings: Settings) -> list[str]:
    seeds = _seed_domains(scope)
    found: set[str] = set(seeds)

    if settings.dry_run or not tools.tool_available(settings.tools.subfinder):
        if not settings.dry_run:
            console.print("[yellow]subfinder no disponible: uso dominios semilla del scope.[/yellow]")
        # En dry_run simulamos un par de subdominios plausibles.
        if settings.dry_run:
            for s in seeds:
                found.update({f"www.{s}", f"api.{s}", f"dev.{s}"})
    else:
        for seed in seeds:
            code, out, _ = tools.run(
                [settings.tools.subfinder, "-silent", "-d", seed], timeout=600
            )
            if code == 0:
                found.update(tools.lines(out))

    # Filtro de scope DURO
    allowed, rejected = scope.filter_allowed(sorted(found))
    if rejected:
        console.print(f"[dim]Descartados {len(rejected)} subdominios fuera de scope.[/dim]")
    return allowed


def probe_live(subdomains: list[str], scope: Scope, settings: Settings) -> list[dict]:
    """httpx sobre los subdominios -> lista de dicts {url, host, ip, tech, ...}."""
    results: list[dict] = []

    if settings.dry_run or not tools.tool_available(settings.tools.httpx):
        for sd in subdomains:
            results.append({
                "url": f"https://{sd}",
                "host": sd,
                "ip": "203.0.113.10",
                "port": 443,
                "tech": "nginx, React" if settings.dry_run else "",
                "source": "dry_run" if settings.dry_run else "no-httpx",
            })
        if not settings.dry_run:
            console.print("[yellow]httpx no disponible: asumo https:// sin fingerprint.[/yellow]")
        return [r for r in results if scope.is_allowed(r["url"])]

    rps = scope.effective_rate_limit(settings.limits.global_rate_limit_rps)
    stdin = "\n".join(subdomains)
    cmd = [
        settings.tools.httpx, "-silent", "-json",
        "-rate-limit", str(rps),
        "-timeout", str(settings.limits.http_timeout_s),
        "-tech-detect", "-status-code", "-title",
    ]
    code, out, _ = tools.run(cmd, timeout=900, input_text=stdin)
    for obj in tools.iter_jsonl(out):
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
    console.print(f"[bold]Recon[/bold] para programa [cyan]{scope.program}[/cyan]")
    subs = enumerate_subdomains(scope, settings)
    console.print(f"  Subdominios en scope: [green]{len(subs)}[/green]")
    if not scope.rules.allow_active_scan and not settings.dry_run:
        # Modo pasivo: no se envia ninguna peticion a los hosts. Se guardan como
        # candidatos sin sondear (source='pasivo-sin-sondeo'); no son "hosts vivos".
        console.print("  [yellow]allow_active_scan=false: sin sondeo httpx. "
                      "Los subdominios se guardan como candidatos NO verificados.[/yellow]")
        for sd in subs:
            db.upsert_asset(scope.program, url=f"https://{sd}", host=sd,
                            source="pasivo-sin-sondeo")
        return []
    live = probe_live(subs, scope, settings)
    console.print(f"  Hosts vivos: [green]{len(live)}[/green]")
    for asset in live:
        db.upsert_asset(scope.program, **asset)
    return live
