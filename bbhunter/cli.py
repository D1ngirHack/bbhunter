"""CLI de BBHunter (Typer).

Opcion global: --program/-p NOMBRE (o BBHUNTER_PROGRAM) usa programs/NOMBRE/scope.yaml
(y programs/NOMBRE/settings.yaml si existe) en lugar de config/.

Comandos principales:
  bbhunter init [--program X]   Crea la configuracion desde los ejemplos.
  bbhunter programs             Lista los programas de programs/.
  bbhunter scope-check URL      Comprueba si un objetivo esta en scope.
  bbhunter recon                Enumeracion + hosts vivos.
  bbhunter scan                 Escaneo de vulnerabilidades (pide autorizacion).
  bbhunter enrich               Redacta explicacion/repro/impacto/remediacion.
  bbhunter report               Genera informes (Markdown/HTML/PDF).
  bbhunter run                  Pipeline completo recon->scan->enrich->report.
  bbhunter list                 Lista hallazgos.
  bbhunter set-status ID EST    Cambia el estado de un hallazgo.
  bbhunter dashboard            Lanza el panel web local.
  bbhunter audit [--failed]     Registro de auditoria de ejecuciones y fallos.
  bbhunter refs sync|search|finding|stats
                                Informes divulgados (HackerOne) y writeups (Medium).
"""
from __future__ import annotations

import os

import typer
from rich.console import Console
from rich.table import Table

from . import enrich as enrich_mod
from . import recon as recon_mod
from . import report as report_mod
from . import scan as scan_mod
from .config import RESOURCES, ROOT, load_settings
from .db import DB
from .scope import (
    PhaseNotAllowed,
    list_programs,
    load_scope,
    parse_pattern,
    program_scope_path,
    valid_program_name,
)

app = typer.Typer(add_completion=False, help="Asistente semi-automatico de bug bounty.")
console = Console()

STATUSES = ["new", "validated", "false_positive", "duplicate", "ready", "reported"]


_STATE: dict[str, str | None] = {"program": None}
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@app.callback()
def main(
    program: str = typer.Option(
        None, "--program", "-p", envvar="BBHUNTER_PROGRAM",
        help="Programa de programs/NOMBRE/ (por defecto, config/scope.yaml)."),
):
    """Asistente semi-automatico de bug bounty."""
    if program and not valid_program_name(program):
        console.print(f"[red]Nombre de programa no valido:[/red] {program!r} "
                      "(minusculas, digitos, '.', '_' o '-')")
        raise typer.Exit(code=1)
    _STATE["program"] = program or None


def _settings():
    prog = _STATE["program"]
    if prog:
        override = program_scope_path(prog).with_name("settings.yaml")
        if override.exists():
            return load_settings(override)
    return load_settings()


def _scope():
    try:
        return load_scope(program=_STATE["program"])
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Scope:[/red] {exc}")
        raise typer.Exit(code=1) from None


def _ctx():
    settings = _settings()
    scope = _scope()
    db = DB(settings.abs_db_path())
    return settings, scope, db


def _scope_limits(scope) -> list[str]:
    """Lineas que resumen limites de puerto/ruta/IP y la politica de nuclei."""
    out = []
    pats = [(raw, parse_pattern(raw)) for raw in scope.in_scope]
    restricted = [raw for raw, p in pats if not p.host_wide]
    if restricted:
        out.append(f"Limitado por puerto/ruta: {', '.join(restricted)}")
    nets = [raw for raw, p in pats if p.network is not None]
    if nets:
        out.append("IP/CIDR (solo objetivos escritos como IP; los CIDR no se expanden): "
                   + ", ".join(nets))
    wild = [raw for raw, p in pats if p.wildcard]
    if wild:
        apex = "incluyen" if scope.rules.wildcard_includes_apex else "NO incluyen"
        out.append(f"Wildcards ({apex} el apex): {', '.join(wild)}")
    n = scope.nuclei
    if n.is_allowlist():
        parts = [f"-t {', '.join(n.templates)}" if n.templates else "",
                 f"-id {', '.join(n.template_ids)}" if n.template_ids else "",
                 f"-tags {', '.join(n.tags)}" if n.tags else ""]
        out.append("Nuclei allowlist: " + " | ".join(p for p in parts if p))
    else:
        tail = " -> se omitira: el scope limita rutas" if scope.has_path_patterns() else ""
        out.append("Nuclei: TODAS las plantillas instaladas (sin allowlist)" + tail)
    out.append(f"Nuclei excluye tags: {', '.join(n.exclude_tags) or '(ninguna)'} | "
               f"interactsh: {'permitido' if n.allow_interactsh else 'desactivado'}")
    return out


def _authorization_gate(scope, assume_yes: bool, settings=None) -> None:
    console.print("\n[bold red]AVISO LEGAL[/bold red]")
    console.print(
        "Solo puedes escanear objetivos para los que tengas AUTORIZACION explicita "
        "(programa de bug bounty con scope valido o permiso por escrito). El escaneo "
        "no autorizado es ilegal en la mayoria de paises."
    )
    console.print(f"Programa: [cyan]{scope.program}[/cyan] | Plataforma: {scope.platform}")
    console.print(f"Politica: {scope.policy_url or '(no indicada)'}")
    console.print(f"In-scope: {', '.join(scope.in_scope) or '(vacio)'}")
    for line in _scope_limits(scope):
        console.print(f"  {line}")
    if scope.request_headers:
        hdrs = ", ".join(f"{k}: {v}" for k, v in scope.request_headers.items())
        console.print(f"Cabeceras en todo el trafico: [cyan]{hdrs}[/cyan]")
    else:
        console.print("[yellow]Sin cabeceras de identificacion (request_headers). "
                      "Comprueba si el programa exige alguna.[/yellow]")
    if settings is not None:
        console.print(f"Proxy: {settings.proxy or '(ninguno)'} | "
                      f"Registro de auditoria: {settings.abs_audit_path()}")
    if not scope.rules.allow_automated_tools:
        console.print("[yellow]OJO: el scope marca allow_automated_tools=false. "
                      "Confirma en la politica que puedes usar herramientas automaticas.[/yellow]")
    if assume_yes:
        return
    if not typer.confirm("Confirmo que estoy autorizado a probar este scope"):
        console.print("[red]Operacion cancelada.[/red]")
        raise typer.Exit(code=1)


@app.command()
def init(
    program: str = typer.Option(None, "--program", "-p",
                                help="Crear programs/NOMBRE/scope.yaml en vez de config/scope.yaml."),
):
    """Crea la configuracion local desde los ejemplos (nunca sobrescribe)."""
    program = program or _STATE["program"]
    examples = RESOURCES / "config"
    targets = [("settings", ROOT / "config" / "settings.yaml")]
    if program:
        if not valid_program_name(program):
            console.print(f"[red]Nombre de programa no valido:[/red] {program!r}")
            raise typer.Exit(code=1)
        targets.append(("scope", program_scope_path(program)))
    else:
        targets.append(("scope", ROOT / "config" / "scope.yaml"))
    for name, dst in targets:
        if dst.exists():
            console.print(f"[yellow]Ya existe {dst}, no lo sobrescribo.[/yellow]")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = (examples / f"{name}.example.yaml").read_text(encoding="utf-8")
        if name == "scope" and program:
            text = text.replace('program: "ejemplo-programa"', f'program: "{program}"', 1)
        dst.write_text(text, encoding="utf-8")
        console.print(f"[green]Creado[/green] {dst}")
    where = f"programs/{program}/scope.yaml" if program else "config/scope.yaml"
    console.print(f"Edita {where} con el scope REAL y config/settings.yaml con tus ajustes.")
    if program:
        console.print(f"Despues usa: bbhunter -p {program} <comando>")


@app.command("programs")
def programs_cmd():
    """Lista los programas configurados en programs/."""
    names = list_programs()
    if not names:
        console.print("[dim]No hay programas. Crea uno con: bbhunter init --program NOMBRE[/dim]")
        return
    settings = load_settings()
    db = DB(settings.abs_db_path())
    table = Table(title=f"Programas ({ROOT / 'programs'})")
    for col in ("Programa", "Plataforma", "In-scope", "Hallazgos", "Politica"):
        table.add_column(col, overflow="fold")
    for name in names:
        try:
            sc = load_scope(program=name)
        except Exception as exc:  # noqa: BLE001
            table.add_row(name, "", f"[red]error: {exc}[/red]", "", "")
            continue
        table.add_row(name, sc.platform, str(len(sc.in_scope)),
                      str(len(db.findings(program=sc.program))), sc.policy_url)
    db.close()
    console.print(table)


@app.command("scope-check")
def scope_check(target: str):
    """Comprueba si un objetivo (URL o dominio) esta en scope."""
    _, scope, _ = _ctx()
    allowed = scope.is_allowed(target)
    color = "green" if allowed else "red"
    console.print(f"[{color}]{'EN SCOPE' if allowed else 'FUERA DE SCOPE'}[/{color}]: {scope.reason(target)}")
    if not allowed:
        raise typer.Exit(code=1)


def _blocked(exc: PhaseNotAllowed) -> None:
    console.print(f"[bold red]BLOQUEADO[/bold red] {exc}")
    raise typer.Exit(code=2)


def _check_phases(scope, settings, phases: tuple[str, ...]) -> None:
    """Comprueba la politica ANTES de pedir confirmacion o lanzar nada."""
    if settings.dry_run:
        return
    try:
        for phase in phases:
            scope.check_phase(phase)
    except PhaseNotAllowed as exc:
        _blocked(exc)


@app.command()
def recon():
    """Enumeracion de subdominios + deteccion de hosts vivos."""
    settings, scope, db = _ctx()
    _check_phases(scope, settings, ("recon",))
    try:
        recon_mod.run_recon(scope, settings, db)
    except PhaseNotAllowed as exc:
        _blocked(exc)
    finally:
        db.close()


@app.command()
def scan(yes: bool = typer.Option(False, "--yes", "-y", help="Omitir confirmacion de autorizacion.")):
    """Escaneo de vulnerabilidades sobre los assets in-scope."""
    settings, scope, db = _ctx()
    _check_phases(scope, settings, ("scan",))
    _authorization_gate(scope, yes, settings)
    try:
        scan_mod.run_scan(scope, settings, db)
    except PhaseNotAllowed as exc:
        _blocked(exc)
    finally:
        db.close()


@app.command()
def enrich(
    id: int = typer.Option(None, help="Enriquecer solo este hallazgo."),
    final: bool = typer.Option(False, help="Usar el modelo final (mas caro)."),
    force: bool = typer.Option(False, help="Reenriquecer aunque ya tenga contenido."),
):
    """Redacta explicacion/reproduccion/impacto/remediacion (Claude o plantillas)."""
    settings, scope, db = _ctx()
    enrich_mod.enrich_findings(scope.program, settings, db, finding_id=id, final=final, force=force)
    db.close()


@app.command()
def report(
    status: str = typer.Option(None, help="Filtrar por estado (p.ej. ready)."),
    id: int = typer.Option(None, help="Generar solo este hallazgo."),
    pdf: bool = typer.Option(False, help="Generar tambien PDF (requiere weasyprint)."),
):
    """Genera informes profesionales por hallazgo."""
    settings, scope, db = _ctx()
    report_mod.generate_reports(scope, settings, db, status=status, finding_id=id, pdf=pdf)
    db.close()


@app.command()
def run(
    yes: bool = typer.Option(False, "--yes", "-y", help="Omitir confirmacion."),
    pdf: bool = typer.Option(False, help="Generar PDF ademas de Markdown/HTML."),
    final: bool = typer.Option(False, help="Usar modelo final para los informes."),
):
    """Pipeline completo: recon -> scan -> enrich -> report."""
    settings, scope, db = _ctx()
    # run necesita recon + scan: si la politica bloquea cualquiera, no empieza nada.
    _check_phases(scope, settings, ("recon", "scan"))
    _authorization_gate(scope, yes, settings)
    try:
        recon_mod.run_recon(scope, settings, db)
        scan_mod.run_scan(scope, settings, db)
    except PhaseNotAllowed as exc:
        db.close()
        _blocked(exc)
    enrich_mod.enrich_findings(scope.program, settings, db, final=final)
    report_mod.generate_reports(scope, settings, db, pdf=pdf)
    console.print("\n[bold green]Pipeline completado.[/bold green] Revisa y VALIDA cada hallazgo "
                  "antes de enviarlo. Usa 'bbhunter dashboard' para triar.")
    db.close()


@app.command("list")
def list_findings(status: str = typer.Option(None, help="Filtrar por estado.")):
    """Lista los hallazgos almacenados."""
    _, scope, db = _ctx()
    rows = db.findings(program=scope.program, status=status)
    table = Table(title=f"Hallazgos — {scope.program}")
    for col in ("ID", "Tier", "Sev", "CVSS", "Clase", "Nombre", "Estado"):
        table.add_column(col)
    for r in rows:
        table.add_row(str(r["id"]), r.get("vrt_tier", ""), r.get("severity", ""),
                      f"{r.get('cvss_score') or 0:.1f}", r.get("vuln_class", ""),
                      (r.get("name") or "")[:40], r.get("status", ""))
    console.print(table)
    console.print(f"Total: {len(rows)}")
    db.close()


@app.command("set-status")
def set_status(id: int, status: str):
    """Cambia el estado de un hallazgo (new/validated/false_positive/duplicate/ready/reported)."""
    if status not in STATUSES:
        console.print(f"[red]Estado invalido.[/red] Validos: {', '.join(STATUSES)}")
        raise typer.Exit(code=1)
    _, _, db = _ctx()
    db.set_status(id, status)
    console.print(f"[green]Hallazgo #{id} -> {status}[/green]")
    db.close()


# ----------------------------------------------------------------- referencias
refs_app = typer.Typer(help="Informes divulgados (HackerOne) y writeups (Medium) de referencia.")
app.add_typer(refs_app, name="refs")


def _print_refs(rows: list[dict], title: str) -> None:
    table = Table(title=title, show_lines=False)
    for col in ("Fuente", "Sev", "Bounty", "Tipo / Etiquetas", "Titulo", "URL"):
        table.add_column(col, overflow="fold")
    for r in rows:
        extra = r.get("vuln_type") or r.get("tags") or ""
        bounty = f"{r['bounty']:.0f}" if r.get("bounty") else ""
        table.add_row(r["source"], r.get("severity") or "", bounty, extra[:40],
                      (r.get("title") or "")[:70], r["url"])
    console.print(table)
    if not rows:
        console.print("[yellow]Sin resultados.[/yellow] ¿Has ejecutado 'bbhunter refs sync'?")


@refs_app.command("sync")
def refs_sync(
    source: str = typer.Option("all", help="hackerone | medium | all"),
):
    """Descarga/actualiza las referencias (no contacta con ningun objetivo)."""
    from . import references as refs_mod

    settings, _, db = _ctx()
    cfg = settings.references
    if source in ("all", "hackerone"):
        console.print("[bold]HackerOne[/bold]: descargando dataset de informes divulgados ...")
        try:
            n = refs_mod.sync_hackerone(db.conn, cfg.hackerone_url, timeout=cfg.timeout_s)
            console.print(f"  [green]{n}[/green] informes guardados/actualizados")
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]Error:[/red] {type(exc).__name__}: {exc}")
    if source in ("all", "medium"):
        console.print(f"[bold]Medium[/bold]: feeds de {', '.join(cfg.medium_tags)} ...")
        n, errors = refs_mod.sync_medium(db.conn, cfg.medium_tags, timeout=cfg.timeout_s)
        console.print(f"  [green]{n}[/green] writeups guardados/actualizados")
        for e in errors:
            console.print(f"  [yellow]{e}[/yellow]")
    db.close()


@refs_app.command("search")
def refs_search(
    query: str,
    source: str = typer.Option(None, help="hackerone | medium (por defecto ambas)"),
    limit: int = typer.Option(15, help="Numero maximo de resultados."),
):
    """Busca referencias por texto (p.ej. 'ssrf', 'subdomain takeover', 'idor')."""
    from . import references as refs_mod

    _, _, db = _ctx()
    rows = refs_mod.search(db.conn, query, source=source, limit=limit)
    _print_refs(rows, f"Referencias: '{query}'")
    db.close()


@refs_app.command("finding")
def refs_finding(id: int, limit: int = typer.Option(8, help="Resultados por fuente.")):
    """Informes y writeups relacionados con un hallazgo concreto."""
    from . import references as refs_mod

    _, _, db = _ctx()
    f = db.finding(id)
    if not f:
        console.print(f"[red]No existe el hallazgo #{id}[/red]")
        db.close()
        raise typer.Exit(code=1)
    related = refs_mod.for_finding(db.conn, f, limit=limit)
    _print_refs(related["hackerone"], f"HackerOne — similares a #{id} {f.get('name','')}")
    s = refs_mod.bounty_summary(related["hackerone"])
    if s.get("paid"):
        console.print(f"  Bounties pagados en estos {s['n']}: {s['paid']} | min {s['min']:.0f} "
                      f"| mediana {s['median']:.0f} | max {s['max']:.0f} USD")
    _print_refs(related["medium"], "Medium — writeups relacionados")
    db.close()


@refs_app.command("stats")
def refs_stats():
    """Cuantas referencias hay guardadas y cuando se sincronizaron."""
    from . import references as refs_mod

    _, _, db = _ctx()
    st = refs_mod.stats(db.conn)
    if not st:
        console.print("[yellow]No hay referencias. Ejecuta 'bbhunter refs sync'.[/yellow]")
    for src, info in st.items():
        console.print(f"{src}: [green]{info['count']}[/green] (ultima sync: {info['last_sync']})")
    db.close()


@app.command("audit")
def audit_log(
    last: int = typer.Option(20, help="Numero de entradas mas recientes."),
    failed: bool = typer.Option(False, "--failed", help="Solo fallos y herramientas omitidas."),
    program: str = typer.Option(None, help="Filtrar por programa (por defecto, el activo)."),
):
    """Registro de auditoria: que herramienta se ejecuto, contra que, cuando y con que resultado."""
    from .audit import read_entries

    settings = _settings()
    prog = program or _scope().program
    entries = [e for e in read_entries(settings.abs_audit_path(), last=10_000, failed_only=failed)
               if e.get("program") == prog][-last:]
    table = Table(title=f"Auditoria — {prog} ({settings.abs_audit_path()})")
    for col in ("Fecha (UTC)", "Fase", "Herramienta", "Objetivos", "RPS", "Codigo", "Seg", "Detalle"):
        table.add_column(col, overflow="fold")
    for e in entries:
        if e.get("event") == "tool_skipped":
            table.add_row(e["ts"], e.get("phase", ""), e.get("tool", ""), "", "", "[yellow]omitido[/yellow]",
                          "", e.get("reason", ""))
            continue
        code = str(e.get("exit_code"))
        code = code if e.get("ok") else f"[red]{code}[/red]"
        detail = ""
        if not e.get("ok"):
            err_lines = (e.get("stderr_tail") or "").strip().splitlines()
            detail = err_lines[-1][:80] if err_lines else "(sin stderr)"
        table.add_row(e["ts"], e.get("phase", ""), e.get("tool", ""), str(e.get("targets_count", "")),
                      str(e.get("rate_limit_rps") or ""), code, str(e.get("duration_s", "")), detail)
    console.print(table)
    if not entries:
        console.print("[dim]Sin entradas.[/dim]")


@app.command()
def dashboard(host: str = "127.0.0.1", port: int = 8000):
    """Lanza el dashboard web local para triar hallazgos."""
    import uvicorn

    if host not in _LOOPBACK:
        console.print(f"[bold red]AVISO[/bold red]: escuchar en {host} expone hallazgos y evidencias "
                      "a la red. El panel no tiene autenticacion; usa 127.0.0.1 y un tunel SSH.")
        if not typer.confirm("Continuar igualmente?"):
            raise typer.Exit(code=1)
    _scope()  # valida el programa antes de arrancar
    os.environ["BBHUNTER_DASHBOARD_HOST"] = host
    if _STATE["program"]:
        os.environ["BBHUNTER_PROGRAM"] = _STATE["program"]
    console.print(f"[bold]Dashboard[/bold] en http://{host}:{port}")
    uvicorn.run("bbhunter.dashboard.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
