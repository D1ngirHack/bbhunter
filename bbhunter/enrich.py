"""Enriquecimiento de hallazgos: completa explanation/reproduction/impact/
remediation (via Claude o plantillas) para los hallazgos que aun no lo tienen.
"""
from __future__ import annotations

from rich.console import Console

from . import llm, references
from .config import Settings
from .db import DB

console = Console()


def enrich_findings(program: str, settings: Settings, db: DB, finding_id: int | None = None,
                    final: bool = False, force: bool = False) -> int:
    if finding_id is not None:
        rows = [db.finding(finding_id)]
        rows = [r for r in rows if r]
    else:
        rows = db.findings(program=program)

    count = 0
    for row in rows:
        if not force and row.get("explanation"):
            continue
        console.print(f"  Enriqueciendo #{row['id']} [cyan]{row.get('name','')}[/cyan] ...")
        similar = None
        if settings.references.in_llm_prompt:
            similar = references.for_finding(db.conn, row, limit=5)["hackerone"]
        data = llm.enrich_with_llm(row, settings, final=final, similar=similar)
        db.update_finding(
            row["id"],
            explanation=data.get("explanation", ""),
            reproduction=data.get("reproduction", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
        )
        count += 1
    console.print(f"  Hallazgos enriquecidos: [green]{count}[/green]")
    return count
