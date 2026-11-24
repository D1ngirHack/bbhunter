"""Registro de auditoria y deteccion de fallos de las herramientas.

Cada ejecucion de una herramienta externa (subfinder, httpx, nuclei, dalfox)
pasa por Auditor.run(), que:

- deja una linea JSON en data/audit.jsonl: cuando, programa, fase, herramienta,
  comando (con secretos enmascarados), cuantos objetivos y cuales, limite de
  peticiones, codigo de salida, duracion y el final del stderr;
- detecta el fallo (codigo != 0, timeout, binario ausente) y lo muestra, para
  que "0 hallazgos" nunca oculte "la herramienta no funciono".

Sirve para demostrar al programa que se respeto el scope y la tasa, y para saber
si un resultado vacio es real o un escaneo incompleto.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from . import tools
from .redact import redact_text

console = Console()
MAX_TARGETS_LOGGED = 50


@dataclass
class ToolResult:
    tool: str
    code: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.code == 0


@dataclass
class Auditor:
    path: Path
    program: str
    failures: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ registro
    def _write(self, entry: dict) -> None:
        entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"),
                 "program": self.program, **entry}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    @staticmethod
    def _targets_info(targets: list[str]) -> dict:
        joined = "\n".join(targets)
        return {
            "targets_count": len(targets),
            "targets": targets[:MAX_TARGETS_LOGGED],
            "targets_truncated": len(targets) > MAX_TARGETS_LOGGED,
            "targets_sha256": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
        }

    # ----------------------------------------------------------------- ejecucion
    def run(self, tool: str, cmd: list[str], *, phase: str, targets: list[str],
            rate_limit: int | None = None, timeout: int = 1800,
            input_text: str | None = None) -> ToolResult:
        start = time.monotonic()
        code, out, err = tools.run(cmd, timeout=timeout, input_text=input_text)
        result = ToolResult(tool, code, out or "", err or "", round(time.monotonic() - start, 2))
        stderr_tail, _ = redact_text(result.stderr[-1500:])
        self._write({
            "event": "tool_run",
            "phase": phase,
            "tool": tool,
            "argv": [redact_text(a)[0] for a in cmd],
            **self._targets_info(targets),
            "rate_limit_rps": rate_limit,
            "exit_code": code,
            "ok": result.ok,
            "duration_s": result.duration_s,
            "stdout_lines": len(tools.lines(result.stdout)),
            "stderr_tail": stderr_tail,
        })
        if not result.ok:
            self.failures.append(f"{tool} (fase {phase}, codigo {code})")
            last = "\n".join(stderr_tail.strip().splitlines()[-4:]) or "(sin stderr)"
            console.print(f"[bold red]FALLO[/bold red] {tool} terminó con código {code}. "
                          f"Resultados de esta herramienta INCOMPLETOS.\n[dim]{last}[/dim]")
        return result

    def skip(self, tool: str, *, phase: str, reason: str) -> None:
        """Herramienta que no se ejecuto (no instalada, bloqueada por politica...)."""
        self.skipped.append(f"{tool}: {reason}")
        self._write({"event": "tool_skipped", "phase": phase, "tool": tool, "reason": reason})

    def summary(self, phase: str) -> bool:
        """Imprime el estado final de la fase. Devuelve True si fue completa."""
        if self.failures:
            console.print(f"[bold red]RESULTADO INCOMPLETO ({phase}):[/bold red] "
                          f"{len(self.failures)} ejecucion(es) fallida(s): "
                          + "; ".join(self.failures)
                          + ". Un recuento bajo o cero NO significa que no haya nada. "
                            "Revisa 'bbhunter audit --failed'.")
        if self.skipped:
            console.print(f"[yellow]Omitido ({phase}):[/yellow] " + "; ".join(self.skipped))
        return not self.failures


def read_entries(path: Path, last: int = 20, failed_only: bool = False) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if failed_only and e.get("ok", True) and e.get("event") != "tool_skipped":
                continue
            entries.append(e)
    return entries[-last:]
