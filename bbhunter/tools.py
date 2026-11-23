"""Ejecucion de binarios externos (subfinder, httpx, nuclei, dalfox...).

Incluye comprobacion de disponibilidad y modo dry_run (datos simulados) para
poder probar el pipeline sin las herramientas instaladas o sin tocar objetivos.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Iterable


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(cmd: list[str], timeout: int = 1800, input_text: str | None = None) -> tuple[int, str, str]:
    """Ejecuta un comando y devuelve (returncode, stdout, stderr).

    No usa shell=True: los argumentos se pasan como lista para evitar inyeccion.
    """
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"binario no encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout tras {timeout}s: {' '.join(cmd)}"


def lines(text: str) -> list[str]:
    return [ln for ln in (text or "").splitlines() if ln.strip()]


def iter_jsonl(text: str) -> Iterable[dict]:
    import json

    for ln in lines(text):
        try:
            yield json.loads(ln)
        except json.JSONDecodeError:
            continue
