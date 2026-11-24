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


# Flags de cabecera y proxy de cada herramienta (por clave, no por ruta del binario).
_HEADER_FLAG = {"httpx": "-H", "nuclei": "-H", "dalfox": "-H"}
_PROXY_FLAG = {"httpx": "-http-proxy", "nuclei": "-proxy", "dalfox": "--proxy"}


def traffic_args(tool: str, headers: dict[str, str], proxy: str = "") -> list[str]:
    """Argumentos para que una herramienta que toca el objetivo envie las cabeceras
    del programa y, opcionalmente, pase por un proxy (Burp). subfinder no los usa:
    consulta fuentes pasivas de terceros, no el objetivo."""
    args: list[str] = []
    flag = _HEADER_FLAG.get(tool)
    if flag:
        for name, value in headers.items():
            args += [flag, f"{name}: {value}"]
    if proxy and tool in _PROXY_FLAG:
        args += [_PROXY_FLAG[tool], proxy]
    return args


def lines(text: str) -> list[str]:
    return [ln for ln in (text or "").splitlines() if ln.strip()]


def iter_jsonl(text: str) -> Iterable[dict]:
    import json

    for ln in lines(text):
        try:
            yield json.loads(ln)
        except json.JSONDecodeError:
            continue
