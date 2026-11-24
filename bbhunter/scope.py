"""Gate de scope: el componente de seguridad mas importante.

Decide si un host/URL esta AUTORIZADO. out_of_scope tiene prioridad sobre
in_scope. El matching de wildcard "*.ejemplo.com" cubre cualquier subdominio
(y, por convencion aqui, tambien el apex ejemplo.com).

Ninguna etapa de recon/escaneo debe tocar un objetivo que no pase por
Scope.is_allowed(). Los tests en tests/test_scope.py lo verifican.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, field_validator

from .config import ROOT


class PhaseNotAllowed(Exception):
    """La politica del scope prohibe ejecutar esta fase."""


class ScopeRules(BaseModel):
    rate_limit_rps: int = 5
    allow_active_scan: bool = True
    allow_automated_tools: bool = True
    notes: str = ""


class Scope(BaseModel):
    program: str = "unnamed"
    platform: str = "privado"
    policy_url: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules: ScopeRules = Field(default_factory=ScopeRules)
    # Cabeceras que exige el programa en TODO el trafico (p.ej. X-Bug-Bounty: usuario).
    # Se pasan a httpx, nuclei y dalfox.
    request_headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("request_headers")
    @classmethod
    def _check_headers(cls, v: dict[str, str]) -> dict[str, str]:
        clean = {}
        for name, value in (v or {}).items():
            name, value = str(name).strip(), str(value).strip()
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"nombre de cabecera invalido: {name!r}")
            if any(c in value for c in "\r\n\0") or len(value) > 512:
                raise ValueError(f"valor de cabecera invalido para {name}")
            clean[name] = value
        return clean

    # ---- normalizacion ----
    @staticmethod
    def _host(target: str) -> str:
        """Extrae el hostname en minusculas de una URL o dominio, sin puerto."""
        target = (target or "").strip().lower()
        if not target:
            return ""
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).hostname or ""
        return host

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if not host or not pattern:
            return False
        if pattern.startswith("*."):
            base = pattern[2:]
            # wildcard cubre subdominios y el apex
            return host == base or host.endswith("." + base)
        return host == pattern

    # ---- decision ----
    def is_allowed(self, target: str) -> bool:
        host = self._host(target)
        if not host:
            return False
        # out_of_scope manda
        if any(self._matches(host, p) for p in self.out_of_scope):
            return False
        return any(self._matches(host, p) for p in self.in_scope)

    def reason(self, target: str) -> str:
        host = self._host(target)
        if not host:
            return "objetivo invalido (sin host)"
        for p in self.out_of_scope:
            if self._matches(host, p):
                return f"'{host}' coincide con out_of_scope '{p}'"
        for p in self.in_scope:
            if self._matches(host, p):
                return f"'{host}' coincide con in_scope '{p}'"
        return f"'{host}' no coincide con ningun patron in_scope"

    def filter_allowed(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Devuelve (permitidos, rechazados)."""
        allowed, rejected = [], []
        for t in targets:
            (allowed if self.is_allowed(t) else rejected).append(t)
        return allowed, rejected

    def check_phase(self, phase: str) -> None:
        """Bloqueo duro segun las reglas (no se salta con --yes).

        - allow_automated_tools=false -> ninguna fase con herramientas (recon, scan).
        - allow_active_scan=false     -> no hay escaneo (nuclei/dalfox); el recon
          queda en modo pasivo (subfinder sin sondeo httpx).
        """
        if not self.rules.allow_automated_tools:
            raise PhaseNotAllowed(
                f"'{phase}' bloqueado: el scope tiene allow_automated_tools=false. "
                "Trabaja manualmente segun la politica del programa."
            )
        if phase == "scan" and not self.rules.allow_active_scan:
            raise PhaseNotAllowed(
                "'scan' bloqueado: el scope tiene allow_active_scan=false. "
                "Solo puedes hacer recon pasivo y pruebas manuales permitidas."
            )

    def effective_rate_limit(self, global_cap: int) -> int:
        return max(1, min(self.rules.rate_limit_rps, global_cap))


def load_scope(path: str | Path | None = None) -> Scope:
    if path is None:
        for candidate in (ROOT / "config" / "scope.yaml", ROOT / "config" / "scope.example.yaml"):
            if candidate.exists():
                path = candidate
                break
        else:
            raise FileNotFoundError("No existe config/scope.yaml ni config/scope.example.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Scope(**data)
