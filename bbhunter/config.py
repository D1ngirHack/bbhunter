"""Carga de configuracion (settings.yaml) y scope (scope.yaml) con validacion."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

# Raiz del proyecto = carpeta que contiene el paquete bbhunter/
ROOT = Path(__file__).resolve().parent.parent


class ToolPaths(BaseModel):
    subfinder: str = "subfinder"
    httpx: str = "httpx"
    naabu: str = "naabu"
    nuclei: str = "nuclei"
    dalfox: str = "dalfox"


class Limits(BaseModel):
    global_rate_limit_rps: int = 10
    nuclei_concurrency: int = 25
    http_timeout_s: int = 10


class References(BaseModel):
    """Fuentes de referencia (solo consulta, nunca tocan objetivos)."""
    hackerone_url: str = (
        "https://raw.githubusercontent.com/codebygk/hackerone-bug-bounty-reports/"
        "master/data/reports.json"
    )
    medium_tags: list[str] = Field(default_factory=lambda: [
        "bug-bounty", "bugbounty-writeup", "xss", "ssrf", "idor",
        "information-disclosure", "subdomain-takeover",
    ])
    timeout_s: int = 60
    in_llm_prompt: bool = True   # pasar informes similares a Claude para calibrar


class Settings(BaseModel):
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    anthropic_model_final: str = "claude-opus-5-5"
    llm_enabled: bool = True
    tools: ToolPaths = Field(default_factory=ToolPaths)
    limits: Limits = Field(default_factory=Limits)
    references: References = Field(default_factory=References)
    dry_run: bool = False
    db_path: str = "data/bbhunter.sqlite"
    reports_dir: str = "reports"
    audit_log: str = "data/audit.jsonl"
    # Proxy HTTP(S)/SOCKS5 para httpx, nuclei y dalfox (p.ej. Burp: http://127.0.0.1:8080).
    proxy: str = ""
    # Enmascarar secretos en la evidencia antes de guardarla (BD, informes, dashboard).
    redact_evidence: bool = True
    # Que evidencia se envia a la API de Claude: "redacted" (enmascarada) | "none" (nada).
    llm_evidence: Literal["redacted", "none"] = "redacted"

    @field_validator("proxy")
    @classmethod
    def _check_proxy(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return ""
        if any(c in v for c in "\r\n \t") or not re.match(r"^(https?|socks5h?)://[^/]+/?$", v):
            raise ValueError("proxy debe ser como http://127.0.0.1:8080 o socks5://host:puerto")
        return v

    def abs_audit_path(self) -> Path:
        p = Path(self.audit_log)
        return p if p.is_absolute() else ROOT / p

    def resolved_api_key(self) -> str:
        """La variable de entorno tiene prioridad sobre el fichero."""
        return os.environ.get("ANTHROPIC_API_KEY", "").strip() or self.anthropic_api_key.strip()

    def abs_db_path(self) -> Path:
        p = Path(self.db_path)
        return p if p.is_absolute() else ROOT / p

    def abs_reports_dir(self) -> Path:
        p = Path(self.reports_dir)
        return p if p.is_absolute() else ROOT / p


def _load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_settings(path: str | Path | None = None) -> Settings:
    """Carga settings.yaml; si no existe, usa settings.example.yaml; si tampoco,
    valores por defecto."""
    if path is not None:
        return Settings(**_load_yaml(Path(path)))
    for candidate in (ROOT / "config" / "settings.yaml", ROOT / "config" / "settings.example.yaml"):
        if candidate.exists():
            return Settings(**_load_yaml(candidate))
    return Settings()
