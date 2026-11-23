"""Carga de configuracion (settings.yaml) y scope (scope.yaml) con validacion."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

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


class Settings(BaseModel):
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    anthropic_model_final: str = "claude-opus-5-5"
    llm_enabled: bool = True
    tools: ToolPaths = Field(default_factory=ToolPaths)
    limits: Limits = Field(default_factory=Limits)
    dry_run: bool = False
    db_path: str = "data/bbhunter.sqlite"
    reports_dir: str = "reports"

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
