"""Configuracion comun de tests: nunca escribir en data/audit.jsonl del repo."""
import pytest

from bbhunter.config import Settings


@pytest.fixture(autouse=True)
def _audit_to_tmp(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(Settings, "abs_audit_path", lambda self: path)
    return path
