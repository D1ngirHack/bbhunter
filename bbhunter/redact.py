"""Enmascarado de secretos en evidencia, registros y prompts.

La evidencia sale de respuestas del objetivo (un .env, un .git/config, cabeceras).
Guardarla o enviarla a terceros (API de Claude) en claro expone credenciales de la
empresa, y muchos programas prohiben compartir sus datos. Aqui se enmascaran
conservando los 4 primeros caracteres: suficiente para demostrar en el informe que
el valor es real, sin reproducirlo entero.
"""
from __future__ import annotations

import re
from typing import Any

KEEP = 4

# (patron, tipo, grupo que contiene el secreto)
_PATTERNS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "private_key", 0),
    (re.compile(r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)"
                r"\s*:\s*)(.+)$"), "header", 2),
    (re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{12,})"), "bearer", 2),
    (re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)"), "url_password", 2),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key", 0),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}"), "jwt", 0),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "github_token", 0),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "slack_token", 0),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "google_api_key", 0),
    (re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), "stripe_key", 0),
    # clave = valor / clave: valor / "clave": "valor" con nombres tipicos de secreto
    (re.compile(r"(?i)([\w.-]*(?:pass(?:word)?|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
                r"|private[_-]?key|client[_-]?secret|credentials?)[\w.-]*[\"']?\s*[=:]\s*[\"']?)"
                r"([^\s\"'&,;<>]{4,})"), "key_value", 2),
]


def _mask(value: str, kind: str) -> str:
    if "[REDACTADO" in value:
        return value
    return f"{value[:KEEP]}...[REDACTADO:{kind}]"


def redact_text(text: str) -> tuple[str, int]:
    """Devuelve (texto enmascarado, numero de secretos enmascarados)."""
    if not text:
        return text, 0
    count = 0
    for pattern, kind, group in _PATTERNS:
        def repl(m: re.Match[str], kind: str = kind, group: int = group) -> str:
            nonlocal count
            secret = m.group(group)
            if "[REDACTADO" in secret:
                return m.group(0)
            count += 1
            start, end = m.start(group) - m.start(0), m.end(group) - m.start(0)
            whole = m.group(0)
            return whole[:start] + _mask(secret, kind) + whole[end:]
        text = pattern.sub(repl, text)
    return text, count


def redact_obj(obj: Any) -> tuple[Any, int]:
    """Aplica redact_text recursivamente a str dentro de dict/list."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out, total = {}, 0
        for k, v in obj.items():
            out[k], n = redact_obj(v)
            total += n
        return out, total
    if isinstance(obj, (list, tuple)):
        items, total = [], 0
        for v in obj:
            r, n = redact_obj(v)
            items.append(r)
            total += n
        return items, total
    return obj, 0
