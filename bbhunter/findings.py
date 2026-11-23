"""Normalizacion y deduplicacion de hallazgos."""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse


def dedup_hash(program: str, vuln_class: str, template_id: str, url: str, param: str = "") -> str:
    """Hash estable para deduplicar. Normaliza el host+path (sin query) + clase +
    template + parametro para que el mismo hallazgo no entre dos veces."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    base = f"{parsed.hostname or ''}{parsed.path or ''}".lower().rstrip("/")
    key = "|".join([program.lower(), vuln_class, template_id or "", base, (param or "").lower()])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
