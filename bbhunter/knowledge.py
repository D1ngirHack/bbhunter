"""Carga de la base de conocimiento (vrt_mapping.yaml, vuln_kb.yaml) y utilidades
de severidad: CVSS v3.1 -> score -> severidad -> tier VRT (P1-P5).
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

from .config import ROOT


@functools.lru_cache(maxsize=1)
def vrt_mapping() -> dict:
    with open(ROOT / "knowledge" / "vrt_mapping.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@functools.lru_cache(maxsize=1)
def vuln_kb() -> dict:
    with open(ROOT / "knowledge" / "vuln_kb.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def classify(tags: list[str] | str, name: str = "") -> str:
    """Devuelve la clave de clase (exposure | xss_reflected | generic) a partir de
    las tags/nombre de un hallazgo."""
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace(",", " ").split()]
    tagset = {t.lower() for t in tags}
    haystack = " ".join(tagset) + " " + name.lower()
    classes = vuln_kb()["classes"]
    for key, spec in classes.items():
        if key == "generic":
            continue
        match_tags = [m.lower() for m in spec.get("match_tags", [])]
        if tagset.intersection(match_tags) or any(m in haystack for m in match_tags):
            return key
    return "generic"


def kb_for(vuln_class: str) -> dict:
    return vuln_kb()["classes"].get(vuln_class, vuln_kb()["classes"]["generic"])


def cvss_score(vector: str) -> float:
    """Calcula el base score CVSS v3.1 desde un vector. Si falla, 0.0."""
    try:
        from cvss import CVSS3

        return float(CVSS3(vector).base_score)
    except Exception:
        return 0.0


def severity_from_score(score: float) -> str:
    for band in vrt_mapping()["cvss_bands"]:
        if band["min"] <= score <= band["max"]:
            return band["severity"]
    return "Informational"


def tier_from_severity(severity: str) -> str:
    return vrt_mapping()["severity_to_tier"].get(severity, "P5")


def tier_info(tier: str) -> dict:
    return vrt_mapping()["tiers"].get(tier, {})


def grade(vector: str) -> dict:
    """Devuelve un dict con score, severity, tier e info del tier para un vector."""
    score = cvss_score(vector)
    severity = severity_from_score(score)
    tier = tier_from_severity(severity)
    return {
        "cvss_vector": vector,
        "cvss_score": score,
        "severity": severity,
        "vrt_tier": tier,
        "tier_info": tier_info(tier),
    }
