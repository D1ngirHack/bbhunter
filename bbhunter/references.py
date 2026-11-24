"""Base de referencias: informes divulgados de HackerOne y writeups de Medium.

Sirve como material de CONSULTA para el cazador, nunca toca ningun objetivo:

- HackerOne: dataset publico de ~10.000 informes divulgados mantenido en
  github.com/codebygk/hackerone-bug-bounty-reports (solo metadatos: titulo,
  programa, tipo de vulnerabilidad, severidad, bounty, upvotes, enlace). El
  repositorio no declara licencia, por eso NO se incluye en BBHunter: se
  descarga a data/ (gitignored) con `bbhunter refs sync`.
- Medium: feeds RSS publicos por etiqueta (medium.com/feed/tag/<tag>). Se
  guarda titulo, autor, fecha, etiquetas, un resumen corto y el enlace. No se
  hace scraping de articulos (muro de pago / terminos de uso).

Todo lo descargado es contenido de terceros NO confiable: se muestra escapado,
solo se enlazan URLs https de los dominios esperados y, si se pasa a Claude,
va marcado como datos de referencia.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import urlparse

from . import knowledge

USER_AGENT = "bbhunter-refs/0.1 (+local research tool)"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS refs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT NOT NULL,          -- hackerone | medium
    url        TEXT NOT NULL UNIQUE,
    title      TEXT NOT NULL,
    program    TEXT,
    vuln_type  TEXT,
    severity   TEXT,
    bounty     REAL DEFAULT 0,
    upvotes    INTEGER DEFAULT 0,
    tags       TEXT,
    author     TEXT,
    published  TEXT,
    summary    TEXT,
    fetched_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_refs_source ON refs(source);
"""

# Dominios desde los que aceptamos enlaces de HackerOne (evita javascript:, phishing...).
# Medium publica tambien en dominios propios de publicaciones (infosecwriteups.com...),
# asi que para Medium solo se exige https.
_ALLOWED_HOSTS = {"hackerone": ("hackerone.com",)}


# --------------------------------------------------------------------------- utils
def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def safe_url(url: str, source: str) -> str:
    """Devuelve la URL si es https (y, para HackerOne, de hackerone.com); si no, ''."""
    try:
        p = urlparse((url or "").strip())
    except ValueError:
        return ""
    if p.scheme != "https" or not p.hostname:
        return ""
    host = p.hostname.lower()
    allowed = _ALLOWED_HOSTS.get(source, ())
    if any(host == h or host.endswith("." + h) for h in allowed):
        return url.strip()
    return url.strip() if source == "medium" else ""


def _strip_html(text: str, limit: int = 400) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _clean_medium_url(url: str) -> str:
    """Quita el ?source=rss... que añade Medium."""
    return url.split("?", 1)[0] if url else url


def _fetch(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URLs de config)
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"Descarga demasiado grande (> {MAX_DOWNLOAD_BYTES} bytes): {url}")
    return data


def _upsert(conn: sqlite3.Connection, rows: Iterable[dict]) -> int:
    cols = ["source", "url", "title", "program", "vuln_type", "severity", "bounty",
            "upvotes", "tags", "author", "published", "summary"]
    sql = (
        f"INSERT INTO refs ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
        "ON CONFLICT(url) DO UPDATE SET "
        + ", ".join(f"{c}=excluded.{c}" for c in cols if c != "url")
        + ", fetched_at=datetime('now')"
    )
    n = 0
    for r in rows:
        conn.execute(sql, [r.get(c) for c in cols])
        n += 1
    conn.commit()
    return n


# ----------------------------------------------------------------------- hackerone
def parse_hackerone(raw: bytes | str) -> list[dict]:
    """Normaliza el reports.json de codebygk/hackerone-bug-bounty-reports."""
    data = json.loads(raw)
    reports = data.get("reports", []) if isinstance(data, dict) else data
    out: list[dict] = []
    for r in reports:
        if not isinstance(r, dict):
            continue
        title = str(r.get("title") or "").strip()
        url = safe_url(str(r.get("url") or ""), "hackerone")
        if not title or not url:
            continue
        try:
            bounty = float(r.get("bounty") or 0)
        except (TypeError, ValueError):
            bounty = 0.0
        try:
            upvotes = int(r.get("upvotes") or 0)
        except (TypeError, ValueError):
            upvotes = 0
        out.append({
            "source": "hackerone",
            "url": url,
            "title": title[:300],
            "program": str(r.get("program") or "")[:120],
            "vuln_type": str(r.get("vulnerability_type") or "")[:160],
            "severity": str(r.get("severity") or "").lower()[:20],
            "bounty": bounty,
            "upvotes": upvotes,
            "tags": str(r.get("asset_type") or "")[:40],
            "author": "",
            "published": str(r.get("disclosed_at") or "")[:30],
            "summary": "",
        })
    return out


def sync_hackerone(conn: sqlite3.Connection, url: str, timeout: int = 60) -> int:
    ensure_schema(conn)
    rows = parse_hackerone(_fetch(url, timeout))
    return _upsert(conn, rows)


# -------------------------------------------------------------------------- medium
def parse_medium_rss(raw: bytes | str, tag: str = "") -> list[dict]:
    """Parsea un feed RSS de Medium (medium.com/feed/tag/<tag>)."""
    ns = {"dc": "http://purl.org/dc/elements/1.1/",
          "content": "http://purl.org/rss/1.0/modules/content/"}
    root = ET.fromstring(raw)
    out: list[dict] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        url = safe_url(_clean_medium_url((item.findtext("link") or "").strip()), "medium")
        if not title or not url:
            continue
        cats = [c.text.strip() for c in item.findall("category") if c.text]
        if tag and tag not in cats:
            cats.append(tag)
        body = item.findtext("content:encoded", namespaces=ns) or item.findtext("description") or ""
        published = item.findtext("pubDate") or ""
        try:
            published = parsedate_to_datetime(published).isoformat()
        except (TypeError, ValueError):
            pass
        out.append({
            "source": "medium",
            "url": url,
            "title": _strip_html(title, 300),
            "program": "",
            "vuln_type": "",
            "severity": "",
            "bounty": 0.0,
            "upvotes": 0,
            "tags": ",".join(sorted(set(cats)))[:300],
            "author": (item.findtext("dc:creator", namespaces=ns) or "").strip()[:120],
            "published": published[:30],
            "summary": _strip_html(body),
        })
    return out


def sync_medium(conn: sqlite3.Connection, tags: list[str], timeout: int = 30) -> tuple[int, list[str]]:
    """Descarga los feeds de cada etiqueta. Devuelve (filas, errores)."""
    ensure_schema(conn)
    total, errors = 0, []
    for tag in tags:
        tag = re.sub(r"[^a-z0-9-]", "", tag.strip().lower())
        if not tag:
            continue
        try:
            rows = parse_medium_rss(_fetch(f"https://medium.com/feed/tag/{tag}", timeout), tag)
            total += _upsert(conn, rows)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{tag}: {type(exc).__name__}: {exc}")
    return total, errors


# -------------------------------------------------------------------------- search
_STOPWORDS = {"de", "en", "el", "la", "los", "las", "del", "con", "por", "para", "un", "una",
              "the", "and", "for", "with", "via", "in", "on", "of", "detect", "detection",
              "panel", "page", "file", "version", "fichero", "accesible", "expuesto",
              "repositorio", "parametro", "busqueda"}


def _terms_for_finding(finding: dict) -> tuple[list[str], list[str], list[str]]:
    """(tipos H1, palabras clave de la clase, palabras del nombre del hallazgo)."""
    spec = knowledge.kb_for(finding.get("vuln_class", "generic"))
    refs_cfg = spec.get("refs", {}) or {}
    types = list(refs_cfg.get("hackerone_types", []))
    keywords = list(refs_cfg.get("keywords", []))
    # Palabras significativas del nombre: pesan mas (son lo especifico del hallazgo)
    name_words = [w.lower() for w in re.findall(r"[a-zA-Z0-9.\-]{3,}", finding.get("name") or "")
                  if w.lower() not in _STOPWORDS]
    return types, keywords, name_words


def search(conn: sqlite3.Connection, query: str = "", *, types: list[str] | None = None,
           keywords: list[str] | None = None, priority: list[str] | None = None,
           source: str | None = None, limit: int = 10) -> list[dict]:
    """Busca referencias puntuando coincidencias.

    - query: texto libre (se parte en palabras; cuentan como prioritarias).
    - types: tipos exactos/parciales de vulnerabilidad de HackerOne (peso alto).
    - keywords: palabras clave sobre titulo/etiquetas/resumen.
    - priority: palabras especificas (p.ej. del nombre del hallazgo) que pesan doble.
    Ordena por puntuacion y, a igualdad, por bounty y upvotes.
    """
    ensure_schema(conn)
    types = [t.lower() for t in (types or []) if t]
    prio = [w.lower() for w in re.findall(r"[\w.\-]{2,}", query or "")]
    prio += [p.lower() for p in (priority or []) if p]
    prio = set(prio)
    words = list(prio) + [k.lower() for k in (keywords or []) if k]
    words = list(dict.fromkeys(words))
    if not types and not words:
        return []

    conds, params = [], []
    for t in types:
        conds.append("lower(vuln_type) LIKE ?")
        params.append(f"%{t}%")
    for w in words:
        conds.append("(lower(title) LIKE ? OR lower(tags) LIKE ? OR lower(vuln_type) LIKE ?)")
        params += [f"%{w}%"] * 3
    sql = f"SELECT * FROM refs WHERE ({' OR '.join(conds)})"
    if source:
        sql += " AND source=?"
        params.append(source)
    rows = [dict(r) for r in _rows(conn, sql, params)]

    def score(r: dict) -> float:
        vt, title = (r.get("vuln_type") or "").lower(), (r.get("title") or "").lower()
        tags, summ = (r.get("tags") or "").lower(), (r.get("summary") or "").lower()
        s = sum(3 for t in types if t in vt)
        for w in words:
            m = 2 if w in prio else 1
            s += m * (2 if w in title else 0)
            s += m * (1 if w in tags or w in vt else 0)
            s += m * (0.5 if w in summ else 0)
        return s

    for r in rows:
        r["_score"] = score(r)
    rows.sort(key=lambda r: (r["_score"], r.get("bounty") or 0, r.get("upvotes") or 0),
              reverse=True)
    return rows[:limit]


def _rows(conn: sqlite3.Connection, sql: str, params: list[Any]):
    prev = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.row_factory = prev


def for_finding(conn: sqlite3.Connection, finding: dict, limit: int = 5) -> dict[str, list[dict]]:
    """Referencias relacionadas con un hallazgo, separadas por fuente."""
    types, keywords, name_words = _terms_for_finding(finding)
    return {
        "hackerone": search(conn, types=types, keywords=keywords, priority=name_words,
                            source="hackerone", limit=limit),
        "medium": search(conn, types=[], keywords=keywords + types, priority=name_words,
                         source="medium", limit=limit),
    }


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    ensure_schema(conn)
    out: dict[str, Any] = {}
    for src, n, last in conn.execute(
        "SELECT source, COUNT(*), MAX(fetched_at) FROM refs GROUP BY source"
    ).fetchall():
        out[src] = {"count": n, "last_sync": last}
    return out


def bounty_summary(rows: list[dict]) -> dict[str, Any]:
    """Resumen de bounties de una lista de informes H1 (para calibrar severidad)."""
    paid = sorted(r["bounty"] for r in rows if (r.get("bounty") or 0) > 0)
    if not paid:
        return {"n": len(rows), "paid": 0}
    mid = paid[len(paid) // 2]
    return {"n": len(rows), "paid": len(paid), "min": paid[0], "median": mid, "max": paid[-1]}


def prompt_context(rows: list[dict], limit: int = 5) -> str:
    """Bloque de texto para pasar a Claude. Se recorta y se marca como datos."""
    lines = []
    for r in rows[:limit]:
        title = re.sub(r"[\r\n`]+", " ", r.get("title") or "")[:150]
        lines.append(f"- [{r.get('severity') or '?'}] {title} | tipo: {r.get('vuln_type') or '?'}"
                     f" | bounty: {r.get('bounty') or 0:.0f} USD")
    return "\n".join(lines)
