"""Almacenamiento en SQLite para assets y findings."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .references import SCHEMA as REFS_SCHEMA

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program    TEXT NOT NULL,
    host       TEXT NOT NULL,
    url        TEXT,
    ip         TEXT,
    port       INTEGER,
    tech       TEXT,
    source     TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program     TEXT NOT NULL,
    dedup_hash  TEXT NOT NULL,
    vuln_class  TEXT,
    name        TEXT,
    template_id TEXT,
    url         TEXT,
    param       TEXT,
    severity    TEXT,
    cvss_score  REAL,
    cvss_vector TEXT,
    vrt_tier    TEXT,
    evidence    TEXT,
    explanation TEXT,
    reproduction TEXT,
    impact      TEXT,
    remediation TEXT,
    refs        TEXT,
    status      TEXT DEFAULT 'new',
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(program, dedup_hash)
);
"""


class DB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.executescript(REFS_SCHEMA)
        self.conn.commit()

    # ---- assets ----
    def upsert_asset(self, program: str, **fields: Any) -> None:
        fields.setdefault("host", "")
        cols = ["program"] + list(fields.keys())
        vals = [program] + list(fields.values())
        placeholders = ", ".join(["?"] * len(cols))
        updates = ", ".join(f"{c}=excluded.{c}" for c in fields if c != "url")
        sql = (
            f"INSERT INTO assets ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(program, url) DO UPDATE SET {updates}"
        )
        self.conn.execute(sql, vals)
        self.conn.commit()

    def assets(self, program: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM assets WHERE program=? ORDER BY host", (program,)
        ).fetchall()
        return [dict(r) for r in rows]

    def live_urls(self, program: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT url FROM assets WHERE program=? AND url IS NOT NULL", (program,)
        ).fetchall()
        return [r["url"] for r in rows]

    # ---- findings ----
    def insert_finding(self, program: str, dedup_hash: str, **fields: Any) -> bool:
        """Devuelve True si se inserto, False si ya existia (duplicado)."""
        for k in ("evidence", "refs"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], ensure_ascii=False)
        cols = ["program", "dedup_hash"] + list(fields.keys())
        vals = [program, dedup_hash] + list(fields.values())
        placeholders = ", ".join(["?"] * len(cols))
        sql = (
            f"INSERT OR IGNORE INTO findings ({', '.join(cols)}) "
            f"VALUES ({placeholders})"
        )
        cur = self.conn.execute(sql, vals)
        self.conn.commit()
        return cur.rowcount > 0

    def update_finding(self, finding_id: int, **fields: Any) -> None:
        for k in ("evidence", "refs"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = json.dumps(fields[k], ensure_ascii=False)
        sets = ", ".join(f"{c}=?" for c in fields)
        vals = list(fields.values()) + [finding_id]
        self.conn.execute(f"UPDATE findings SET {sets} WHERE id=?", vals)
        self.conn.commit()

    def set_status(self, finding_id: int, status: str) -> None:
        self.conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.conn.commit()

    def findings(self, program: str | None = None, status: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if program:
            q += " AND program=?"
            params.append(program)
        if status:
            q += " AND status=?"
            params.append(status)
        q += " ORDER BY cvss_score DESC, id DESC"
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def finding(self, finding_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()
