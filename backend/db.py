"""
db.py — SQLite persistence for scans and findings
===================================================
Extends the users.db with scans + findings tables.
"""
import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("DB_PATH", "/root/pyrit-ui-backend/users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_scans_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'queued',
                progress     INTEGER DEFAULT 0,
                total_attacks INTEGER DEFAULT 0,
                completed_attacks INTEGER DEFAULT 0,
                started_at   TEXT NOT NULL,
                completed_at TEXT,
                asr          REAL DEFAULT 0.0,
                source       TEXT DEFAULT 'pending',
                owner        TEXT NOT NULL,
                error        TEXT,
                config_json  TEXT,
                scorecard_json TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id           TEXT PRIMARY KEY,
                scan_id      TEXT NOT NULL,
                category     TEXT NOT NULL,
                strategy     TEXT NOT NULL,
                prompt       TEXT,
                response     TEXT,
                result       TEXT NOT NULL,
                severity     TEXT NOT NULL,
                owasp_id     TEXT,
                owasp_name   TEXT,
                mitre_id     TEXT,
                mitre_name   TEXT,
                attack_success INTEGER DEFAULT 0,
                owner        TEXT,
                score        REAL,
                threshold    INTEGER DEFAULT 3,
                reason       TEXT,
                complexity   TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
        conn.commit()


# ── Scan CRUD ─────────────────────────────────────────────────────────────────
def db_create_scan(scan: Dict) -> None:
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO scans
            (id, name, status, progress, total_attacks, completed_attacks,
             started_at, completed_at, asr, source, owner, error, config_json, scorecard_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan["id"], scan["name"], scan["status"], scan.get("progress", 0),
            scan.get("total_attacks", 0), scan.get("completed_attacks", 0),
            scan["started_at"], scan.get("completed_at"),
            scan.get("asr", 0.0), scan.get("source", "pending"),
            scan.get("owner", ""), scan.get("error"),
            json.dumps(scan.get("config", {})),
            json.dumps(scan.get("scorecard")) if scan.get("scorecard") else None,
        ))
        conn.commit()


def db_update_scan(scan_id: str, **kwargs) -> None:
    if not kwargs:
        return
    fields = []
    values = []
    for k, v in kwargs.items():
        if k == "scorecard":
            fields.append("scorecard_json = ?")
            values.append(json.dumps(v) if v else None)
        else:
            fields.append(f"{k} = ?")
            values.append(v)
    values.append(scan_id)
    with get_db() as conn:
        conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()


def db_save_findings(scan_id: str, findings: List[Dict], owner: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        for f in findings:
            conn.execute("""
                INSERT INTO findings
                (id, scan_id, category, strategy, prompt, response, result, severity,
                 owasp_id, owasp_name, mitre_id, mitre_name, attack_success, owner,
                 score, threshold, reason, complexity)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                f["id"], scan_id, f["category"], f["strategy"],
                f.get("prompt", "")[:1000], f.get("response", "")[:2000],
                f["result"], f["severity"],
                f.get("owasp", {}).get("id", ""), f.get("owasp", {}).get("name", ""),
                f.get("mitre", {}).get("id", ""), f.get("mitre", {}).get("name", ""),
                1 if f.get("attack_success") else 0, owner,
                f.get("score"), f.get("threshold", 3),
                f.get("reason", ""), f.get("complexity", "easy"),
            ))
        conn.commit()


def db_get_scan(scan_id: str) -> Optional[Dict]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["config"] = json.loads(d.pop("config_json") or "{}")
    d["scorecard"] = json.loads(d.pop("scorecard_json") or "null")
    return d


def db_list_scans(owner: Optional[str] = None, role: str = "admin") -> List[Dict]:
    with get_db() as conn:
        if role == "admin":
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans WHERE owner=? ORDER BY started_at DESC", (owner,)).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d.pop("config_json", None)
        d.pop("scorecard_json", None)
        result.append(d)
    return result


def db_get_findings(scan_id: str, result: str = None, severity: str = None, category: str = None) -> List[Dict]:
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params = [scan_id]
    if result:
        query += " AND result = ?"
        params.append(result.upper())
    if severity:
        query += " AND severity = ?"
        params.append(severity.lower())
    if category:
        query += " AND category = ?"
        params.append(category.lower())
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def db_delete_scan(scan_id: str) -> bool:
    with get_db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
    return cur.rowcount > 0


# ── Dashboard stats ───────────────────────────────────────────────────────────
def db_global_stats(owner: str = None, role: str = "admin") -> Dict:
    with get_db() as conn:
        if role == "admin":
            scans = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='completed'").fetchone()["c"]
            total_attacks = conn.execute("SELECT COALESCE(SUM(total_attacks),0) as s FROM scans WHERE status='completed'").fetchone()["s"]
            critical = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='critical'").fetchone()["c"]
            high = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='high'").fetchone()["c"]
            failed = conn.execute("SELECT COUNT(*) as c FROM findings WHERE result='FAIL'").fetchone()["c"]
            total_f = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
            owasp = conn.execute("SELECT DISTINCT owasp_id FROM findings WHERE owasp_id != ''").fetchall()
            recent = conn.execute("SELECT id,name,asr,started_at,owner,source FROM scans WHERE status='completed' ORDER BY started_at DESC LIMIT 10").fetchall()
            top_cats = conn.execute("""
                SELECT category, COUNT(*) as total,
                       SUM(CASE WHEN result='FAIL' THEN 1 ELSE 0 END) as failed
                FROM findings GROUP BY category ORDER BY failed DESC LIMIT 5
            """).fetchall()
            trend = conn.execute("""
                SELECT name, asr, started_at FROM scans
                WHERE status='completed' ORDER BY started_at DESC LIMIT 10
            """).fetchall()
        else:
            scans = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='completed' AND owner=?", (owner,)).fetchone()["c"]
            total_attacks = conn.execute("SELECT COALESCE(SUM(total_attacks),0) as s FROM scans WHERE status='completed' AND owner=?", (owner,)).fetchone()["s"]
            critical = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='critical' AND owner=?", (owner,)).fetchone()["c"]
            high = conn.execute("SELECT COUNT(*) as c FROM findings WHERE severity='high' AND owner=?", (owner,)).fetchone()["c"]
            failed = conn.execute("SELECT COUNT(*) as c FROM findings WHERE result='FAIL' AND owner=?", (owner,)).fetchone()["c"]
            total_f = conn.execute("SELECT COUNT(*) as c FROM findings WHERE owner=?", (owner,)).fetchone()["c"]
            owasp = conn.execute("SELECT DISTINCT owasp_id FROM findings WHERE owasp_id != '' AND owner=?", (owner,)).fetchall()
            recent = conn.execute("SELECT id,name,asr,started_at,owner,source FROM scans WHERE status='completed' AND owner=? ORDER BY started_at DESC LIMIT 10", (owner,)).fetchall()
            top_cats = conn.execute("""
                SELECT category, COUNT(*) as total,
                       SUM(CASE WHEN result='FAIL' THEN 1 ELSE 0 END) as failed
                FROM findings WHERE owner=? GROUP BY category ORDER BY failed DESC LIMIT 5
            """, (owner,)).fetchall()
            trend = conn.execute("""
                SELECT name, asr, started_at FROM scans
                WHERE status='completed' AND owner=? ORDER BY started_at DESC LIMIT 10
            """, (owner,)).fetchall()

    asr = round(failed / total_f * 100, 1) if total_f else 0.0
    return {
        "completed_scans": scans,
        "total_attacks": total_attacks,
        "overall_asr": asr,
        "critical_findings": critical,
        "high_findings": high,
        "owasp_coverage": [r["owasp_id"] for r in owasp],
        "recent_scans": [dict(r) for r in recent],
        "top_categories": [{"category": r["category"], "total": r["total"], "failed": r["failed"], "asr": round(r["failed"]/r["total"]*100,1) if r["total"] else 0} for r in top_cats],
        "trend": [{"name": r["name"], "asr": r["asr"], "date": r["started_at"][:10]} for r in reversed(trend)],
    }

# ── Prompt libraries ──────────────────────────────────────────────────────────
def init_prompt_library():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS prompt_libraries (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                description TEXT,
                prompts_json TEXT NOT NULL,
                owner      TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()

def db_save_prompt_library(lib_id: str, name: str, description: str, prompts: list, owner: str) -> dict:
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM prompt_libraries WHERE id=?", (lib_id,)).fetchone()
        if existing:
            conn.execute("""
                UPDATE prompt_libraries SET name=?, description=?, prompts_json=?, updated_at=?
                WHERE id=? AND owner=?
            """, (name, description, json.dumps(prompts), now, lib_id, owner))
        else:
            conn.execute("""
                INSERT INTO prompt_libraries (id, name, description, prompts_json, owner, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?)
            """, (lib_id, name, description, json.dumps(prompts), owner, now, now))
        conn.commit()
    return db_get_prompt_library(lib_id)

def db_get_prompt_library(lib_id: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM prompt_libraries WHERE id=?", (lib_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["prompts"] = json.loads(d.pop("prompts_json", "[]"))
    return d

def db_list_prompt_libraries(owner: str, role: str = "analyst") -> list:
    with get_db() as conn:
        if role == "admin":
            rows = conn.execute("SELECT * FROM prompt_libraries ORDER BY updated_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM prompt_libraries WHERE owner=? ORDER BY updated_at DESC", (owner,)).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["prompts"] = json.loads(d.pop("prompts_json", "[]"))
        d["prompt_count"] = len(d["prompts"])
        result.append(d)
    return result

def db_delete_prompt_library(lib_id: str, owner: str, role: str = "analyst") -> bool:
    with get_db() as conn:
        if role == "admin":
            cur = conn.execute("DELETE FROM prompt_libraries WHERE id=?", (lib_id,))
        else:
            cur = conn.execute("DELETE FROM prompt_libraries WHERE id=? AND owner=?", (lib_id, owner))
        conn.commit()
    return cur.rowcount > 0
