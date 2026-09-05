"""
OXHUNTER - resume.py
Scan Resume/Pause - SQLite based checkpoint system
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Optional, List, Dict

DB_PATH = Path("data/resume.db")


class ResumeManager:
    """Save and restore scan progress using SQLite."""

    def __init__(self, db_path: str = str(DB_PATH)):
        self.db = Path(db_path)
        self.db.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db)

    def _init_db(self):
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id   TEXT PRIMARY KEY,
                    target    TEXT,
                    config    TEXT,
                    status    TEXT DEFAULT 'running',
                    started   REAL,
                    updated   REAL
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS progress (
                    scan_id   TEXT,
                    url       TEXT,
                    module    TEXT,
                    done      INTEGER DEFAULT 0,
                    result    TEXT,
                    PRIMARY KEY (scan_id, url, module)
                )""")

    # ── Scan Lifecycle ────────────────────────

    def start(self, scan_id: str, target: str, config: Dict) -> bool:
        """Register new scan."""
        try:
            with self._conn() as c:
                c.execute("INSERT OR IGNORE INTO scans VALUES (?,?,?,?,?,?)",
                    (scan_id, target, json.dumps(config), "running", time.time(), time.time()))
            return True
        except Exception:
            return False

    def pause(self, scan_id: str):
        self._set_status(scan_id, "paused")

    def complete(self, scan_id: str):
        self._set_status(scan_id, "completed")

    def _set_status(self, scan_id: str, status: str):
        with self._conn() as c:
            c.execute("UPDATE scans SET status=?, updated=? WHERE scan_id=?",
                      (status, time.time(), scan_id))

    # ── Progress Tracking ─────────────────────

    def mark_done(self, scan_id: str, url: str, module: str, result: Dict = None):  # BUG-002 FIX: mutable default arg
        """Mark a URL+module combo as scanned."""
        result = result or {}  # BUG-002 FIX: fresh dict every call
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO progress VALUES (?,?,?,1,?)",
                      (scan_id, url, module, json.dumps(result)))

    def is_done(self, scan_id: str, url: str, module: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT done FROM progress WHERE scan_id=? AND url=? AND module=?",
                (scan_id, url, module)).fetchone()
            return bool(row and row[0])

    def pending(self, scan_id: str, urls: List[str], module: str) -> List[str]:
        """Return only URLs not yet scanned for a module."""
        return [u for u in urls if not self.is_done(scan_id, u, module)]

    # ── Restore ───────────────────────────────

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if not row:
                return None
            return {"scan_id": row[0], "target": row[1],
                    "config": json.loads(row[2]), "status": row[3]}

    def list_scans(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT scan_id, target, status, started FROM scans ORDER BY started DESC"
            ).fetchall()
            return [{"scan_id": r[0], "target": r[1],
                     "status": r[2], "started": r[3]} for r in rows]

    def get_results(self, scan_id: str) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT url, module, result FROM progress WHERE scan_id=? AND done=1",
                (scan_id,)).fetchall()
            return [{"url": r[0], "module": r[1],
                     "result": json.loads(r[2])} for r in rows]

    def delete(self, scan_id: str):
        with self._conn() as c:
            c.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
            c.execute("DELETE FROM progress WHERE scan_id=?", (scan_id,))

    def stats(self, scan_id: str) -> Dict:
        with self._conn() as c:
            total = c.execute(
                "SELECT COUNT(*) FROM progress WHERE scan_id=?", (scan_id,)).fetchone()[0]
            done  = c.execute(
                "SELECT COUNT(*) FROM progress WHERE scan_id=? AND done=1", (scan_id,)).fetchone()[0]
            return {"total": total, "done": done, "pending": total - done,
                    "pct": round(done / max(total, 1) * 100, 1)}
