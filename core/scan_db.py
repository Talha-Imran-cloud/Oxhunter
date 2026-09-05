"""
Scan History & Database Module (SQLite)
Stores scan results, history, and allows resume functionality
"""

import sqlite3
import json
import os
import uuid
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass, field


@dataclass
class ScanRecord:
    """Represents a scan session record"""
    scan_id: str
    target: str
    started_at: str
    finished_at: str
    status: str          # 'running', 'completed', 'paused', 'failed'
    modules_run: List[str]
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    scan_config: Dict


@dataclass
class FindingRecord:
    """Represents a single finding stored in DB"""
    finding_id: str
    scan_id: str
    module: str
    type: str
    severity: str
    confidence: str
    url: str
    evidence: str
    remediation: str
    created_at: str
    extra: Dict = field(default_factory=dict)


class ScanDatabase:
    """
    SQLite-based Scan History & Resume Database
    Features:
    - Store scan sessions with full metadata
    - Save findings per scan
    - Resume interrupted scans
    - Query scan history
    - Export scan data
    - Multi-target tracking
    """

    def __init__(self, db_path: str = "data/oxhunter_scans.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
        self.conn = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-safe DB connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        """Initialize database schema"""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id         TEXT PRIMARY KEY,
                    target          TEXT NOT NULL,
                    started_at      TEXT NOT NULL,
                    finished_at     TEXT,
                    status          TEXT DEFAULT 'running',
                    modules_run     TEXT DEFAULT '[]',
                    total_findings  INTEGER DEFAULT 0,
                    critical        INTEGER DEFAULT 0,
                    high            INTEGER DEFAULT 0,
                    medium          INTEGER DEFAULT 0,
                    low             INTEGER DEFAULT 0,
                    info            INTEGER DEFAULT 0,
                    scan_config     TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id      TEXT PRIMARY KEY,
                    scan_id         TEXT NOT NULL,
                    module          TEXT NOT NULL,
                    type            TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    confidence      TEXT NOT NULL,
                    url             TEXT NOT NULL,
                    evidence        TEXT,
                    remediation     TEXT,
                    created_at      TEXT NOT NULL,
                    extra           TEXT DEFAULT '{}',
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS scan_progress (
                    scan_id         TEXT NOT NULL,
                    module          TEXT NOT NULL,
                    status          TEXT DEFAULT 'pending',
                    started_at      TEXT,
                    finished_at     TEXT,
                    urls_scanned    INTEGER DEFAULT 0,
                    PRIMARY KEY (scan_id, module),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS targets (
                    target_id       TEXT PRIMARY KEY,
                    url             TEXT NOT NULL UNIQUE,
                    added_at        TEXT NOT NULL,
                    last_scanned    TEXT,
                    scan_count      INTEGER DEFAULT 0,
                    notes           TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_module    ON findings(module);
                CREATE INDEX IF NOT EXISTS idx_scans_target       ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_status       ON scans(status);
            """)
            conn.commit()
        finally:
            conn.close()

    # ── Scan Management ───────────────────────────────────────────────────────

    def create_scan(self, target: str, modules: List[str],
                    config: Optional[Dict] = None) -> str:
        """Create a new scan session, return scan_id"""
        scan_id = str(uuid.uuid4())
        now     = datetime.utcnow().isoformat()

        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO scans
                    (scan_id, target, started_at, status, modules_run, scan_config)
                VALUES (?, ?, ?, 'running', ?, ?)
            """, (scan_id, target, now,
                  json.dumps(modules),
                  json.dumps(config or {})))

            # Init progress for each module
            for module in modules:
                conn.execute("""
                    INSERT INTO scan_progress (scan_id, module, status)
                    VALUES (?, ?, 'pending')
                """, (scan_id, module))

            # Update target table
            conn.execute("""
                INSERT INTO targets (target_id, url, added_at, scan_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(url) DO UPDATE SET
                    scan_count = scan_count + 1,
                    last_scanned = excluded.added_at
            """, (str(uuid.uuid4()), target, now))

            conn.commit()
        finally:
            conn.close()

        return scan_id

    def update_scan_status(self, scan_id: str, status: str,
                           findings_summary: Optional[Dict] = None):
        """Update scan status and findings count"""
        now  = datetime.utcnow().isoformat()
        conn = self._get_conn()
        try:
            if findings_summary:
                conn.execute("""
                    UPDATE scans SET
                        status         = ?,
                        finished_at    = ?,
                        total_findings = ?,
                        critical       = ?,
                        high           = ?,
                        medium         = ?,
                        low            = ?,
                        info           = ?
                    WHERE scan_id = ?
                """, (
                    status, now,
                    findings_summary.get('total', 0),
                    findings_summary.get('critical', 0),
                    findings_summary.get('high', 0),
                    findings_summary.get('medium', 0),
                    findings_summary.get('low', 0),
                    findings_summary.get('info', 0),
                    scan_id
                ))
            else:
                conn.execute("""
                    UPDATE scans SET status = ?, finished_at = ?
                    WHERE scan_id = ?
                """, (status, now, scan_id))
            conn.commit()
        finally:
            conn.close()

    def update_module_progress(self, scan_id: str, module: str,
                                status: str, urls_scanned: int = 0):
        """Update module scan progress"""
        now  = datetime.utcnow().isoformat()
        conn = self._get_conn()
        try:
            if status == 'running':
                conn.execute("""
                    UPDATE scan_progress SET status = ?, started_at = ?
                    WHERE scan_id = ? AND module = ?
                """, (status, now, scan_id, module))
            else:
                conn.execute("""
                    UPDATE scan_progress
                    SET status = ?, finished_at = ?, urls_scanned = ?
                    WHERE scan_id = ? AND module = ?
                """, (status, now, urls_scanned, scan_id, module))
            conn.commit()
        finally:
            conn.close()

    def pause_scan(self, scan_id: str):
        """Pause a running scan"""
        self.update_scan_status(scan_id, 'paused')

    def resume_scan(self, scan_id: str) -> Optional[Dict]:
        """
        Get resume data for a paused/interrupted scan.
        Returns dict with pending modules and already-found findings.
        """
        conn = self._get_conn()
        try:
            # Get scan info
            scan = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()

            if not scan:
                return None

            # Get pending modules
            pending = conn.execute("""
                SELECT module FROM scan_progress
                WHERE scan_id = ? AND status IN ('pending', 'running')
            """, (scan_id,)).fetchall()

            # Get completed modules
            completed = conn.execute("""
                SELECT module FROM scan_progress
                WHERE scan_id = ? AND status = 'completed'
            """, (scan_id,)).fetchall()

            # Update status back to running
            conn.execute(
                "UPDATE scans SET status = 'running' WHERE scan_id = ?",
                (scan_id,)
            )
            conn.commit()

            return {
                'scan_id':          scan_id,
                'target':           scan['target'],
                'pending_modules':  [r['module'] for r in pending],
                'completed_modules':[r['module'] for r in completed],
                'config':           json.loads(scan['scan_config']),
            }
        finally:
            conn.close()

    # ── Findings Management ───────────────────────────────────────────────────

    def save_finding(self, scan_id: str, module: str, finding) -> str:
        """Save a single finding to database"""
        finding_id = str(uuid.uuid4())
        now        = datetime.utcnow().isoformat()

        # Extract common fields from finding dataclass
        severity    = getattr(finding, 'severity',    'info')
        confidence  = getattr(finding, 'confidence',  'low')
        url         = getattr(finding, 'url',         '')
        evidence    = getattr(finding, 'evidence',    '')
        remediation = getattr(finding, 'remediation', '')
        ftype       = getattr(finding, 'type',        module)

        # Store extra fields as JSON
        extra = {}
        for attr in ['payload', 'parameter', 'bypass_technique', 'match',
                     'js_file', 'waf_name', 'session_cookie', 'subdomain']:
            val = getattr(finding, attr, None)
            if val:
                extra[attr] = str(val)[:500]

        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO findings
                    (finding_id, scan_id, module, type, severity, confidence,
                     url, evidence, remediation, created_at, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id, scan_id, module, ftype, severity, confidence,
                url, evidence[:2000], remediation[:2000], now,
                json.dumps(extra)
            ))
            conn.commit()
        finally:
            conn.close()

        return finding_id

    def save_findings_bulk(self, scan_id: str, module: str, findings: List) -> int:
        """Save multiple findings at once"""
        if not findings:
            return 0

        saved = 0
        for finding in findings:
            try:
                self.save_finding(scan_id, module, finding)
                saved += 1
            except Exception:  # BUG-013 FIX: removed unused 'as e'
                pass

        return saved

    def get_findings(self, scan_id: str, severity: Optional[str] = None,
                     module: Optional[str] = None) -> List[Dict]:
        """Get findings for a scan with optional filters"""
        conn = self._get_conn()
        try:
            query  = "SELECT * FROM findings WHERE scan_id = ?"
            params = [scan_id]

            if severity:
                query  += " AND severity = ?"
                params.append(severity)
            if module:
                query  += " AND module = ?"
                params.append(module)

            query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"

            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_findings_summary(self, scan_id: str) -> Dict:
        """Get severity summary for a scan"""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings WHERE scan_id = ?
                GROUP BY severity
            """, (scan_id,)).fetchall()

            summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
            for row in rows:
                sev = row['severity'].lower()
                if sev in summary:
                    summary[sev] = row['count']
                    summary['total'] += row['count']

            return summary
        finally:
            conn.close()

    # ── History & Reporting ───────────────────────────────────────────────────

    def get_scan_history(self, limit: int = 20, target: Optional[str] = None) -> List[Dict]:
        """Get scan history"""
        conn = self._get_conn()
        try:
            if target:
                rows = conn.execute("""
                    SELECT * FROM scans WHERE target LIKE ?
                    ORDER BY started_at DESC LIMIT ?
                """, (f"%{target}%", limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM scans
                    ORDER BY started_at DESC LIMIT ?
                """, (limit,)).fetchall()

            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_scan_detail(self, scan_id: str) -> Optional[Dict]:
        """Get full scan details with findings"""
        conn = self._get_conn()
        try:
            scan = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()

            if not scan:
                return None

            scan_dict = dict(scan)
            scan_dict['findings'] = self.get_findings(scan_id)
            scan_dict['summary']  = self.get_findings_summary(scan_id)
            scan_dict['progress'] = [
                dict(r) for r in conn.execute(
                    "SELECT * FROM scan_progress WHERE scan_id = ?", (scan_id,)
                ).fetchall()
            ]
            return scan_dict
        finally:
            conn.close()

    def get_all_targets(self) -> List[Dict]:
        """Get all scanned targets"""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM targets ORDER BY last_scanned DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all its findings"""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM findings      WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scan_progress WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans         WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def export_scan_json(self, scan_id: str) -> Optional[str]:
        """Export full scan data as JSON string"""
        detail = self.get_scan_detail(scan_id)
        if not detail:
            return None
        return json.dumps(detail, indent=2, default=str)

    def search_findings(self, query: str, limit: int = 50) -> List[Dict]:
        """Full-text search across findings"""
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT f.*, s.target FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE f.evidence LIKE ? OR f.url LIKE ? OR f.type LIKE ?
                ORDER BY CASE f.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_stats(self) -> Dict:
        """Get overall database statistics"""
        conn = self._get_conn()
        try:
            total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_targets  = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='critical'"
            ).fetchone()[0]

            recent = conn.execute("""
                SELECT target, started_at, total_findings, status
                FROM scans ORDER BY started_at DESC LIMIT 5
            """).fetchall()

            return {
                'total_scans':    total_scans,
                'total_findings': total_findings,
                'total_targets':  total_targets,
                'critical_total': critical_count,
                'recent_scans':   [dict(r) for r in recent],
            }
        finally:
            conn.close()

    def print_history(self):
        """Print formatted scan history to console"""
        history = self.get_scan_history(limit=10)
        if not history:
            print("No scan history found.")
            return

        print("\n" + "="*80)
        print(f"{'SCAN ID':<36} {'TARGET':<30} {'STATUS':<10} {'FINDINGS':<8} {'DATE'}")
        print("="*80)
        for scan in history:
            scan_id   = scan['scan_id'][:8] + "..."
            target    = scan['target'][:28]
            status    = scan['status']
            findings  = scan['total_findings']
            date      = scan['started_at'][:16]
            print(f"{scan_id:<36} {target:<30} {status:<10} {findings:<8} {date}")
        print("="*80 + "\n")
