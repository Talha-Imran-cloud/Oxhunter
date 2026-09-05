"""
OXHUNTER - logger.py
Colored Console + File Logging
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Colors ────────────────────────────────────
R  = "\033[91m"   # Red
Y  = "\033[93m"   # Yellow
G  = "\033[92m"   # Green
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
DIM= "\033[2m"
RST= "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": R, "HIGH": R, "MEDIUM": Y,
    "LOW": B, "INFO": G,
}

BANNER = f"""{M}
  ██████  ██   ██ ██   ██ ██    ██ ███    ██ ████████ ███████ ██████
 ██    ██  ██ ██  ██   ██ ██    ██ ████   ██    ██    ██      ██   ██
 ██    ██   ███   ███████ ██    ██ ██ ██  ██    ██    █████   ██████
 ██    ██  ██ ██  ██   ██ ██    ██ ██  ██ ██    ██    ██      ██   ██
  ██████  ██   ██ ██   ██  ██████  ██   ████    ██    ███████ ██   ██
{C}              Advanced Web Security Scanner v1.0{RST}
"""


class OXLogger:
    """Colored console + optional file logger."""

    def __init__(self, name: str = "OXHUNTER", log_file: Optional[str] = None,
                 verbose: bool = False, silent: bool = False):
        self.verbose = verbose
        self.silent  = silent
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
            self._logger.addHandler(fh)

    def _print(self, prefix: str, color: str, msg: str):
        if not self.silent:
            print(f"{color}[{prefix}]{RST} {msg}")

    def info(self, msg: str):
        self._print("*", C, msg)
        self._logger.info(msg)

    def success(self, msg: str):
        self._print("+", G, msg)
        self._logger.info(f"SUCCESS: {msg}")

    def warning(self, msg: str):
        self._print("!", Y, msg)
        self._logger.warning(msg)

    def error(self, msg: str):
        self._print("✗", R, msg)
        self._logger.error(msg)

    def debug(self, msg: str):
        if self.verbose:
            self._print("~", DIM, msg)
        self._logger.debug(msg)

    def vuln(self, vuln_type: str, severity: str, url: str, detail: str = ""):
        color = SEVERITY_COLOR.get(severity.upper(), W)
        print(f"\n{color}[VULN FOUND]{RST}")
        print(f"  {W}Type    :{RST} {vuln_type}")
        print(f"  {W}Severity:{RST} {color}{severity}{RST}")
        print(f"  {W}URL     :{RST} {url}")
        if detail:
            print(f"  {W}Detail  :{RST} {detail}")
        self._logger.warning(f"VULN|{severity}|{vuln_type}|{url}|{detail}")

    def scan_start(self, target: str):
        print(f"\n{G}[+] Scan Started{RST} → {C}{target}{RST}")
        print(f"{DIM}    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}\n")

    def scan_end(self, total_vulns: int, elapsed: float):
        print(f"\n{G}[✓] Scan Complete{RST}")
        print(f"    Vulnerabilities : {R if total_vulns else G}{total_vulns}{RST}")
        print(f"    Time Taken      : {elapsed:.1f}s\n")

    def banner(self):
        if not self.silent:
            print(BANNER)

    def progress(self, current: int, total: int, label: str = ""):
        if self.silent:
            return
        pct  = int((current / max(total, 1)) * 40)
        bar  = f"{G}{'█' * pct}{DIM}{'░' * (40 - pct)}{RST}"
        print(f"\r  [{bar}] {current}/{total} {label}", end="", flush=True)
        if current >= total:
            print()


# ── Singleton ─────────────────────────────────
_log: Optional[OXLogger] = None

def get_logger(log_file: Optional[str] = None,
               verbose: bool = False, silent: bool = False) -> OXLogger:
    global _log
    if _log is None:
        _log = OXLogger(log_file=log_file, verbose=verbose, silent=silent)
    return _log
