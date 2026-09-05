"""
OXHUNTER - utils/logger.py
Compatibility logger — wraps core.logger for all modules
"""

import logging
import sys

# ── Colors ────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
B   = "\033[94m"
C   = "\033[96m"
DIM = "\033[2m"
RST = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": R, "HIGH": R,
    "MEDIUM":   Y, "LOW":  B, "INFO": G,
}


class ModuleLogger:
    """
    Lightweight logger used by all scanner modules.
    Compatible with both asyncio modules and sync code.
    """

    def __init__(self, name: str, verbose: bool = False, silent: bool = False):
        self.name    = name
        self.verbose = verbose
        self.silent  = silent
        self._log    = logging.getLogger(f"oxhunter.{name}")
        if not self._log.handlers:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(logging.Formatter(
                f"%(asctime)s [{name}] %(levelname)s: %(message)s",
                datefmt="%H:%M:%S"
            ))
            self._log.addHandler(h)
        self._log.setLevel(logging.DEBUG if verbose else logging.INFO)
        self._log.propagate = False

    def _print(self, prefix: str, color: str, msg: str):
        if not self.silent:
            print(f"{color}[{prefix}]{RST} {msg}", flush=True)

    def info(self, msg: str):
        self._print("*", C, msg)
        self._log.info(msg)

    def success(self, msg: str):
        self._print("+", G, msg)
        self._log.info(f"SUCCESS: {msg}")

    def warning(self, msg: str):
        self._print("!", Y, msg)
        self._log.warning(msg)

    def error(self, msg: str):
        self._print("✗", R, msg)
        self._log.error(msg)

    def debug(self, msg: str):
        if self.verbose:
            self._print("~", DIM, msg)
        self._log.debug(msg)

    def vuln(self, severity: str, vuln_type: str, url: str, detail: str = ""):
        color = SEVERITY_COLOR.get(severity.upper(), R)
        print(f"\n{color}[VULN]{RST} [{severity}] {vuln_type}")
        print(f"  URL    : {url}")
        if detail:
            print(f"  Detail : {detail[:120]}")
        self._log.warning(f"VULN|{severity}|{vuln_type}|{url}")


# ── Global registry ───────────────────────────
_loggers: dict = {}


def setup_logger(name: str, verbose: bool = False,
                 silent: bool = False) -> ModuleLogger:
    """
    Main factory used by all modules:
        from utils.logger import setup_logger
        self.logger = setup_logger("XSS")
    """
    if name not in _loggers:
        _loggers[name] = ModuleLogger(name, verbose=verbose, silent=silent)
    return _loggers[name]


def get_logger(name: str = "OXHUNTER") -> ModuleLogger:
    """Alias for setup_logger."""
    return setup_logger(name)


def set_verbose(state: bool = True):
    """Enable verbose mode on all loggers."""
    for logger in _loggers.values():
        logger.verbose = state
        logger._log.setLevel(logging.DEBUG if state else logging.INFO)


def set_silent(state: bool = True):
    """Enable silent mode on all loggers."""
    for logger in _loggers.values():
        logger.silent = state
