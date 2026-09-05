"""Stable paths for files bundled with OXHUNTER.
FIXED: WARN-001 — exports PAYLOADS_DIR and REPORTS_DIR
"""
from pathlib import Path

# core/ directory — always available after install
_CORE_DIR     = Path(__file__).resolve().parent
_PROJECT_ROOT = _CORE_DIR.parent

# ── Canonical path exports (importable by all modules) ──────────
PAYLOADS_DIR = _PROJECT_ROOT / "payloads"
REPORTS_DIR  = _PROJECT_ROOT / "reports"

# config.yaml lives inside core/ package (bundled with the wheel)
DEFAULT_CONFIG_PATH = _CORE_DIR / "config.yaml"
_ROOT_CONFIG        = _PROJECT_ROOT / "config.yaml"


def resolve_config_path(config_path=None) -> Path:
    """Resolve the bundled default or an explicit user-supplied config path."""
    if config_path is None or str(config_path) == "config.yaml":
        # BUG-008 FIX: check root config first so user edits are respected
        if _ROOT_CONFIG.is_file():
            return _ROOT_CONFIG
        if DEFAULT_CONFIG_PATH.is_file():
            return DEFAULT_CONFIG_PATH
        raise FileNotFoundError(
            f"Configuration file not found. Looked in:\n"
            f"  {DEFAULT_CONFIG_PATH}\n"
            f"  {_ROOT_CONFIG}"
        )
    path = Path(config_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    return path
