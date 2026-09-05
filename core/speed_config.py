"""
OXHUNTER - speed_config.py
Speed Preset System — Fast / Normal / Stealth modes

Usage (in oxhunter CLI):
    --speed fast      →  threads=20, delay=0.1, timeout=10
    --speed normal    →  threads=10, delay=0.5, timeout=20  (default)
    --speed stealth   →  threads=2,  delay=3.0, timeout=30
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SpeedPreset:
    name            : str
    threads         : int
    delay           : float
    timeout         : int
    crawler_batch   : int   # URLs crawled per async batch
    module_chunk    : int   # tasks per asyncio.gather chunk in run_tasks()
    description     : str


# ── Presets ───────────────────────────────────────────────────────────────────

PRESETS = {
    "fast": SpeedPreset(
        name          = "fast",
        threads       = 20,
        delay         = 0.1,
        timeout       = 10,
        crawler_batch = 30,
        module_chunk  = 100,
        description   = "Maximum speed — best for CTFs / labs / your own server",
    ),
    "normal": SpeedPreset(
        name          = "normal",
        threads       = 10,
        delay         = 0.5,
        timeout       = 20,
        crawler_batch = 20,
        module_chunk  = 50,
        description   = "Balanced — default mode for bug bounty",
    ),
    "stealth": SpeedPreset(
        name          = "stealth",
        threads       = 2,
        delay         = 3.0,
        timeout       = 30,
        crawler_batch = 5,
        module_chunk  = 10,
        description   = "Slow & quiet — evades WAF rate-limit detection",
    ),
}

DEFAULT_PRESET = PRESETS["normal"]


def get_preset(name: Optional[str]) -> SpeedPreset:
    """
    Return SpeedPreset by name.
    Falls back to 'normal' if name is None or unrecognised.
    """
    if not name:
        return DEFAULT_PRESET
    key = name.strip().lower()
    if key not in PRESETS:
        import logging
        logging.getLogger("SpeedConfig").warning(
            f"[!] Unknown speed preset '{name}'. "
            f"Valid: {list(PRESETS.keys())}. Using 'normal'."
        )
        return DEFAULT_PRESET
    return PRESETS[key]


def apply_preset(preset: SpeedPreset,
                 threads : Optional[int]   = None,
                 delay   : Optional[float] = None,
                 timeout : Optional[int]   = None) -> SpeedPreset:
    """
    Merge CLI overrides on top of a preset.
    Explicit --threads / --delay / --timeout always win.
    """
    from dataclasses import replace
    return replace(
        preset,
        threads = threads  if threads  is not None else preset.threads,
        delay   = delay    if delay    is not None else preset.delay,
        timeout = timeout  if timeout  is not None else preset.timeout,
    )
