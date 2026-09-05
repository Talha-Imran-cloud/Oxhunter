"""Nuclei integration for authorized, explicitly scoped scans."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Iterable


class NucleiRunner:
    def __init__(self, binary: str = "nuclei", concurrency: int = 10,
                 rate_limit: int = 50, timeout: int = 10, retries: int = 0):
        self.binary = binary
        self.concurrency = max(1, min(concurrency, 50))
        self.rate_limit = max(1, min(rate_limit, 500))
        self.timeout = max(1, timeout)
        self.retries = max(0, min(retries, 2))

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    @staticmethod
    def _validate_templates(template_dir: str) -> str:
        path = Path(template_dir).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"Nuclei template directory not found: {path}")
        return str(path)

    @staticmethod
    def _validate_targets(targets: Iterable[str], max_targets: int = 256) -> list[str]:
        values = []
        for target in targets:
            target = str(target).strip()
            if target and target.startswith(("http://", "https://")):
                values.append(target)
        values = list(dict.fromkeys(values))
        if not values: raise ValueError("at least one absolute HTTP(S) target is required")
        if len(values) > max_targets: raise ValueError(f"target limit is {max_targets}")
        return values

    async def run(self, targets: Iterable[str], template_dir: str,
                  authorized: bool = False, severities: Iterable[str] = ("info", "low", "medium", "high", "critical")) -> list[dict]:
        if not authorized:
            raise PermissionError("explicit authorization is required for Nuclei scans")
        if not self.available():
            raise FileNotFoundError("nuclei executable was not found in PATH")
        targets = self._validate_targets(targets)
        template_dir = self._validate_templates(template_dir)
        severity = ",".join(str(x).lower() for x in severities)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
            handle.write("\\n".join(targets) + "\\n")
            target_file = handle.name
        cmd = [self.binary, "-list", target_file, "-templates", template_dir,
               "-jsonl", "-silent", "-no-color", "-severity", severity,
               "-c", str(self.concurrency), "-rate-limit", str(self.rate_limit),
               "-timeout", str(self.timeout), "-retries", str(self.retries)]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
        finally:
            Path(target_file).unlink(missing_ok=True)
        if proc.returncode != 0:
            raise RuntimeError(f"nuclei failed ({proc.returncode}): {stderr.decode(errors='replace')[-2000:]}")
        findings = []
        for line in stdout.decode(errors="replace").splitlines():
            try: findings.append(json.loads(line))
            except json.JSONDecodeError: continue
        return findings
