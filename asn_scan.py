"""Passive ASN prefix discovery for authorized asset inventory."""
from __future__ import annotations

import re
import httpx


class ASNScanner:
    def __init__(self, max_prefixes: int = 32, timeout: float = 10.0):
        self.max_prefixes = max(1, min(max_prefixes, 128))
        self.timeout = timeout

    async def prefixes(self, asn: str) -> list[str]:
        asn = asn.upper().strip()
        if not re.fullmatch(r"AS?\d+", asn):
            raise ValueError("ASN must look like AS13335 or 13335")
        resource = asn if asn.startswith("AS") else "AS" + asn
        endpoint = "https://stat.ripe.net/data/announced-prefixes/data.json"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.get(endpoint, params={"resource": resource})
            response.raise_for_status()
            data = response.json().get("data", {})
        prefixes = data.get("prefixes", [])
        values = [str(item.get("prefix", "")) for item in prefixes if item.get("prefix")]
        return sorted(set(values))[: self.max_prefixes]
