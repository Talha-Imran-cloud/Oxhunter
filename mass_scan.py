"""Controlled mass/ASN scanning helpers for authorized assets only."""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, asdict
from typing import Iterable

import httpx


@dataclass
class Asset:
    host: str
    url: str
    source: str


class MassScanner:
    def __init__(self, concurrency: int = 10, timeout: float = 5.0,
                 max_hosts: int = 256, delay: float = 0.1):
        self.concurrency = max(1, min(concurrency, 50))
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.delay = max(0.0, delay)

    def expand_cidr(self, cidr: str) -> list[str]:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > self.max_hosts:
            raise ValueError(f"CIDR contains {network.num_addresses} addresses; limit is {self.max_hosts}")
        return [str(ip) for ip in network.hosts()]

    def resolve_domain(self, domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")
        if not domain or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for ch in domain):
            raise ValueError(f"invalid domain: {domain}")
        try:
            return sorted({item[4][0] for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)})
        except socket.gaierror:
            return []

    def load_targets(self, targets: Iterable[str] = (), cidrs: Iterable[str] = (), domains: Iterable[str] = ()) -> list[Asset]:
        assets = {}
        for raw in targets:
            target = raw.strip()
            if not target: continue
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            host = target.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
            assets[target] = Asset(host, target, "target")
        for cidr in cidrs:
            for ip in self.expand_cidr(cidr):
                for scheme in ("http", "https"):
                    url = f"{scheme}://{ip}"
                    assets[url] = Asset(ip, url, f"cidr:{cidr}")
        for domain in domains:
            for ip in self.resolve_domain(domain):
                for scheme in ("http", "https"):
                    url = f"{scheme}://{domain}"
                    assets[url] = Asset(domain, url, f"dns:{ip}")
        if len(assets) > self.max_hosts * 2:
            raise ValueError("target set exceeds configured safety limit")
        return list(assets.values())

    async def probe(self, assets: list[Asset]) -> list[dict]:
        semaphore = asyncio.Semaphore(self.concurrency)
        results = []
        headers = {"User-Agent": "0xHunter Mass Scanner (Authorized Testing)"}
        async with httpx.AsyncClient(headers=headers, timeout=self.timeout, verify=False, follow_redirects=False) as client:
            async def one(asset: Asset):
                async with semaphore:
                    try:
                        response = await client.get(asset.url)
                        await asyncio.sleep(self.delay)
                        return {**asdict(asset), "status_code": response.status_code,
                                "content_length": len(response.content),
                                "server": response.headers.get("server", "")}
                    except httpx.HTTPError as exc:
                        return {**asdict(asset), "error": type(exc).__name__}
            results = await asyncio.gather(*(one(asset) for asset in assets))
        return results

    async def scan(self, targets=(), cidrs=(), domains=(), authorized=False) -> list[dict]:
        if not authorized:
            raise PermissionError("explicit authorization is required for mass scanning")
        assets = self.load_targets(targets, cidrs, domains)
        return await self.probe(assets)


async def scan_targets(targets=(), cidrs=(), domains=(), authorized=False, **kwargs):
    return await MassScanner(**kwargs).scan(targets, cidrs, domains, authorized=authorized)
