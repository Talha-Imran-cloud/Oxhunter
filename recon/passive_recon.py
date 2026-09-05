"""
OXHUNTER - recon/passive_recon.py
Passive Recon Engine — Shodan + Wayback Machine + Google Dorks + crt.sh
"""

import re
import socket
import requests
import urllib3
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from utils.logger import setup_logger

urllib3.disable_warnings()


@dataclass
class ReconResult:
    source      : str
    type        : str
    value       : str
    detail      : str  = ""
    severity    : str  = "INFO"
    url         : str  = ""
    evidence    : str  = ""


class PassiveRecon:
    """
    Passive Recon Engine — no active scanning.
    Sources: crt.sh, Wayback Machine, HackerTarget,
             Shodan (if API key), Google Dorks guide,
             SecurityTrails-style DNS recon.
    """

    GOOGLE_DORKS = [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:env',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:config',
        'site:{domain} inurl:backup',
        'site:{domain} inurl:api',
        'site:{domain} inurl:.git',
        'site:{domain} intext:password',
        'site:{domain} intext:"api_key"',
        'site:{domain} intext:"secret_key"',
        'site:{domain} intext:"access_token"',
        'site:{domain} inurl:phpinfo.php',
        'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp',
        'site:{domain} inurl:wp-content',
        'site:{domain} inurl:wp-admin',
        '"@{domain}" email',
    ]

    def __init__(self, shodan_key: Optional[str] = None,
                 timeout: int = 15, proxy: Optional[str] = None):
        self.shodan_key = shodan_key
        self.timeout    = timeout
        self.logger     = setup_logger("PassiveRecon")
        self.session    = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0 OXHUNTER/2.0"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, **kw)
        except Exception:
            return None

    @staticmethod
    def _extract_domain(target: str) -> str:
        target = target.replace("https://","").replace("http://","").split("/")[0]
        parts  = target.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else target

    # ── 1. crt.sh Certificate Transparency ───────

    def crt_sh(self, domain: str) -> List[ReconResult]:
        """Find subdomains via SSL certificate transparency logs."""
        results = []
        self.logger.info(f"crt.sh — searching {domain}")
        r = self._get(f"https://crt.sh/?q=%.{domain}&output=json")
        if not r or r.status_code != 200:
            return results
        try:
            data  = r.json()
            found = set()
            for entry in data:
                names = entry.get("name_value", "")
                for name in names.split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name and name not in found:
                        found.add(name)
                        results.append(ReconResult(
                            source="crt.sh", type="subdomain",
                            value=name,
                            detail=f"Issued: {entry.get('not_before','?')[:10]} | CA: {entry.get('issuer_name','?')[:40]}",
                        ))
            self.logger.info(f"crt.sh found {len(results)} subdomains")
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        return results

    # ── 2. Wayback Machine ────────────────────────

    def wayback(self, domain: str, limit: int = 100) -> List[ReconResult]:
        """Find historical URLs from Wayback Machine."""
        results = []
        self.logger.info(f"Wayback Machine — searching {domain}")
        url = ("https://web.archive.org/cdx/search/cdx"
               f"?url=*.{domain}/*&output=json&fl=original,statuscode,timestamp"
               f"&collapse=urlkey&limit={limit}")
        r = self._get(url)
        if not r or r.status_code != 200:
            return results
        try:
            data  = r.json()
            found = set()
            # Interesting extensions
            interesting = re.compile(
                r'\.(php|asp|aspx|jsp|env|sql|bak|zip|tar|gz|log|conf|config|xml|json|yaml|yml|key|pem)(\?|$)',
                re.IGNORECASE
            )
            for row in data[1:]:   # Skip header row
                orig, status, ts = row[0], row[1], row[2]
                if orig in found:
                    continue
                found.add(orig)
                severity = "INFO"
                if interesting.search(orig):
                    severity = "MEDIUM"
                if any(k in orig.lower() for k in ["admin","password","secret","key","backup","dump"]):
                    severity = "HIGH"
                results.append(ReconResult(
                    source   = "wayback",
                    type     = "historical_url",
                    value    = orig,
                    detail   = f"Status:{status} | Archived:{ts[:8]}",
                    severity = severity,
                    url      = orig,
                ))
            self.logger.info(f"Wayback found {len(results)} historical URLs")
        except Exception as e:
            self.logger.debug(f"Wayback error: {e}")
        return results

    # ── 3. HackerTarget DNS Recon ─────────────────

    def hackertarget(self, domain: str) -> List[ReconResult]:
        """DNS records via HackerTarget free API."""
        results = []
        self.logger.info(f"HackerTarget — DNS recon {domain}")

        # Hostname search
        r = self._get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                if "," in line:
                    subdomain, ip = line.split(",", 1)
                    results.append(ReconResult(
                        source="hackertarget", type="subdomain",
                        value=subdomain.strip(),
                        detail=f"IP: {ip.strip()}",
                    ))

        # DNS lookup
        r2 = self._get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r2 and r2.status_code == 200:
            for line in r2.text.strip().splitlines():
                if line:
                    results.append(ReconResult(
                        source="hackertarget", type="dns_record",
                        value=line, detail="DNS Record",
                    ))

        self.logger.info(f"HackerTarget found {len(results)} records")
        return results

    # ── 4. Shodan ─────────────────────────────────

    def shodan(self, domain: str) -> List[ReconResult]:
        """Query Shodan for exposed services (requires API key)."""
        results = []
        if not self.shodan_key:
            self.logger.debug("Shodan: no API key")
            return results

        self.logger.info(f"Shodan — searching {domain}")
        r = self._get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": self.shodan_key, "query": f"hostname:{domain}"}
        )
        if not r or r.status_code != 200:
            return results
        try:
            data = r.json()
            for match in data.get("matches", []):
                ip       = match.get("ip_str", "")
                port     = match.get("port", "")
                product  = match.get("product", "")
                version  = match.get("version", "")
                vulns    = match.get("vulns", {})

                severity = "CRITICAL" if vulns else ("HIGH" if port in [21,22,23,3389] else "MEDIUM")
                detail   = f"IP:{ip} Port:{port} {product} {version}"
                if vulns:
                    detail += f" | CVEs: {', '.join(list(vulns.keys())[:3])}"

                results.append(ReconResult(
                    source   = "shodan",
                    type     = "exposed_service",
                    value    = f"{ip}:{port}",
                    detail   = detail,
                    severity = severity,
                    evidence = f"Vulns: {list(vulns.keys())}" if vulns else "",
                ))
            self.logger.info(f"Shodan found {len(results)} exposed services")
        except Exception as e:
            self.logger.debug(f"Shodan error: {e}")
        return results

    # ── 5. Google Dorks ───────────────────────────

    def google_dorks(self, domain: str) -> List[ReconResult]:
        """Generate Google dork queries (manual — no scraping)."""
        results = []
        self.logger.info(f"Generating Google Dorks for {domain}")
        for dork in self.GOOGLE_DORKS:
            query = dork.replace("{domain}", domain)
            results.append(ReconResult(
                source   = "google_dorks",
                type     = "dork_query",
                value    = query,
                detail   = f"Search: https://www.google.com/search?q={query.replace(' ','+')}",
                severity = "INFO",
                url      = f"https://www.google.com/search?q={query.replace(' ','+')}",
            ))
        self.logger.info(f"Generated {len(results)} Google dorks")
        return results

    # ── 6. IP Reverse DNS ─────────────────────────

    def reverse_dns(self, domain: str) -> List[ReconResult]:
        """Get IP and reverse DNS info."""
        results = []
        try:
            ip = socket.gethostbyname(domain)
            results.append(ReconResult(
                source="dns", type="a_record",
                value=ip, detail=f"{domain} → {ip}",
            ))
            # Reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results.append(ReconResult(
                    source="dns", type="ptr_record",
                    value=hostname, detail=f"{ip} → {hostname}",
                ))
            except Exception:
                pass

            # HackerTarget reverse IP
            r = self._get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
            if r and r.status_code == 200 and "error" not in r.text.lower():
                domains = [d.strip() for d in r.text.strip().splitlines() if d.strip()]
                for d in domains[:10]:
                    results.append(ReconResult(
                        source="hackertarget", type="shared_hosting",
                        value=d, detail=f"Shares IP {ip} with {domain}",
                        severity="INFO",
                    ))
        except Exception as e:
            self.logger.debug(f"DNS error: {e}")
        return results

    # ── 7. Email Recon ────────────────────────────

    def email_recon(self, domain: str) -> List[ReconResult]:
        """Find email patterns and contacts from public sources."""
        results = []

        # MX Records
        r = self._get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r and r.status_code == 200:
            mx_records = re.findall(r'MX\s+[\d\s]+(.+)', r.text)
            for mx in mx_records:
                results.append(ReconResult(
                    source="dns", type="mx_record",
                    value=mx.strip(),
                    detail=f"Mail server for {domain}",
                ))

        # Email format guess
        common_formats = [
            f"firstname.lastname@{domain}",
            f"f.lastname@{domain}",
            f"firstname@{domain}",
        ]
        for fmt in common_formats:
            results.append(ReconResult(
                source="recon", type="email_format",
                value=fmt, detail="Common corporate email format",
                severity="INFO",
            ))

        return results

    # ── Full Recon ────────────────────────────────

    def run(self, target: str,
            include_wayback: bool = True,
            include_dorks: bool = True) -> Dict:
        """
        Run full passive recon on target.
        Returns structured results from all sources.
        """
        domain  = self._extract_domain(target)
        self.logger.info(f"Starting passive recon on {domain}")

        all_results: List[ReconResult] = []

        # Always run
        all_results.extend(self.crt_sh(domain))
        all_results.extend(self.hackertarget(domain))
        all_results.extend(self.reverse_dns(domain))
        all_results.extend(self.email_recon(domain))
        all_results.extend(self.shodan(domain))

        if include_wayback:
            all_results.extend(self.wayback(domain, limit=50))

        if include_dorks:
            all_results.extend(self.google_dorks(domain))

        # Organize results
        by_type: Dict[str, List] = {}
        for r in all_results:
            by_type.setdefault(r.type, []).append({
                "source"  : r.source,
                "value"   : r.value,
                "detail"  : r.detail,
                "severity": r.severity,
                "url"     : r.url,
            })

        subdomains = [r for r in all_results if r.type == "subdomain"]
        urls       = [r for r in all_results if r.type == "historical_url"]
        services   = [r for r in all_results if r.type == "exposed_service"]
        high_sev   = [r for r in all_results if r.severity in ["HIGH","CRITICAL"]]

        self.logger.info(
            "Passive recon complete — "
            f"{len(subdomains)} subdomains, "
            f"{len(urls)} URLs, "
            f"{len(services)} services, "
            f"{len(high_sev)} high-severity items"
        )

        return {
            "domain"          : domain,
            "target"          : target,
            "timestamp"       : datetime.now().isoformat(),
            "total"           : len(all_results),
            "subdomains"      : [r.value for r in subdomains],
            "historical_urls" : [r.value for r in urls if r.severity in ["HIGH","MEDIUM"]],
            "exposed_services": [{"host": r.value, "detail": r.detail} for r in services],
            "high_severity"   : [{"type": r.type, "value": r.value, "detail": r.detail} for r in high_sev],
            "google_dorks"    : [r.url for r in all_results if r.type == "dork_query"],
            "by_type"         : by_type,
            "all_results"     : [
                {"source": r.source, "type": r.type, "value": r.value,
                 "detail": r.detail, "severity": r.severity}
                for r in all_results
            ],
        }

    def html_report(self, data: Dict) -> str:
        """Generate HTML passive recon report."""
        subdomains = data.get("subdomains", [])
        urls       = data.get("historical_urls", [])
        services   = data.get("exposed_services", [])
        high       = data.get("high_severity", [])
        dorks      = data.get("google_dorks", [])

        sub_rows  = "".join(f"<tr><td>{s}</td></tr>" for s in subdomains[:50])
        url_rows  = "".join(f"<tr><td><a style='color:#60a5fa' href='{u}' target='_blank'>{u[:80]}</a></td></tr>" for u in urls[:30])
        svc_rows  = "".join(f"<tr><td>{s['host']}</td><td style='color:#94a3b8'>{s['detail']}</td></tr>" for s in services)
        dork_rows = "".join(f"<tr><td><a style='color:#60a5fa' href='{d}' target='_blank'>{d[:80]}</a></td></tr>" for d in dorks[:20])

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Passive Recon — {data.get('domain')}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:20px;max-width:1200px;margin:0 auto}}
h2{{color:#60a5fa;border-bottom:1px solid #1e3a5f;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
th{{background:#1e293b;padding:8px;text-align:left;color:#60a5fa}}
td{{padding:8px;border-bottom:1px solid #1e293b;font-size:13px}}
.badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
.stat{{background:#1e293b;border-radius:8px;padding:16px;display:inline-block;margin:8px;text-align:center;min-width:120px}}
</style></head><body>
<h1 style="color:#f87171">🔍 OXHUNTER — Passive Recon Report</h1>
<p style="color:#94a3b8">Domain: <strong style="color:white">{data.get('domain')}</strong> | 
Scanned: {data.get('timestamp','')[:19]} | Total: {data.get('total',0)} items</p>

<div>
<div class="stat"><div style="font-size:24px;color:#60a5fa">{len(subdomains)}</div><div>Subdomains</div></div>
<div class="stat"><div style="font-size:24px;color:#f59e0b">{len(urls)}</div><div>Historical URLs</div></div>
<div class="stat"><div style="font-size:24px;color:#ef4444">{len(services)}</div><div>Exposed Services</div></div>
<div class="stat"><div style="font-size:24px;color:#dc2626">{len(high)}</div><div>High Severity</div></div>
</div>

<h2>🌐 Subdomains ({len(subdomains)})</h2>
<table><tr><th>Subdomain</th></tr>{sub_rows}</table>

<h2>📜 Interesting Historical URLs ({len(urls)})</h2>
<table><tr><th>URL</th></tr>{url_rows}</table>

<h2>🔌 Exposed Services ({len(services)})</h2>
<table><tr><th>Host:Port</th><th>Details</th></tr>{svc_rows}</table>

<h2>🔎 Google Dorks ({len(dorks)})</h2>
<table><tr><th>Dork Query</th></tr>{dork_rows}</table>

<p style="color:#475569;font-size:12px;margin-top:20px">Generated by OXHUNTER v2.0 — For authorized security testing only</p>
</body></html>"""
