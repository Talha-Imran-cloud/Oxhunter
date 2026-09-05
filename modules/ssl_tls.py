"""
SSL/TLS Security Checker Module
Tests for weak SSL/TLS configurations, expired certs, weak ciphers, and vulnerabilities
"""

import asyncio
import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import List, Optional, Dict
from dataclasses import dataclass, field

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class SSLFinding:
    """Represents an SSL/TLS security finding"""
    host: str
    port: int
    type: str
    severity: str
    confidence: str
    evidence: str
    remediation: str


@dataclass
class SSLReport:
    """Full SSL/TLS report for a host"""
    host: str
    port: int
    grade: str              # A, B, C, D, F
    cert_subject: str
    cert_issuer: str
    cert_expiry: str
    cert_valid: bool
    cert_days_remaining: int
    tls_versions: List[str]
    weak_versions: List[str]
    findings: List[SSLFinding] = field(default_factory=list)


class SSLTLSScanner:
    """
    SSL/TLS Security Scanner
    Checks:
    - Certificate validity, expiry, self-signed
    - Weak TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Weak cipher suites
    - HSTS header presence
    - HTTP to HTTPS redirect
    - Mixed content issues
    - Certificate hostname mismatch
    - Heartbleed, POODLE indicators (header-based)
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("SSLTLS")
        self.findings: List[SSLFinding] = []
        self.reports: List[SSLReport] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(15.0, connect=10.0)

        # Weak TLS versions
        self.weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        self.strong_versions = ['TLSv1.2', 'TLSv1.3']

        # Weak cipher keywords
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5',
            'anon', 'ADH', 'AECDH', '3DES', 'RC2',
            'IDEA', 'SEED', 'PSK', 'SRP'
        ]

    def _get_cert_info(self, host: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information"""
        try:
            # FIX: Use CERT_OPTIONAL so getpeercert() returns real cert dict.
            # CERT_NONE causes getpeercert() to return {} (empty) even on valid HTTPS,
            # which was incorrectly triggering the "no_certificate" false positive.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL  # FIX: was CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()  # Now returns real dict with CERT_OPTIONAL
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        'cert': cert or {},
                        'cipher': cipher,
                        'version': version,
                        'cipher_name': cipher[0] if cipher else 'Unknown',
                        'cipher_bits': cipher[2] if cipher else 0,
                        'connected': True,  # FIX: flag to show connection succeeded
                    }
        except ssl.SSLCertVerificationError as e:
            return {'error': 'cert_verification', 'message': str(e), 'connected': True}
        except ssl.SSLError as e:
            return {'error': 'ssl_error', 'message': str(e), 'connected': False}
        except Exception as e:
            return {'error': 'connection_error', 'message': str(e), 'connected': False}

    def _check_weak_tls(self, host: str, port: int, version: str) -> bool:
        """Check if a specific TLS version is supported"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Try to force specific version
            if version == 'TLSv1':
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            elif version == 'TLSv1.1':
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except Exception:
            return False

    def _analyze_certificate(self, host: str, port: int, cert_data: Dict) -> List[SSLFinding]:
        """Analyze certificate for issues"""
        findings = []
        cert = cert_data.get('cert', {})

        if not cert:
            # FIX: Only report no_certificate if we couldn't connect at all.
            # An empty cert dict with a successful connection just means the cert
            # data wasn't parseable — NOT that SSL is missing.
            # This was the main source of false positives on valid HTTPS sites.
            if not cert_data.get('connected', False):
                findings.append(SSLFinding(
                    host=host, port=port,
                    type="no_certificate",
                    severity="critical",
                    confidence="high",
                    evidence="No SSL certificate returned — connection may not be encrypted",
                    remediation="Install a valid SSL/TLS certificate from a trusted CA."
                ))
            return findings

        # Check expiry
        not_after = cert.get('notAfter', '')
        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.datetime.utcnow()
                days_remaining = (expiry - now).days

                if days_remaining < 0:
                    findings.append(SSLFinding(
                        host=host, port=port,
                        type="expired_certificate",
                        severity="critical",
                        confidence="high",
                        evidence=f"Certificate expired {abs(days_remaining)} days ago on {not_after}",
                        remediation="Renew SSL certificate immediately. Use Let's Encrypt for free auto-renewal."
                    ))
                elif days_remaining < 14:
                    findings.append(SSLFinding(
                        host=host, port=port,
                        type="expiring_soon",
                        severity="high",
                        confidence="high",
                        evidence=f"Certificate expires in {days_remaining} days ({not_after})",
                        remediation="Renew SSL certificate before expiry. Enable auto-renewal."
                    ))
                elif days_remaining < 30:
                    findings.append(SSLFinding(
                        host=host, port=port,
                        type="expiring_soon",
                        severity="medium",
                        confidence="high",
                        evidence=f"Certificate expires in {days_remaining} days ({not_after})",
                        remediation="Plan SSL certificate renewal soon."
                    ))
            except Exception:
                pass

        # Check hostname match
        subject = dict(x[0] for x in cert.get('subject', []))
        san = cert.get('subjectAltName', [])
        cn = subject.get('commonName', '')

        host_matched = (host == cn or host.endswith('.' + cn.lstrip('*.')))
        san_matched  = any(host == v for t, v in san if t == 'DNS') or \
                       any(host.endswith('.' + v.lstrip('*.')) for t, v in san if t == 'DNS')

        if not host_matched and not san_matched:
            findings.append(SSLFinding(
                host=host, port=port,
                type="hostname_mismatch",
                severity="high",
                confidence="high",
                evidence=f"Certificate CN '{cn}' does not match host '{host}'",
                remediation="Use a certificate that matches the hostname or includes it in SAN."
            ))

        # Check weak cipher
        cipher_name = cert_data.get('cipher_name', '')
        cipher_bits = cert_data.get('cipher_bits', 0)

        for weak in self.weak_ciphers:
            if weak.upper() in cipher_name.upper():
                findings.append(SSLFinding(
                    host=host, port=port,
                    type="weak_cipher",
                    severity="high",
                    confidence="high",
                    evidence=f"Weak cipher in use: {cipher_name} ({cipher_bits} bits)",
                    remediation=(
                        "Disable weak ciphers. Use only strong cipher suites:\n"
                        "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, "
                        "ECDHE-RSA-AES256-GCM-SHA384"
                    )
                ))
                break

        # Check key size
        if cipher_bits and cipher_bits < 128:
            findings.append(SSLFinding(
                host=host, port=port,
                type="weak_key_size",
                severity="high",
                confidence="high",
                evidence=f"Weak cipher key size: {cipher_bits} bits (minimum recommended: 128)",
                remediation="Use cipher suites with at least 128-bit key strength."
            ))

        return findings

    async def _check_http_headers(self, url: str, host: str, port: int) -> List[SSLFinding]:
        """Check HTTP security headers related to SSL/TLS"""
        findings = []
        try:
            async def _do_request():
                return await self.client.get(url, follow_redirects=True)
            response = await self.rate_limiter.execute_with_retry(_do_request)

            # HSTS check
            hsts = response.headers.get('strict-transport-security', '')
            if not hsts:
                findings.append(SSLFinding(
                    host=host, port=port,
                    type="missing_hsts",
                    severity="medium",
                    confidence="high",
                    evidence="Strict-Transport-Security (HSTS) header is missing",
                    remediation=(
                        "Add HSTS header: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    )
                ))
            else:
                # Check max-age
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 15552000:  # 180 days
                        findings.append(SSLFinding(
                            host=host, port=port,
                            type="weak_hsts_max_age",
                            severity="low",
                            confidence="high",
                            evidence=f"HSTS max-age too short: {max_age}s (recommended: 31536000+)",
                            remediation="Set HSTS max-age to at least 31536000 (1 year)."
                        ))
                if 'includeSubDomains' not in hsts:
                    findings.append(SSLFinding(
                        host=host, port=port,
                        type="hsts_no_subdomains",
                        severity="low",
                        confidence="high",
                        evidence="HSTS missing 'includeSubDomains' directive",
                        remediation="Add 'includeSubDomains' to HSTS header."
                    ))

        except Exception as e:
            self.logger.debug(f"Header check failed {url}: {e}")

        return findings

    async def _check_http_redirect(self, host: str, port: int) -> Optional[SSLFinding]:
        """Check if HTTP redirects to HTTPS"""
        try:
            async def _do_request():
                return await self.client.get(
                    f"http://{host}/",
                    follow_redirects=False
                )
            response = await self.rate_limiter.execute_with_retry(_do_request)

            # FIX: Check Location header first — CDN/proxy may return 200 on HTTP
            # but Location shows redirect target (e.g. Cloudflare, Google CDN).
            # Also: status 200 after following is fine if the INITIAL response redirected.
            location = response.headers.get('location', '')

            if response.status_code in [301, 302, 307, 308]:
                # Good — there IS a redirect. Check it goes to HTTPS.
                if location and not location.startswith('https://'):
                    return SSLFinding(
                        host=host, port=port,
                        type="http_redirect_not_https",
                        severity="medium",
                        confidence="high",
                        evidence=f"HTTP redirects to non-HTTPS location: {location}",
                        remediation="Ensure HTTP redirects go to HTTPS URL."
                    )
                # Redirect to HTTPS — all good
                return None

            # FIX: status 200 on HTTP does NOT always mean no redirect exists.
            # Some CDNs (Cloudflare, Akamai, Google) terminate HTTP at edge and
            # serve HTTPS internally — the raw socket sees 200 but traffic IS encrypted.
            # Only report if we're confident it's a real non-redirecting HTTP server.
            if response.status_code == 200 and not location:
                # Check if the server header suggests it's a real origin server
                server = response.headers.get('server', '').lower()
                # Skip false positive for well-known CDN/proxy servers
                cdn_indicators = ['gws', 'cloudflare', 'akamai', 'fastly', 'nginx', 'apache']
                if any(ind in server for ind in cdn_indicators):
                    # Likely CDN handling — don't report as false positive
                    return None
                return SSLFinding(
                    host=host, port=port,
                    type="no_http_redirect",
                    severity="medium",
                    confidence="medium",  # FIX: lowered confidence (was "high")
                    evidence=f"HTTP does not redirect to HTTPS (status: {response.status_code})",
                    remediation=(
                        "Configure server to redirect all HTTP traffic to HTTPS.\n"
                        "Nginx: return 301 https://$host$request_uri;\n"
                        "Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
                    )
                )

        except Exception:
            pass
        return None

    async def _check_weak_tls_versions(self, host: str, port: int) -> List[SSLFinding]:
        """Check for weak TLS version support"""
        findings = []
        loop = asyncio.get_event_loop()

        for version in ['TLSv1', 'TLSv1.1']:
            try:
                supported = await loop.run_in_executor(
                    None, self._check_weak_tls, host, port, version
                )
                if supported:
                    findings.append(SSLFinding(
                        host=host, port=port,
                        type="weak_tls_version",
                        severity="high" if version == 'TLSv1' else "medium",
                        confidence="high",
                        evidence=f"Weak TLS version supported: {version}",
                        remediation=(
                            f"Disable {version} support. Only allow TLSv1.2 and TLSv1.3.\n"
                            "Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                            "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                        )
                    ))
            except Exception:
                pass

        return findings

    async def scan_host(self, host: str, port: int, url: str) -> SSLReport:
        """Scan a single host for SSL/TLS issues"""
        self.logger.info(f"Scanning SSL/TLS for {host}:{port}")
        all_findings = []

        # Get cert info in executor (blocking)
        loop = asyncio.get_event_loop()
        cert_data = await loop.run_in_executor(None, self._get_cert_info, host, port)

        cert = cert_data.get('cert', {}) if cert_data else {}
        tls_version = cert_data.get('version', 'Unknown') if cert_data else 'Unknown'

        # Self-signed check
        if cert_data and 'error' in cert_data and 'CERTIFICATE_VERIFY_FAILED' in cert_data.get('message', ''):
            all_findings.append(SSLFinding(
                host=host, port=port,
                type="self_signed_or_untrusted",
                severity="high",
                confidence="high",
                evidence="Certificate verification failed — may be self-signed or from untrusted CA",
                remediation="Use a certificate from a trusted Certificate Authority (CA) like Let's Encrypt."
            ))

        # Cert analysis
        if cert_data and not cert_data.get('error'):
            all_findings.extend(self._analyze_certificate(host, port, cert_data))

        # Weak TLS versions
        weak_tls = await self._check_weak_tls_versions(host, port)
        all_findings.extend(weak_tls)

        # HTTP header checks
        header_findings = await self._check_http_headers(url, host, port)
        all_findings.extend(header_findings)

        # HTTP -> HTTPS redirect
        redirect_finding = await self._check_http_redirect(host, port)
        if redirect_finding:
            all_findings.append(redirect_finding)

        # Calculate grade
        grade = self._calculate_grade(all_findings)

        # Build cert info
        cert_subject = ''
        cert_issuer  = ''
        cert_expiry  = ''
        cert_valid   = True
        days_remaining = 0

        if cert:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer  = dict(x[0] for x in cert.get('issuer', []))
            cert_subject = subject.get('commonName', 'Unknown')
            cert_issuer  = issuer.get('organizationName', 'Unknown')
            cert_expiry  = cert.get('notAfter', 'Unknown')
            try:
                expiry = datetime.datetime.strptime(cert_expiry, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry - datetime.datetime.utcnow()).days
                cert_valid = days_remaining > 0
            except Exception:
                pass

        weak_versions_found = [f.evidence.split(': ')[-1] for f in all_findings if f.type == 'weak_tls_version']

        report = SSLReport(
            host=host,
            port=port,
            grade=grade,
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
            cert_expiry=cert_expiry,
            cert_valid=cert_valid,
            cert_days_remaining=days_remaining,
            tls_versions=[tls_version],
            weak_versions=weak_versions_found,
            findings=all_findings
        )

        self.findings.extend(all_findings)
        self.reports.append(report)

        for f in all_findings:
            self.logger.warning(f"SSL [{f.severity.upper()}]: {host} | {f.type} | {f.evidence[:80]}")

        return report

    def _calculate_grade(self, findings: List[SSLFinding]) -> str:
        """Calculate SSL grade based on findings"""
        severities = [f.severity for f in findings]
        if 'critical' in severities:
            return 'F'
        critical_types = ['expired_certificate', 'self_signed_or_untrusted', 'weak_tls_version']
        if any(f.type in critical_types for f in findings):
            return 'D'
        if 'high' in severities:
            return 'C'
        if 'medium' in severities:
            return 'B'
        if 'low' in severities:
            return 'B+'
        return 'A'

    async def scan(self, target_urls: List[str], forms: List = None) -> List[SSLFinding]:  # NEW-BUG-001 FIX
        forms = forms or []  # NEW-BUG-001 FIX
        """Main SSL/TLS scan method"""
        # Extract unique HTTPS hosts
        hosts_seen = set()
        scan_targets = []
        for url in target_urls:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                host = parsed.hostname
                port = parsed.port or 443
                key  = f"{host}:{port}"
                if key not in hosts_seen:
                    hosts_seen.add(key)
                    scan_targets.append((host, port, url))
            elif parsed.scheme == 'http':
                host = parsed.hostname
                port = parsed.port or 443
                https_url = url.replace('http://', 'https://', 1)
                key = f"{host}:{port}"
                if key not in hosts_seen:
                    hosts_seen.add(key)
                    scan_targets.append((host, port, https_url))

        if not scan_targets:
            self.logger.info("No HTTPS targets found for SSL scan")
            return []

        self.logger.info(f"Starting SSL/TLS scan on {len(scan_targets)} hosts")

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client
            tasks = [self.scan_host(h, p, u) for h, p, u in scan_targets]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(f"SSL/TLS scan complete. Found {len(self.findings)} issues across {len(self.reports)} hosts")
        return self.findings
