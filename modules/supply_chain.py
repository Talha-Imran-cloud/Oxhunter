"""
OXHUNTER - modules/supply_chain.py
Supply Chain Attack Detector
npm/pip typosquatting, dependency confusion, malicious packages
"""

import re
import json
import requests
import urllib3
from typing import List, Optional
from dataclasses import dataclass
from utils.logger import setup_logger

urllib3.disable_warnings()

# ── Common internal package name patterns ─────
INTERNAL_PATTERNS = re.compile(
    r'(?:company|internal|private|corp|local|dev|test|staging|prod|backend|frontend|api|core|lib|sdk|client|server)',
    re.IGNORECASE
)

# ── Known malicious/typosquatted packages ─────
KNOWN_TYPOSQUATS = {
    "npm": {
        "lodash"    : ["1odash", "l0dash", "1odahs", "loadsh", "lodahs"],
        "express"   : ["expresss", "exprss", "expres"],
        "react"     : ["reakt", "r3act", "reeact"],
        "axios"     : ["axois", "axious", "axiso"],
        "moment"    : ["momment", "momnent", "memoent"],
        "chalk"     : ["chak", "chalkk", "chalke"],
        "webpack"   : ["webpakc", "webpac", "webpackk"],
        "eslint"    : ["eslintt", "eslnit"],
        "typescript": ["typscript", "typescrip"],
        "jquery"    : ["jquerry", "jqeury"],
    },
    "pip": {
        "requests"  : ["request", "requestss", "requets"],
        "numpy"     : ["numy", "nump", "numpyy"],
        "pandas"    : ["panda", "pandass", "panadas"],
        "flask"     : ["flask1", "flaask", "flaskk"],
        "django"    : ["djano", "djangoo", "dajngo"],
        "boto3"     : ["bto3", "bot3", "boto"],
        "sqlalchemy": ["sqlalchmy", "sqlalchemy2"],
        "pyyaml"    : ["pyaml", "py-yaml"],
        "pillow"    : ["pilow", "pillow2"],
        "cryptography": ["cryptograpy", "cryptograhy"],
    }
}


@dataclass
class SupplyChainFinding:
    type        : str
    severity    : str
    package     : str
    ecosystem   : str    # npm, pip, etc.
    url         : str    = ""
    detail      : str    = ""
    evidence    : str    = ""
    remediation : str    = ""
    payload     : str    = ""
    confidence  : str    = "medium"


class SupplyChainDetector:
    """
    Supply Chain Attack Detector.
    Detects:
    - Dependency confusion attacks
    - Typosquatted packages
    - Internal package name exposure
    - Malicious package indicators
    - Outdated packages with known CVEs
    """

    def __init__(self, rate_limiter=None, timeout: int = 10,
                 proxy: Optional[str] = None):
        self.timeout = timeout
        self.logger  = setup_logger("SupplyChain")
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, **kw)
        except Exception:
            return None

    # ── 1. package.json / requirements.txt scan ──

    def scan_package_file(self, base_url: str) -> List[SupplyChainFinding]:
        """Scan exposed package files for internal/typosquatted packages."""
        findings = []
        files_to_check = [
            ("/package.json",       "npm"),
            ("/package-lock.json",  "npm"),
            ("/yarn.lock",          "npm"),
            ("/requirements.txt",   "pip"),
            ("/Pipfile",            "pip"),
            ("/Pipfile.lock",       "pip"),
            ("/setup.py",           "pip"),
            ("/pyproject.toml",     "pip"),
            ("/composer.json",      "composer"),
            ("/Gemfile",            "gem"),
        ]

        for path, ecosystem in files_to_check:
            url = base_url.rstrip("/") + path
            r   = self._get(url)
            if not r or r.status_code != 200:
                continue

            self.logger.info(f"Found package file: {url}")
            findings.append(SupplyChainFinding(
                type="exposed_package_file", severity="MEDIUM",
                package=path, ecosystem=ecosystem, url=url,
                detail=f"Package file exposed publicly: {path}",
                evidence=r.text[:200],
                remediation=f"Restrict access to {path} in web server config",
            ))

            # Parse packages from file
            packages = self._parse_packages(r.text, ecosystem)
            for pkg in packages:
                # Check typosquatting
                typo_f = self.check_typosquat(pkg, ecosystem, url)
                findings.extend(typo_f)

                # Check internal package names
                if INTERNAL_PATTERNS.search(pkg):
                    dep_f = self.check_dependency_confusion(pkg, ecosystem, url)
                    findings.extend(dep_f)

        return findings

    def _parse_packages(self, content: str, ecosystem: str) -> List[str]:
        """Parse package names from file content."""
        packages = []
        try:
            if ecosystem == "npm":
                data = json.loads(content)
                for section in ["dependencies", "devDependencies", "peerDependencies"]:
                    packages.extend(data.get(section, {}).keys())
            elif ecosystem == "pip":
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = re.split(r"[>=<!~]", line)[0].strip()
                        if pkg:
                            packages.append(pkg)
        except Exception:
            # Fallback: regex
            packages = re.findall(r'"([a-z][a-z0-9\-_]{1,40})"', content)
        return list(set(packages))

    # ── 2. Typosquatting Check ────────────────────

    def check_typosquat(self, package: str, ecosystem: str,
                         source_url: str) -> List[SupplyChainFinding]:
        """Check if package name is a typosquat of popular package."""
        findings = []
        pkg_lower = package.lower()

        eco_squats = KNOWN_TYPOSQUATS.get(ecosystem, {})
        for real_pkg, squats in eco_squats.items():
            if pkg_lower in squats:
                findings.append(SupplyChainFinding(
                    type="typosquatting_detected", severity="HIGH",
                    package=package, ecosystem=ecosystem, url=source_url,
                    detail=f"'{package}' looks like typosquat of '{real_pkg}'",
                    evidence=f"Similar to popular package: {real_pkg}",
                    remediation=f"Verify if '{package}' is intentional. Use '{real_pkg}' instead.",
                ))

        return findings

    # ── 3. Dependency Confusion ───────────────────

    def check_dependency_confusion(self, package: str, ecosystem: str,
                                    source_url: str) -> List[SupplyChainFinding]:
        """
        Check if internal package name exists in public registry.
        If it does → potential dependency confusion attack vector.
        """
        findings = []

        # Check if package exists in public registry
        exists_public = False
        registry_url  = ""

        if ecosystem == "npm":
            registry_url = f"https://registry.npmjs.org/{package}"
            r = self._get(registry_url)
            exists_public = r and r.status_code == 200
        elif ecosystem == "pip":
            registry_url = f"https://pypi.org/pypi/{package}/json"
            r = self._get(registry_url)
            exists_public = r and r.status_code == 200

        if exists_public:
            findings.append(SupplyChainFinding(
                type="dependency_confusion_risk", severity="CRITICAL",
                package=package, ecosystem=ecosystem, url=source_url,
                detail=f"Internal package '{package}' also exists in public {ecosystem} registry!",
                evidence=f"Public registry URL: {registry_url}",
                remediation=(
                    "Set scope for internal packages. "
                    "Use private registry mirror. "
                    "Pin exact versions with integrity hashes."
                ),
            ))
        else:
            # Package doesn't exist publicly — potential hijacking target
            findings.append(SupplyChainFinding(
                type="dependency_confusion_target", severity="HIGH",
                package=package, ecosystem=ecosystem, url=source_url,
                detail=f"Internal package '{package}' NOT in public registry — hijackable!",
                evidence=f"Package '{package}' with internal naming not claimed publicly",
                remediation=f"Claim '{package}' in public {ecosystem} registry to prevent hijacking",
                confidence="high",
            ))

        return findings

    # ── 4. JS File Analysis ───────────────────────

    def scan_js_for_packages(self, base_url: str) -> List[SupplyChainFinding]:
        """Scan JS files for CDN-loaded packages that could be hijacked."""
        findings = []
        r = self._get(base_url)
        if not r:
            return findings

        # Find CDN script tags
        cdn_scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']+(?:cdn|jsdelivr|unpkg|cdnjs)[^"\']+)["\']',
            r.text, re.IGNORECASE
        )

        for cdn_url in cdn_scripts:
            # Check for unpinned versions
            if "@latest" in cdn_url or "/master/" in cdn_url:
                findings.append(SupplyChainFinding(
                    type="unpinned_cdn_dependency", severity="MEDIUM",
                    package=cdn_url, ecosystem="cdn", url=base_url,
                    detail="CDN dependency uses unpinned version (@latest or /master/)",
                    evidence=f"Script: {cdn_url[:80]}",
                    remediation="Pin CDN dependencies to specific versions with SRI hashes",
                ))

            # Check for SRI (Subresource Integrity)
            if cdn_url in r.text:
                if 'integrity=' not in r.text:
                    findings.append(SupplyChainFinding(
                        type="missing_sri_hash", severity="MEDIUM",
                        package=cdn_url, ecosystem="cdn", url=base_url,
                        detail="CDN resource loaded without Subresource Integrity (SRI) hash",
                        evidence=f"No integrity= attribute for: {cdn_url[:60]}",
                        remediation="Add integrity attribute: integrity='sha384-...' crossorigin='anonymous'",
                    ))

        return findings

    # ── 5. Check Popular Packages for Version ────

    def check_outdated(self, package: str, version: str,
                        ecosystem: str) -> Optional[SupplyChainFinding]:
        """Check if package version has known vulnerabilities."""
        try:
            if ecosystem == "npm":
                r = self._get(f"https://registry.npmjs.org/{package}")
                if r and r.status_code == 200:
                    data    = r.json()
                    latest  = data.get("dist-tags", {}).get("latest", "")
                    if latest and latest != version:
                        return SupplyChainFinding(
                            type="outdated_package", severity="LOW",
                            package=package, ecosystem=ecosystem,
                            detail=f"{package}@{version} outdated. Latest: {latest}",
                            remediation=f"Update to {package}@{latest}",
                        )
        except Exception:
            pass
        return None

    # ── Full Scan ──────────────────────────────────

    async def scan(self, urls: List[str]) -> List[SupplyChainFinding]:
        """Run all supply chain checks."""
        findings = []
        if not urls:
            return findings

        base_url = urls[0].split("?")[0]
        base_url = "/".join(base_url.split("/")[:3])

        self.logger.info(f"Starting supply chain scan on {base_url}")

        findings.extend(self.scan_package_file(base_url))
        findings.extend(self.scan_js_for_packages(base_url))

        self.logger.info(f"Supply chain scan complete. Found {len(findings)} issues")
        return findings
