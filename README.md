<div align="center">

```
  ___       _   _ _   _ _   _ _____ _____ ____  
 / _ \__  _| | | | | | | \ | |_   _| ____|  _ \ 
| | | \ \/ / |_| | | | |  \| | | | |  _| | |_) |
| |_| |>  <|  _  | |_| | |\  | | | | |___|  _ < 
 \___//_/\_\_| |_|\___/|_| \_| |_| |_____|_| \_\
                                            v2.1.0
```

**Advanced Web Vulnerability Scanner — 84+ Files · 2033+ Payloads · AI-Powered**

[![Python](https://img.shields.io/badge/Python-3.10+-black?style=for-the-badge&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.1.0-black?style=for-the-badge)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-61-black?style=for-the-badge)](modules/)
[![Payloads](https://img.shields.io/badge/Payloads-2033+-black?style=for-the-badge)](payloads/)
[![AI](https://img.shields.io/badge/AI-Groq%20LLaMA%203-black?style=for-the-badge)](https://groq.com)
[![PyPI](https://img.shields.io/badge/PyPI-oxhunter-black?style=for-the-badge&logo=pypi)](https://pypi.org/project/oxhunter/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Talha_Imran-black?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/talha-imran-583a44420)
[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black?style=for-the-badge&logo=github)](https://github.com/Talha-Imran-cloud)

[**Features**](#features) · [**Installation**](#installation) · [**Commands**](#commands) · [**Speed**](#speed-presets) · [**AI Setup**](#ai-setup) · [**Reports**](#reports) · [**Legal**](#legal)

> ⚠️ **For authorized security testing ONLY. Never scan without written permission.**

</div>

---

## What's New in v2.1.0 🔥

| Feature | v2.0.x | v2.1.0 |
|---------|--------|--------|
| Speed Presets (`--speed`) | ❌ | ✅ fast/normal/stealth |
| Parallel Module Scan | ❌ Sequential | ✅ asyncio.gather |
| Token Bucket Rate Limiter | ❌ | ✅ Smooth + 429 backoff |
| Injectable URL Filter | ❌ Scanned all URLs | ✅ Only real params |
| `--module` Flag | ❌ | ✅ Specific modules |
| Config Panel (Report/Mode) | ❌ Showed None | ✅ Properly shown |
| Scan Speed | ~3.5 hrs | **~7–30 min** |

---

## What's New in v2.0

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Payloads | 379 | **2033+** |
| Live Web Dashboard | ❌ | ✅ Real-time |
| Mass Scan / ASN Scanner | ❌ | ✅ |
| Nuclei Template Support | ❌ | ✅ 5000+ templates |
| AI Auto-Exploit Generator | ❌ | ✅ Working PoC |
| Smart Attack Chaining | ❌ | ✅ SSRF→RCE |
| OAuth 2.0 / OIDC Tester | ❌ | ✅ |
| Supply Chain Detector | ❌ | ✅ npm/pip |
| Passive Recon Engine | ❌ | ✅ Shodan+Wayback |
| WAF Detect/Bypass | ❌ | ✅ |
| Compliance Flags | ❌ | ✅ OWASP/PCI/ISO |

---

## Installation

### Via PyPI (Recommended)
```bash
pip install oxhunter
playwright install chromium
0xhunter version
```

### Via Git Clone
```bash
# Linux / Kali / macOS
git clone https://github.com/Talha-Imran-cloud/Oxhunter.git
cd Oxhunter
pip install -r requirements.txt
playwright install chromium
0xhunter version
```

```powershell
# Windows (PowerShell)
git clone https://github.com/Talha-Imran-cloud/Oxhunter.git
cd Oxhunter
pip install -r requirements.txt
playwright install chromium
0xhunter version
```

### Update to Latest
```bash
pip install oxhunter --upgrade
# or force specific version
pip install oxhunter==2.1.0 --force-reinstall
```

---

## Speed Presets 🚀

**v2.1.0 biggest feature** — ab manually `--threads`, `--delay`, `--timeout` set karne ki zaroorat nahi!

| Preset | Threads | Delay | Timeout | Best For | Time |
|--------|---------|-------|---------|----------|------|
| `--speed fast` | 20 | 0.1s | 10s | CTF / Lab / Own server | ~7 min |
| `--speed normal` | 10 | 0.5s | 20s | Bug bounty / Production | ~30 min |
| `--speed stealth` | 2 | 3.0s | 30s | WAF bypass / IDS evasion | ~2-3 hrs |

```bash
# Fast — CTF / Lab
0xhunter scan https://target.com --confirm --speed fast

# Normal — Bug Bounty
0xhunter scan https://target.com --confirm --speed normal

# Stealth — Evade WAF/IDS
0xhunter scan https://target.com --confirm --speed stealth

# Manual override (still works)
0xhunter scan https://target.com --confirm --threads 15 --delay 0.3 --timeout 25
```

> **Note:** `--speed` ke saath manually `--threads`/`--delay` doge to manual value override karega.

---

## Specific Module Scan 🎯

```bash
# Sirf SQLi scan
0xhunter scan https://target.com --confirm --module sqli

# Multiple modules
0xhunter scan https://target.com --confirm --module sqli,xss,cors

# Module + Speed preset
0xhunter scan https://target.com --confirm --module sqli,xss,cors,jwt,headers --speed normal --ai --pdf
```

### Available Modules (26)

| Module | Vulnerability |
|--------|--------------|
| `xss` | Cross-Site Scripting (Reflected, Stored, DOM) |
| `sqli` | SQL Injection (Error, Blind, Time-based) |
| `csrf` | Cross-Site Request Forgery |
| `headers` | Missing Security Headers |
| `open_redirect` | Open Redirect |
| `cors` | CORS Misconfiguration |
| `ssl` | SSL/TLS Weakness |
| `ssrf` | Server-Side Request Forgery |
| `cmdi` | Command Injection |
| `xxe` | XML External Entity |
| `lfi` | Local File Inclusion |
| `idor` | Insecure Direct Object Reference |
| `jwt` | JWT Algorithm Confusion / Weak Secret |
| `session` | Session Fixation |
| `password` | Password Policy / Username Enumeration |
| `dirs` | Directory Bruteforce |
| `git` | Git Exposure |
| `subdomain` | Subdomain Enumeration |
| `tech` | Technology Fingerprinting |
| `js` | JavaScript Analysis (API keys, endpoints) |
| `graphql` | GraphQL Introspection + Injection |
| `waf` | WAF Fingerprint + Bypass |
| `prototype` | Prototype Pollution |
| `race` | Race Condition |
| `smuggling` | HTTP Request Smuggling |
| `websocket` | WebSocket XSS/SQLi/Origin Bypass |

---

## Commands

```bash
0xhunter --help
0xhunter scan --help
0xhunter version
```

### Basic Scan
```bash
# Standard scan — 7 core modules
0xhunter scan https://target.com --confirm

# Full scan — all 61 modules + 2033 payloads
0xhunter scan https://target.com --confirm --full

# Specific modules only
0xhunter scan https://target.com --confirm --module sqli,xss,cors
```

### Speed + Modules (New v2.1.0)
```bash
# Google Bug Bounty
0xhunter scan https://www.google.com --confirm \
  --module sqli,xss,cors,jwt,headers \
  --speed normal \
  --ai --pdf \
  --waf-detect --bug-bounty \
  --scope "*.google.com" \
  --compliance owasp \
  --report-dir ./google_reports \
  --verbose

# CTF / Lab (fastest)
0xhunter scan https://testphp.vulnweb.com --confirm \
  --module sqli,xss,cors \
  --speed fast \
  --ai --pdf \
  --report-dir ./reports \
  --verbose

# WAF Protected Target (stealth)
0xhunter scan https://target.com --confirm \
  --module sqli,xss \
  --speed stealth \
  --waf-detect --waf-bypass \
  --report-dir ./reports
```

### Reports
```bash
0xhunter scan https://target.com --confirm --pdf --report-dir ./reports
0xhunter scan https://target.com --confirm --report html
0xhunter scan https://target.com --confirm --report json
0xhunter scan https://target.com --confirm --report both
```

### Authentication
```bash
0xhunter scan https://target.com --confirm --cookie "session=abc123"
0xhunter scan https://target.com --confirm --token "Bearer eyJhbGci..."
0xhunter scan https://target.com --confirm --auth "admin:password"
```

### AI Features
```bash
# Set API key first
export GROQ_API_KEY="gsk_your_key"           # Linux/Mac
$env:GROQ_API_KEY = "gsk_your_key"           # Windows

0xhunter scan https://target.com --confirm --ai
0xhunter scan https://target.com --confirm --ai --lang ur   # Urdu report
0xhunter scan https://target.com --confirm --ai --exploit-gen
0xhunter scan https://target.com --confirm --ai --chain-attacks
```

### WAF
```bash
0xhunter scan https://target.com --confirm --waf-detect
0xhunter scan https://target.com --confirm --waf-bypass
0xhunter scan https://target.com --confirm --waf-detect --waf-bypass
```

### Compliance & Bug Bounty
```bash
0xhunter scan https://target.com --confirm --compliance owasp
0xhunter scan https://target.com --confirm --compliance pci
0xhunter scan https://target.com --confirm --compliance iso
0xhunter scan https://target.com --confirm --bug-bounty --scope "*.target.com"
```

### Proxy (Burp Suite)
```bash
0xhunter scan https://target.com --confirm --proxy http://127.0.0.1:8080
```

### Live Dashboard
```bash
0xhunter dashboard
0xhunter dashboard --port 9000
# Open: http://127.0.0.1:8787
```

### Mass Scan / ASN
```bash
0xhunter mass-scan --targets-file targets.txt --confirm
0xhunter mass-scan --cidr 192.168.1.0/24 --confirm
0xhunter mass-scan --targets-file targets.txt --asn AS13335 --confirm
```

### Nuclei Templates
```bash
0xhunter nuclei --targets-file targets.txt --confirm
0xhunter nuclei --targets-file targets.txt --confirm --severity critical,high
```

---

## Power Commands

```bash
# Ultimate scan — all features
0xhunter scan https://target.com \
  --confirm --full \
  --speed normal \
  --ai --lang en \
  --waf-detect --waf-bypass \
  --compliance owasp \
  --passive-recon \
  --exploit-gen --chain-attacks \
  --oauth --supply-chain \
  --bug-bounty --scope "*.target.com" \
  --pdf --report-dir ./reports \
  --verbose

# Bug Bounty (Google scope)
0xhunter scan https://www.google.com \
  --confirm \
  --module sqli,xss,cors,jwt,headers,ssrf,lfi,cmdi \
  --speed normal \
  --ai --pdf \
  --waf-detect --bug-bounty \
  --scope "*.google.com" \
  --compliance owasp \
  --report-dir ./google_reports \
  --verbose

# Red Team
0xhunter scan https://target.com \
  --confirm --full \
  --speed stealth \
  --exploit-gen --chain-attacks \
  --waf-bypass \
  --proxy http://127.0.0.1:8080 \
  --pdf --report-dir ./reports
```

---

## All Flags Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--confirm` / `-c` | False | Authorization confirmation (required) |
| `--full` / `-f` | False | All 61 modules |
| `--module` / `-m` | None | Specific modules e.g. `sqli,xss,cors` |
| `--verbose` / `-v` | False | Verbose output |
| `--speed` | None | `fast` / `normal` / `stealth` |
| `--threads` | 10 | Parallel threads (overrides --speed) |
| `--timeout` | 10 | Request timeout (overrides --speed) |
| `--delay` | 0.5 | Delay between requests (overrides --speed) |
| `--pdf` | False | Generate PDF report |
| `--report` | None | `html` / `json` / `both` |
| `--report-dir` | ./reports | Report output directory |
| `--output` | auto | Output file path |
| `--cookie` | None | Session cookie |
| `--token` | None | Bearer/JWT token |
| `--auth` | None | Basic auth `user:pass` |
| `--proxy` | None | Proxy URL e.g. `http://127.0.0.1:8080` |
| `--ai` | False | AI-powered analysis |
| `--lang` | en | Report language `en` / `ur` |
| `--ai-chain` | False | Vulnerability chaining AI |
| `--ai-fp` | False | False positive reducer AI |
| `--waf-detect` | False | WAF fingerprinting |
| `--waf-bypass` | False | WAF bypass payloads |
| `--compliance` | None | `owasp` / `pci` / `iso` |
| `--bug-bounty` | False | Bug bounty mode |
| `--scope` | None | In-scope domains e.g. `*.target.com` |
| `--notify` | None | `slack` / `discord` / `both` |
| `--github-issues` | False | Create GitHub issues |
| `--jira` | False | Create Jira tickets |
| `--export-burp` | None | Export to Burp XML |
| `--resume` | None | Resume scan by ID |
| `--targets` | None | Multi-target file |
| `--passive-recon` | False | Passive recon (Shodan+Wayback) |
| `--recon-only` | False | Recon only, no active scan |
| `--exploit-gen` | False | AI PoC exploit generator |
| `--chain-attacks` | False | Smart attack chaining |
| `--oauth` | False | OAuth 2.0 / OIDC testing |
| `--supply-chain` | False | Supply chain detector |
| `--headless` | False | Headless browser (DOM XSS) |

---

## Features

### 61 Scan Modules
| Category | Modules |
|----------|---------|
| Core (7) | XSS, SQLi, CSRF, Headers, Open Redirect, CORS, SSL/TLS |
| Security (8) | SSRF, CMDi, XXE, IDOR, LFI, Race Condition, HTTP Smuggling, JWT |
| Recon (6) | Subdomain, Directory Brute, Git Exposure, Tech Fingerprint, JS Analysis, Email Harvest |
| Advanced (4) | GraphQL, WebSocket, WAF Bypass, Prototype Pollution |
| Auth (3) | Session Fixation, Password Policy, OAuth/OIDC |
| AI (6) | Payload Generator, Vuln Chaining, FP Reducer, NL Report, Exploit Generator, Attack Chain |
| Compliance (3) | OWASP Top 10, PCI-DSS v4.0, ISO 27001:2022 |

### Payload Count (2033+)
| Category | Count | Category | Count |
|----------|-------|----------|-------|
| XSS | 254 | SSTI | 87 |
| SQLi | 221 | WAF Bypass | 95 |
| SSRF | 173 | IDOR | 83 |
| CMD Injection | 165 | Open Redirect | 68 |
| Sensitive Files | 111 | Auth Bypass | 74 |
| LFI | 139 | JWT | 61 |
| Common Dirs | 163 | XXE | 48 |
| Subdomains | 127 | Prototype Poll | 55 |
| **TOTAL** | | | **2033+** |

---

## AI Setup

1. Go to **[console.groq.com/keys](https://console.groq.com/keys)**
2. Sign up (no credit card required)
3. Create API Key → copy `gsk_xxx`

```bash
# Add to .env file or set directly
GROQ_API_KEY=gsk_your_key_here
```

**Free Tier:** 14,400 req/day · 500K tokens/day ✅

---

## Reports

```
reports/
├── scan_report.pdf       ← PDF report (--pdf)
├── report.html           ← HTML vulnerability report
├── report.json           ← Raw findings (JSON)
├── passive_recon.html    ← Passive recon results
├── attack_chains.html    ← Attack chain analysis
├── burp_export.xml       ← Burp Suite format
├── nl_report_en.txt      ← AI English report
├── nl_report_ur.txt      ← AI Urdu report
└── screenshots/          ← Evidence screenshots
    exploits/
    ├── 01_xss_high.js
    └── 02_sqli_critical.py
```

---

## Severity Levels

| Level | CVSS | Action |
|-------|------|--------|
| 🔴 Critical | 9.0–10.0 | Fix immediately |
| 🟠 High | 7.0–8.9 | Fix within 24h |
| 🟡 Medium | 4.0–6.9 | Fix within 7 days |
| 🔵 Low | 1.0–3.9 | Next sprint |
| ⚪ Info | 0.0 | Monitor |

---

## CI/CD

```yaml
name: OXHUNTER Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install oxhunter && playwright install chromium
      - run: |
          0xhunter scan ${{ secrets.TARGET_URL }} \
            --confirm --full \
            --speed normal \
            --report json --output results.json
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: results.json
```

---

## Troubleshooting

```bash
# Update tool
pip install oxhunter --upgrade

# Force reinstall specific version
pip install oxhunter==2.1.0 --force-reinstall

# playwright missing
playwright install chromium

# AI not working
echo $GROQ_API_KEY   # must start with gsk_

# Slow scan
0xhunter scan https://target.com --confirm --speed fast

# flask missing (dashboard)
pip install flask flask-socketio
```

---

## Legal

```
✅ Authorized penetration testing
✅ Bug bounty (in-scope only)
✅ Security research + education
✅ CTF challenges

❌ Unauthorized scanning
❌ Malicious use
❌ Illegal activity
```

---

<div align="center">

## Author

**Talha Imran** — SOC Analyst · Web Pentester · Security Researcher

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Talha_Imran-black?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/talha-imran-583a44420)
[![GitHub](https://img.shields.io/badge/GitHub-Talha--Imran--cloud-black?style=for-the-badge&logo=github)](https://github.com/Talha-Imran-cloud)
[![PyPI](https://img.shields.io/badge/PyPI-oxhunter-black?style=for-the-badge&logo=pypi)](https://pypi.org/project/oxhunter/)

**⭐ Star this repo if the tool helped you!**

*Built for the security community — use responsibly.*

</div>
