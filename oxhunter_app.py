#!/usr/bin/env python3
"""
0xHunter - Web Vulnerability Scanner
Main CLI Entry Point
"""

import asyncio
import os
import json
import pathlib
from pathlib import Path
from typing import Optional

# Load .env / env file automatically
try:
    from dotenv import load_dotenv
    _base = pathlib.Path(__file__).parent
    # Try all common env file names
    for _name in ['.env', 'env', '.env.local', 'env.local']:
        _env_path = _base / _name
        if _env_path.exists():
            load_dotenv(dotenv_path=_env_path, override=True)
            break
    else:
        load_dotenv(override=True)  # fallback — search default locations
except ImportError:
    pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box
from typer import rich_utils as _ru

_ru.STYLE_HELPTEXT               = ""
_ru.STYLE_HELPTEXT_FIRST_LINE    = "bold white"
_ru.STYLE_OPTION                 = "bold cyan"
_ru.STYLE_ARGUMENT               = "bold cyan"
_ru.STYLE_METAVAR                = "cyan"
_ru.STYLE_METAVAR_SEPARATOR      = "dim"
_ru.STYLE_USAGE                  = "bold white"
_ru.STYLE_USAGE_COMMAND          = "bold red"
_ru.STYLE_REQUIRED_LONG          = "bold red"
_ru.STYLE_REQUIRED_SHORT         = "bold red"
_ru.STYLE_OPTIONS_PANEL_BORDER   = "red"
_ru.STYLE_ARGUMENTS_PANEL_BORDER = "red"
_ru.OPTIONS_PANEL_TITLE          = "  Options"
_ru.ARGUMENTS_PANEL_TITLE        = "  Arguments"

from core.scanner import ScannerEngine
from utils.logger import setup_logger

# FIX #3: Import canonical version instead of hardcoding
from core.config import VERSION

app = typer.Typer(
    name="0xHunter",
    help="[bold white]Web Vulnerability Scanner[/bold white]  [dim]|[/dim]  [red]For Authorized Testing Only[/red]",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
logger  = setup_logger("0xHunter")

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High"    : "red",
    "Medium"  : "yellow",
    "Low"     : "green",
    "Info"    : "cyan",
}

BANNER = r"""
  ___       _   _ _   _ _   _ _____ _____ ____  
 / _ \__  _| | | | | | | \ | |_   _| ____|  _ \ 
| | | \ \/ / |_| | | | |  \| | | | |  _| | |_) |
| |_| |>  <|  _  | |_| | |\  | | | | |___|  _ < 
 \___//_/\_\_| |_|\___/|_| \_| |_| |_____|_| \_\
"""


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(
        Panel.fit(
            "[bold white]Web Vulnerability Scanner[/bold white]  [dim]|[/dim]  "
            "[bold red]For Authorized Testing Only[/bold red]  [dim]|[/dim]  "
            f"[dim]v{VERSION}[/dim]",          # FIX #3: dynamic version
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


def _report_path(output: Optional[str], extension: str, timestamp: str,
                 report_dir: Optional[str] = None) -> Path:
    """Return a unique path for one report format.
    Respects --report-dir if supplied; falls back to ./reports otherwise.
    """
    base_dir = Path(report_dir).expanduser() if report_dir else Path("reports")
    if output:
        path = Path(output).expanduser()
        path = path.with_suffix(extension)
        if not path.is_absolute():
            path = base_dir / path
    else:
        safe_ts = timestamp.replace(":", "-").replace(".", "-")
        path = base_dir / f"0xHunter_Report_{safe_ts}{extension}"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _save_json(result, output: Optional[str]) -> str:
    data = {
        "target"      : result.target,
        "start_time"  : result.start_time,
        "end_time"    : result.end_time,
        "urls_crawled": result.urls_crawled,
        "forms_found" : result.forms_found,
        "findings"    : result.findings,
        "summary"     : result.summary,
    }
    path = Path(output) if output else _report_path(None, '.json', result.start_time)
    if not path.is_absolute():
        path = Path('reports') / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    return str(path.resolve())


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL (e.g., https://example.com)"),

    # ── Authorization ─────────────────────────────────────────────────────────
    confirm : bool         = typer.Option(False,  "--confirm",  "-c",  help="Confirm you have authorization to scan"),

    # ── Scan Mode ─────────────────────────────────────────────────────────────
    full    : bool         = typer.Option(False,  "--full",     "-f",  help="Full scan — all 61 modules"),
    verbose : bool         = typer.Option(False,  "--verbose",  "-v",  help="Verbose output"),
    headless  : bool         = typer.Option(False,  "--headless",        help="Use headless browser for JS-heavy targets"),

    # ── Report ────────────────────────────────────────────────────────────────
    report    : Optional[str]= typer.Option(None,   "--report",    "-r", help="Report format: html | json | pdf | both"),
    output    : Optional[str]= typer.Option(None,   "--output",    "-o", help="Output file path (base name)"),
    pdf       : bool         = typer.Option(False,  "--pdf",             help="Generate PDF report (requires weasyprint or pdfkit)"),
    report_dir: Optional[str]= typer.Option(None,   "--report-dir",      help="Directory to save reports (default: ./reports)"),

    # ── Auth ──────────────────────────────────────────────────────────────────
    cookie  : Optional[str]= typer.Option(None,   "--cookie",         help="Session cookie (e.g. 'session=abc123')"),
    token   : Optional[str]= typer.Option(None,   "--token",          help="Bearer / JWT token"),
    auth    : Optional[str]= typer.Option(None,   "--auth",           help="Basic auth user:pass"),

    # ── Proxy ─────────────────────────────────────────────────────────────────
    proxy   : Optional[str]= typer.Option(None,   "--proxy",          help="Proxy URL (e.g. http://127.0.0.1:8080)"),

    # ── AI Features ───────────────────────────────────────────────────────────
    ai      : bool         = typer.Option(False,  "--ai",             help="Enable AI-powered features (requires GROQ_API_KEY)"),
    lang    : str          = typer.Option("en",   "--lang",           help="Report language: en | ur"),
    ai_chain: bool         = typer.Option(False,  "--ai-chain",       help="AI vulnerability chaining"),
    ai_fp   : bool         = typer.Option(False,  "--ai-fp",          help="AI false positive reducer"),

    # ── WAF ───────────────────────────────────────────────────────────────────
    waf_detect : bool      = typer.Option(False,  "--waf-detect",     help="Detect WAF"),
    waf_bypass : bool      = typer.Option(False,  "--waf-bypass",     help="Auto WAF bypass mode"),

    # ── Compliance ────────────────────────────────────────────────────────────
    compliance: Optional[str]= typer.Option(None, "--compliance",     help="Compliance: owasp | pci | iso"),
    bug_bounty: bool       = typer.Option(False,  "--bug-bounty",     help="Bug bounty mode"),
    scope     : Optional[str]= typer.Option(None, "--scope",          help="In-scope domains (e.g. '*.example.com')"),

    # ── Integrations ──────────────────────────────────────────────────────────
    notify  : Optional[str]= typer.Option(None,   "--notify",         help="Notifications: slack | discord | both"),
    github_issues: bool    = typer.Option(False,  "--github-issues",  help="Auto-create GitHub issues"),
    jira    : bool         = typer.Option(False,  "--jira",           help="Auto-create Jira tickets"),

    # ── Burp ──────────────────────────────────────────────────────────────────
    export_burp: Optional[str]= typer.Option(None,"--export-burp",   help="Export findings to Burp XML"),

    # ── Scan Control ──────────────────────────────────────────────────────────
    speed   : Optional[str]= typer.Option(None,   "--speed",          help="Speed preset: fast | normal | stealth  (overridden by --threads/--delay/--timeout)"),
    threads : int          = typer.Option(None,   "--threads",  "-t", help="Number of threads (default: preset value)"),
    timeout : int          = typer.Option(None,   "--timeout",        help="Request timeout in seconds (default: preset value)"),
    delay   : float        = typer.Option(None,   "--delay",          help="Delay between requests (default: preset value)"),
    resume  : Optional[str]= typer.Option(None,   "--resume",         help="Resume scan by scan ID"),
    targets : Optional[str]= typer.Option(None,   "--targets",        help="File with multiple target URLs"),

    # ── New Features ──────────────────────────────────────────────────────────
    passive_recon  : bool         = typer.Option(False, "--passive-recon",  help="Shodan + Wayback + Google Dorks + crt.sh"),
    recon_only     : bool         = typer.Option(False, "--recon-only",     help="Passive recon only, no active scanning"),
    exploit_gen    : bool         = typer.Option(False, "--exploit-gen",    help="AI PoC exploit generator (requires --ai)"),
    chain_attacks  : bool         = typer.Option(False, "--chain-attacks",  help="Smart attack chaining (SSRF→RCE, XSS→ATO)"),
    oauth          : bool         = typer.Option(False, "--oauth",          help="OAuth 2.0 / OIDC security testing"),
    supply_chain   : bool         = typer.Option(False, "--supply-chain",   help="Supply chain attack detector (npm/pip)"),

    # ── Specific Module Selection ──────────────────────────────────────────────
    module: Optional[str] = typer.Option(
        None, "--module", "-m",
        help=(
            "Run specific module(s) only. Comma-separated. "
            "e.g. --module sqli   or   --module sqli,xss,cors  |  "
            "Available: xss sqli csrf headers open_redirect cors ssl ssrf cmdi "
            "xxe lfi idor jwt session password dirs git subdomain tech js "
            "graphql waf prototype race smuggling websocket"
        ),
    ),
):
    """
    [bold white]Scan a target URL for web vulnerabilities.[/bold white]

    [dim]────────────────────────────────────────[/dim]

    [bold red]Examples:[/bold red]

      [cyan]python 0xhunter.py scan https://example.com --confirm[/cyan]

      [cyan]python 0xhunter.py scan https://example.com --confirm --full --report html[/cyan]

      [cyan]python 0xhunter.py scan https://example.com --confirm --ai --lang ur[/cyan]

      [cyan]python 0xhunter.py scan https://example.com --confirm --proxy http://127.0.0.1:8080[/cyan]

      [cyan]python 0xhunter.py scan https://example.com --confirm --compliance owasp[/cyan]

      [cyan]python 0xhunter.py scan https://example.com --confirm --waf-detect --waf-bypass[/cyan]

    [dim]────────────────────────────────────────[/dim]
    """
    print_banner()

    # ── Authorization Check ───────────────────────────────────────────────────
    # FIX #1: --confirm flag alone is sufficient. Removed redundant interactive
    # AuthorizationChecker.confirm() call that caused a second terminal prompt
    # even when --confirm was already passed (breaks CI/CD pipelines).
    if not confirm:
        console.print(
            Panel(
                "[bold red]Authorization Required[/bold red]\n\n"
                "Use [bold yellow]--confirm[/bold yellow] flag to confirm you have "
                "[bold]written permission[/bold] to scan the target.\n\n"
                "[dim red]Unauthorized scanning is ILLEGAL.[/dim red]",
                border_style="red",
                title="[red]⛔ ACCESS DENIED[/red]",
                padding=(1, 2),
            )
        )
        raise typer.Exit(code=3)

    # ── URL Validation ────────────────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        console.print(Panel(
            "[bold red]Invalid URL[/bold red] — must start with [yellow]http://[/yellow] or [yellow]https://[/yellow]",
            border_style="red", padding=(0, 2)))
        raise typer.Exit(code=2)

    # ── AI Key Check ──────────────────────────────────────────────────────────
    if ai and not os.getenv("GROQ_API_KEY"):
        console.print(Panel(
            "[bold yellow]GROQ_API_KEY not set![/bold yellow]\n\n"
            "Set it with:\n"
            "[cyan]$env:GROQ_API_KEY = 'your_key_here'[/cyan]  (Windows)\n"
            "[cyan]export GROQ_API_KEY='your_key_here'[/cyan]  (Linux/Mac)\n\n"
            "[dim]Get free key at: console.groq.com[/dim]",
            border_style="yellow", title="[yellow]⚠ AI Key Missing[/yellow]", padding=(1,2)))
        raise typer.Exit(code=2)

    # ── Scan Config Panel ─────────────────────────────────────────────────────
    ai_status  = "[green]ON[/green]"  if ai         else "[dim]OFF[/dim]"
    waf_status = "[green]ON[/green]"  if waf_bypass else ("[yellow]DETECT[/yellow]" if waf_detect else "[dim]OFF[/dim]")
    prx_status = f"[cyan]{proxy}[/cyan]" if proxy   else "[dim]None[/dim]"
    cmp_status = f"[cyan]{compliance.upper()}[/cyan]" if compliance else "[dim]None[/dim]"
    bb_status  = "[green]ON[/green]"  if bug_bounty else "[dim]OFF[/dim]"

    # Report status — show all active report formats
    # ── Apply Speed Preset FIRST (before config panel) ──────────────────────
    from core.speed_config import get_preset, apply_preset
    _preset  = get_preset(speed)
    _preset  = apply_preset(_preset, threads=threads, delay=delay, timeout=timeout)
    _threads = _preset.threads
    _timeout = _preset.timeout
    _delay   = _preset.delay

    # Report status
    _report_parts = []
    if report:
        _report_parts.append(report.upper())
    if pdf or (report and report.lower() == "pdf"):
        if "PDF" not in _report_parts:
            _report_parts.append("PDF")
    rpt_status = f"[green]{' + '.join(_report_parts)}[/green]" if _report_parts else "[dim]None[/dim]"

    # Mode status
    if module:
        _mods = [m.strip() for m in module.split(",") if m.strip()]
        mode_status = f"[magenta]Specific ({', '.join(_mods)})[/magenta]"
    elif full:
        mode_status = "[yellow]Full Scan — 61 modules[/yellow]"
    else:
        mode_status = "[yellow]Standard Scan — 7 modules[/yellow]"

    # Speed label
    spd_label = f"  [dim]preset:[magenta]{_preset.name.upper()}[/magenta][/dim]" if speed else ""

    console.print(
        Panel(
            f"[bold white]Target     :[/bold white]  [cyan]{url}[/cyan]\n"
            f"[bold white]Mode       :[/bold white]  {mode_status}  "
            f"([dim]threads:{_threads} timeout:{_timeout}s delay:{_delay}s[/dim]){spd_label}\n"
            f"[bold white]Report     :[/bold white]  {rpt_status}\n"
            f"[bold white]AI         :[/bold white]  {ai_status}  [dim]lang:{lang}[/dim]\n"
            f"[bold white]WAF        :[/bold white]  {waf_status}\n"
            f"[bold white]Proxy      :[/bold white]  {prx_status}\n"
            f"[bold white]Compliance :[/bold white]  {cmp_status}\n"
            f"[bold white]Bug Bounty :[/bold white]  {bb_status}",
            title="[bold red]⚡ Scan Configuration[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()

    # ── Run Scan ──────────────────────────────────────────────────────────────

    async def _run():
        engine = ScannerEngine(
            url,
            threads   = _threads,
            timeout   = _timeout,
            delay     = _delay,
            proxy     = proxy,
            cookie    = cookie,
            token     = token,
            auth      = auth,
            verbose   = verbose,
            headless  = headless,   # --headless FIX: wire option into engine
        )
        # Parse --module flag into list
        _modules = [m.strip().lower() for m in module.split(",")] if module else None
        result = await engine.run(full_scan=full, modules=_modules)

        # ── OAuth Testing (inside event loop) ─────────────────────────────────
        oauth_findings = []
        if oauth:
            try:
                from modules.oauth_tester import OAuthTester
                ot          = OAuthTester()
                oauth_findings = await ot.scan([url])   # FIX #2: await, not get_event_loop()
            except Exception as _e:
                logger.debug(f"OAuth scan error: {_e}")

        # ── Supply Chain (inside event loop) ──────────────────────────────────
        sc_findings = []
        if supply_chain:
            try:
                from modules.supply_chain import SupplyChainDetector
                sc         = SupplyChainDetector()
                sc_findings = await sc.scan([url])      # FIX #2: await, not get_event_loop()
            except Exception as _e:
                logger.debug(f"Supply chain scan error: {_e}")

        return engine, result, oauth_findings, sc_findings

    try:
        engine, result, oauth_findings, sc_findings = asyncio.run(_run())
        findings = result.findings or []

        # ── Results Summary ───────────────────────────────────────────────────
        console.print(Rule("[bold red]SCAN RESULTS[/bold red]", style="red"))

        table = Table(
            title="[bold]Vulnerability Summary[/bold]",
            box=box.ROUNDED, border_style="red",
            header_style="bold red", show_lines=True,
        )
        table.add_column("Severity", justify="center", style="bold", min_width=12)
        table.add_column("Count",    justify="center", min_width=8)

        has_findings = False
        for sev, count in result.summary.items():
            if count > 0:
                has_findings = True
                style = SEVERITY_STYLES.get(sev, "white")
                table.add_row(f"[{style}]{sev}[/{style}]", f"[{style}]{count}[/{style}]")

        if not has_findings:
            table.add_row("[green]No Issues Found[/green]", "[green]0[/green]")
        console.print(table)

        # ── Detailed Findings ─────────────────────────────────────────────────
        if findings:
            console.print(f"\n[bold red]Detailed Findings[/bold red]")
            console.print(Rule(style="red"))
            for i, finding in enumerate(findings, 1):   # FIX #5: renamed 'f' → 'finding'
                sev   = finding.get("severity", "Info")
                style = SEVERITY_STYLES.get(sev, "white")
                console.print(Panel(
                    f"[bold white]Parameter :[/bold white] {finding.get('parameter','N/A')}\n"
                    f"[bold white]Confidence:[/bold white] {finding.get('confidence','N/A')}\n"
                    f"[bold white]Evidence  :[/bold white] {finding.get('evidence','N/A')}",
                    title=f"[{style}]#{i}  [{finding.get('type')}]  {sev}  —  {finding.get('url')}[/{style}]",
                    border_style=style, padding=(0, 2),
                ))

        # ── WAF Detection ─────────────────────────────────────────────────────
        if waf_detect or waf_bypass:
            console.print(Rule("[bold red]WAF Analysis[/bold red]", style="red"))
            from core.waf_detector import WAFDetector
            wd  = WAFDetector(proxy=proxy)
            det = wd.detect(url)
            waf_name = det.get("waf","Unknown")
            if det.get("detected"):
                console.print(f"  [yellow]WAF Detected:[/yellow] [bold]{waf_name}[/bold] (confidence:{det.get('confidence')})")
                if waf_bypass:
                    bypasses = wd.test_bypasses(url, waf_name)
                    working  = [b for b in bypasses if b.get("bypassed")]
                    console.print(f"  [cyan]Bypass Results:[/cyan] {len(working)}/{len(bypasses)} payloads bypassed WAF")
            else:
                console.print("  [green]No WAF detected[/green]")

        # ── AI Features ───────────────────────────────────────────────────────
        if ai and findings:
            console.print(Rule("[bold red]AI Analysis[/bold red]", style="red"))

            _groq_key = os.getenv("GROQ_API_KEY", "").strip()
            if not _groq_key or not _groq_key.startswith("gsk_"):
                console.print(Panel(
                    "[yellow]⚠ GROQ_API_KEY not set or invalid![/yellow]\n\n"
                    "Set it:\n"
                    "  [cyan]$env:GROQ_API_KEY = 'gsk_your_key'[/cyan]  (Windows)\n"
                    "  [cyan]export GROQ_API_KEY='gsk_your_key'[/cyan]   (Linux)\n\n"
                    "Free key: [link]https://console.groq.com/keys[/link]",
                    title="[bold yellow]⚠ AI Key Missing[/bold yellow]",
                    border_style="yellow", padding=(1,2)))
            else:
                # AI Payload Generator
                try:
                    from ai.payload_generator import AIPayloadGenerator
                    gen = AIPayloadGenerator(api_key=os.getenv("GROQ_API_KEY", ""))
                    vuln_types = list(set(finding.get("type","xss") for finding in findings))
                    console.print(f"  [cyan]AI Payload Generator:[/cyan] Generating for {vuln_types}")
                    for vt in vuln_types[:3]:
                        context = {"target": url, "vuln_type": vt}
                        payloads = gen.generate_custom(vt, context)
                        console.print(f"  [dim]→ {vt}: {len(payloads)} AI payloads generated[/dim]")
                except Exception as e:
                    console.print(f"  [yellow]AI Payload Generator skipped: {e}[/yellow]")

            # False Positive Reducer
            if ai_fp:
                try:
                    from ai.fp_reducer import FalsePositiveReducer
                    fpr     = FalsePositiveReducer()
                    before  = len(findings)
                    result_fp = fpr.filter_findings(findings)
                    findings = result_fp.get("confirmed", findings)
                    console.print(f"  [cyan]False Positive Reducer:[/cyan] {before} → {len(findings)} findings")
                except Exception as e:
                    console.print(f"  [yellow]FP Reducer skipped: {e}[/yellow]")

            # Vulnerability Chaining
            if ai_chain:
                try:
                    from ai.vuln_chaining import VulnChainer
                    chainer = VulnChainer()
                    chains  = chainer.analyze_chains(findings)
                    if chains:
                        console.print(f"  [cyan]Vuln Chains Found:[/cyan] {len(chains)}")
                        for ch in chains[:3]:
                            console.print(f"  [dim red]→ {ch}[/dim red]")
                except Exception as e:
                    console.print(f"  [yellow]Chaining skipped: {e}[/yellow]")

            # NL Report
            try:
                from ai.nl_report import NLReportGenerator
                # FIX: language is NOT a constructor param — pass api_key only
                nlr     = NLReportGenerator(api_key=os.getenv("GROQ_API_KEY", ""))
                scan_data = {"target": url, "findings": findings, "summary": result.summary}
                nl_report = nlr.generate_full_report(scan_data, language=lang)
                nl_text = nl_report.get("executive_summary_en") or nl_report.get("executive_summary_ur", "")
                if nl_text:
                    console.print(Panel(
                        nl_text[:800],
                        title=f"[bold red]AI Report ({'Urdu' if lang=='ur' else 'English'})[/bold red]",
                        border_style="red", padding=(1,2),
                    ))
            except Exception as e:
                console.print(f"  [yellow]NL Report skipped: {e}[/yellow]")

        # ── Compliance ────────────────────────────────────────────────────────
        if compliance:
            console.print(Rule("[bold red]Compliance Report[/bold red]", style="red"))
            findings_dicts = [{"vuln_type": finding.get("type",""), "severity": finding.get("severity","")} for finding in findings]
            if compliance == "owasp":
                from compliance.owasp_mapping import OWASPMapper
                score = OWASPMapper.compliance_score(findings_dicts)
                console.print(f"  [cyan]OWASP Top 10:[/cyan] Score [bold]{score['score']}/100[/bold] ({score['status']})")
                console.print(f"  Passed: [green]{score['passed']}[/green]  Failed: [red]{score['failed']}[/red]")
            elif compliance == "pci":
                from compliance.pci_iso_report import ComplianceReporter
                rpt = ComplianceReporter(findings_dicts, url)
                r   = rpt.pci_report()
                console.print(f"  [cyan]PCI-DSS v4.0:[/cyan] Score [bold]{r['score']}/100[/bold] ({r['status']})")
            elif compliance == "iso":
                from compliance.pci_iso_report import ComplianceReporter
                rpt = ComplianceReporter(findings_dicts, url)
                r   = rpt.iso_report()
                console.print(f"  [cyan]ISO 27001:2022:[/cyan] Score [bold]{r['score']}/100[/bold] ({r['status']})")

        # ── Bug Bounty Filter ─────────────────────────────────────────────────
        if bug_bounty and scope:
            from compliance.bug_bounty import setup as bb_setup
            bb    = bb_setup(scope.split(","))
            valid = bb.filter_findings([{"vuln_type":finding.get("type",""),"severity":finding.get("severity",""),"url":finding.get("url","")} for finding in findings])
            console.print(Rule("[bold red]Bug Bounty Mode[/bold red]", style="red"))
            console.print(f"  [cyan]In-Scope Findings:[/cyan] [bold]{len(valid)}[/bold] / {len(findings)}")

        # ── Notifications ─────────────────────────────────────────────────────
        if notify and findings:
            findings_dicts = [{"vuln_type":finding.get("type",""),"severity":finding.get("severity",""),"url":finding.get("url",""),"detail":finding.get("evidence","")} for finding in findings]
            from integrations.slack_webhook import AlertManager
            slack_url   = os.getenv("SLACK_WEBHOOK_URL","")
            discord_url = os.getenv("DISCORD_WEBHOOK_URL","")
            am = AlertManager(
                slack_url   = slack_url   if notify in ["slack","both"]   else "",
                discord_url = discord_url if notify in ["discord","both"] else "",
            )
            am.alert_summary(url, findings_dicts)
            console.print(f"  [green]✔ Notifications sent via {notify}[/green]")

        # ── GitHub Issues ─────────────────────────────────────────────────────
        if github_issues and findings:
            from integrations.jira_github import GitHubIntegration
            gh = GitHubIntegration(
                token = os.getenv("GITHUB_TOKEN",""),
                repo  = os.getenv("GITHUB_REPO",""),
            )
            findings_dicts = [{"vuln_type":finding.get("type",""),"severity":finding.get("severity",""),"url":finding.get("url",""),"detail":finding.get("evidence",""),"cvss_score":0} for finding in findings]
            created = gh.create_bulk(findings_dicts, "HIGH")
            console.print(f"  [green]✔ {len(created)} GitHub issues created[/green]")

        # ── Jira ──────────────────────────────────────────────────────────────
        if jira and findings:
            from integrations.jira_github import JiraIntegration
            ji = JiraIntegration(
                url     = os.getenv("JIRA_URL",""),
                user    = os.getenv("JIRA_USER",""),
                token   = os.getenv("JIRA_TOKEN",""),
                project = os.getenv("JIRA_PROJECT","SEC"),
            )
            findings_dicts = [{"vuln_type":finding.get("type",""),"severity":finding.get("severity",""),"url":finding.get("url",""),"detail":finding.get("evidence",""),"cvss_score":0} for finding in findings]
            created = ji.create_bulk(findings_dicts, "HIGH")
            console.print(f"  [green]✔ {len(created)} Jira tickets created[/green]")

        # ── Burp Export ───────────────────────────────────────────────────────
        if export_burp:
            from integrations.burp_export import BurpExporter
            findings_dicts = [{"vuln_type":finding.get("type",""),"severity":finding.get("severity",""),"url":finding.get("url",""),"payload":finding.get("evidence",""),"detail":finding.get("evidence",""),"cvss_score":0,"remediation":"","evidence":""} for finding in findings]
            path = BurpExporter().export(findings_dicts, export_burp)
            console.print(f"  [green]✔ Burp XML exported → {path}[/green]")

        # ── Reports ───────────────────────────────────────────────────────────
        console.print()
        console.print(Panel("[bold green]✔  Scan completed successfully![/bold green]", border_style="green", padding=(0,2)))

        # ── Resolve report base dir (--report-dir wins over default) ────────
        _rdir = report_dir  # may be None → _report_path falls back to ./reports

        if report:
            fmt = report.lower()
            if fmt in ["html", "both"]:
                console.print("\n[cyan]Generating HTML report...[/cyan]")
                html_path = _report_path(output, '.html', result.start_time, _rdir)
                path = engine.generate_html_report(str(html_path))
                console.print(Panel(f"[bold green]HTML Report:[/bold green]\n[cyan]{os.path.abspath(path)}[/cyan]", border_style="green", padding=(0,2)))
            if fmt in ["json", "both"]:
                console.print("\n[cyan]Generating JSON report...[/cyan]")
                json_path = _report_path(output, '.json', result.start_time, _rdir)
                path = _save_json(result, str(json_path))
                console.print(Panel(f"[bold green]JSON Report:[/bold green]\n[cyan]{path}[/cyan]", border_style="green", padding=(0,2)))
            if fmt in ["pdf"]:
                pdf = True  # --report pdf is equivalent to --pdf
            if fmt not in ["html", "json", "both", "pdf"]:
                console.print(f"[yellow]Unknown format '{fmt}'. Use: html | json | pdf | both[/yellow]")

        # --pdf flag: generate PDF report (works standalone or alongside --report)
        if pdf:
            console.print("\n[cyan]Generating PDF report...[/cyan]")
            try:
                from core.pdf_report import ReportGenerator
                pdf_path = _report_path(output, '.pdf', result.start_time, _rdir)
                gen = ReportGenerator()
                findings_for_pdf = result.findings if hasattr(result, 'findings') else []
                saved = gen.generate_pdf(
                    scan_data={"target": result.target, "start_time": result.start_time,
                               "end_time": result.end_time, "summary": result.summary},
                    findings=findings_for_pdf,
                    output_path=str(pdf_path),
                )
                console.print(Panel(f"[bold green]PDF Report:[/bold green]\n[cyan]{os.path.abspath(saved)}[/cyan]", border_style="green", padding=(0,2)))
            except Exception as _pdf_err:
                console.print(f"[yellow]PDF generation failed: {_pdf_err}[/yellow]\n[dim]Install weasyprint or pdfkit to enable PDF reports.[/dim]")

        # ── Passive Recon ─────────────────────────────────────────────────────
        if passive_recon or recon_only:
            console.print(Rule("[bold red]Passive Recon[/bold red]", style="red"))
            try:
                from recon.passive_recon import PassiveRecon
                pr      = PassiveRecon(shodan_key=os.getenv("SHODAN_API_KEY",""))
                recon_r = pr.run(url)
                console.print(f"  [cyan]Subdomains:[/cyan]  {len(recon_r.get('subdomains',[]))}")
                console.print(f"  [cyan]Historical URLs:[/cyan] {len(recon_r.get('historical_urls',[]))}")
                console.print(f"  [cyan]Exposed Services:[/cyan] {len(recon_r.get('exposed_services',[]))}")
                console.print(f"  [cyan]Google Dorks:[/cyan] {len(recon_r.get('google_dorks',[]))}")
                os.makedirs("reports", exist_ok=True)
                recon_html = pr.html_report(recon_r)
                with open("reports/passive_recon.html", "w", encoding="utf-8") as fh:  # FIX #5: 'f' → 'fh'
                    fh.write(recon_html)
                console.print("  [green]✔ Recon report: reports/passive_recon.html[/green]")
            except Exception as e:
                console.print(f"  [yellow]Passive recon error: {e}[/yellow]")

        # ── OAuth Results (collected inside event loop above) ──────────────────
        if oauth:
            console.print(Rule("[bold red]OAuth/OIDC Testing[/bold red]", style="red"))
            if oauth_findings:
                console.print(f"  [cyan]OAuth Issues:[/cyan] {len(oauth_findings)}")
                for of in oauth_findings:
                    console.print(f"  [{SEVERITY_STYLES.get(of.severity.capitalize(),'white')}][{of.severity}][/] {of.type} — {of.detail[:60]}")
            else:
                console.print("  [green]No OAuth issues found (or module skipped)[/green]")

        # ── Supply Chain Results (collected inside event loop above) ───────────
        if supply_chain:
            console.print(Rule("[bold red]Supply Chain Check[/bold red]", style="red"))
            if sc_findings:
                console.print(f"  [cyan]Supply Chain Issues:[/cyan] {len(sc_findings)}")
                for sf in sc_findings:
                    console.print(f"  [yellow][{sf.severity}][/yellow] {sf.type} — {sf.package[:40]}")
            else:
                console.print("  [green]No supply chain issues found (or module skipped)[/green]")

        # ── AI Exploit Generator ───────────────────────────────────────────────
        if exploit_gen and ai and findings:
            console.print(Rule("[bold red]AI Exploit Generator[/bold red]", style="red"))
            try:
                from ai.exploit_generator import AIExploitGenerator
                eg       = AIExploitGenerator(api_key=os.getenv("GROQ_API_KEY",""))
                exploits = eg.generate_for_all(findings, max_exploits=5)
                saved    = eg.save_exploits(exploits)
                console.print(f"  [green]✔ {len(exploits)} exploits generated[/green]")
                for s in saved:
                    console.print(f"  [cyan]→ {s}[/cyan]")
                exp_html = eg.generate_report(exploits, url)
                with open("reports/exploits.html", "w", encoding="utf-8") as fh:   # FIX #5: 'f' → 'fh'
                    fh.write(exp_html)
                console.print("  [green]✔ Exploit report: reports/exploits.html[/green]")
            except Exception as e:
                console.print(f"  [yellow]Exploit gen error: {e}[/yellow]")

        # ── Smart Attack Chaining ──────────────────────────────────────────────
        if chain_attacks and findings:
            console.print(Rule("[bold red]Attack Chain Analysis[/bold red]", style="red"))
            try:
                from ai.attack_chaining import SmartAttackChainer
                chainer = SmartAttackChainer(api_key=os.getenv("GROQ_API_KEY",""))
                chains  = chainer.ai_chain_analysis(findings) if ai else chainer.find_chains(findings)
                summary = chainer.summary(chains)
                console.print(f"  [cyan]Chains Found:[/cyan]    {summary['total_chains']}")
                console.print(f"  [red]Critical Chains:[/red] {summary['critical_chains']}")
                console.print(f"  [cyan]Highest CVSS:[/cyan]   {summary['highest_cvss']}")
                for c in chains[:3]:
                    console.print(f"  [red][{c.severity}][/red] {c.name} (CVSS:{c.cvss})")
                chain_html = chainer.html_report(chains, url)
                with open("reports/attack_chains.html", "w", encoding="utf-8") as fh:  # FIX #5: 'f' → 'fh'
                    fh.write(chain_html)
                console.print("  [green]✔ Chain report: reports/attack_chains.html[/green]")
            except Exception as e:
                console.print(f"  [yellow]Chain analysis error: {e}[/yellow]")

        # ── CI/CD Exit Code ───────────────────────────────────────────────────
        critical = [finding for finding in findings if finding.get("severity") in ["Critical","High"]]
        if critical:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(Panel(
            f"[bold red]Scan Failed[/bold red]\n\n{e}",
            border_style="red", title="[red]✖ ERROR[/red]", padding=(1,2)))
        raise typer.Exit(code=1)


@app.command("dashboard")
def dashboard(host: str = typer.Option("127.0.0.1", help="Bind address; keep localhost for local use"),
              port: int = typer.Option(8787, help="Dashboard port")):
    """Start the local live scan dashboard."""
    from dashboard_server import ThreadingHTTPServer, Handler
    console.print(f"[green]Dashboard:[/green] http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


@app.command("mass-scan")
def mass_scan(targets_file: Optional[str] = typer.Option(None, help="File with authorized URLs/hosts"),
              cidr: Optional[str] = typer.Option(None, help="One authorized CIDR; limited by --max-hosts"),
              domains_file: Optional[str] = typer.Option(None, help="File with authorized domains"),
              asn: Optional[str] = typer.Option(None, help="ASN for passive prefix discovery, e.g. AS13335"),
              max_hosts: int = typer.Option(256, min=1, max=2048),
              concurrency: int = typer.Option(10, min=1, max=50),
              confirm: bool = typer.Option(False, "--confirm", help="Confirm written authorization"),
              output: Optional[str] = typer.Option(None, help="JSON output path")):
    """Probe an explicitly authorized asset inventory; never use without written permission."""
    if not confirm:
        raise typer.BadParameter("--confirm is required for mass scanning")
    from mass_scan import MassScanner
    from asn_scan import ASNScanner
    import json
    def lines(path):
        return [x.strip() for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()] if path else []
    targets = lines(targets_file)
    domains = lines(domains_file)
    cidrs = [cidr] if cidr else []
    async def run():
        if asn:
            cidrs.extend(await ASNScanner().prefixes(asn))
        return await MassScanner(concurrency=concurrency, max_hosts=max_hosts).scan(
            targets=targets, cidrs=cidrs, domains=domains, authorized=True)
    results = asyncio.run(run())
    text = json.dumps(results, indent=2)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]Mass-scan results:[/green] {Path(output).resolve()}")
    else:
        console.print(text)


@app.command("nuclei")
def nuclei(targets_file: str = typer.Option(..., help="File with authorized HTTP(S) targets"),
           templates: str = typer.Option("nuclei-templates", help="Local Nuclei templates directory"),
           severity: str = typer.Option("info,low,medium,high,critical"),
           concurrency: int = typer.Option(10, min=1, max=50),
           rate_limit: int = typer.Option(50, min=1, max=500),
           confirm: bool = typer.Option(False, "--confirm", help="Confirm written authorization"),
           output: Optional[str] = typer.Option(None, help="JSONL output path")):
    """Run local Nuclei templates against an explicitly authorized target file."""
    if not confirm:
        raise typer.BadParameter("--confirm is required for Nuclei scans")
    from nuclei_integration import NucleiRunner
    targets = [x.strip() for x in Path(targets_file).read_text(encoding="utf-8").splitlines() if x.strip()]
    findings = asyncio.run(NucleiRunner(concurrency=concurrency, rate_limit=rate_limit).run(
        targets, templates, authorized=True, severities=severity.split(",")))
    # FIX #4: "\n" (real newline) instead of "\\n" (literal backslash-n)
    text = "\n".join(json.dumps(x, ensure_ascii=False) for x in findings) + ("\n" if findings else "")
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]Nuclei results:[/green] {Path(output).resolve()}")
    else:
        console.print(text)


@app.command()
def version():
    """Show version information."""
    print_banner()
    console.print(Panel(
        f"[bold white]Version    :[/bold white]  [cyan]{VERSION}[/cyan]\n"   # FIX #3: dynamic version
        "[bold white]Features   :[/bold white]  [cyan]61[/cyan]\n"
        "[bold white]AI Engine  :[/bold white]  [cyan]Groq (LLaMA 3)[/cyan]\n"
        "[bold white]License    :[/bold white]  [dim]MIT with Ethical Use Clause[/dim]\n\n"
        "[dim red]For authorized security testing only.[/dim red]",
        title="[bold red]ℹ  0xHunter[/bold red]",
        border_style="red", padding=(1,2),
    ))


if __name__ == "__main__":
    app()
