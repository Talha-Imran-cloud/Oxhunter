"""
OXHUNTER - slack_webhook.py
Slack + Discord Webhook Alerts
"""

import requests
from typing import List, Dict

SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠",
    "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
}


class SlackAlerter:
    def __init__(self, webhook_url: str):
        self.url = webhook_url

    def _send(self, payload: Dict) -> bool:
        try:
            r = requests.post(self.url, json=payload, timeout=10)
            return r.status_code == 200
        except Exception as e:
            print(f"[!] Slack error: {e}")
            return False

    def send_vuln(self, vuln_type: str, severity: str,
                  url: str, detail: str = "") -> bool:
        em = SEVERITY_EMOJI.get(severity, "⚪")
        payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text",
                    "text": f"{em} OXHUNTER — {severity} Vulnerability Found"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Type:*\n{vuln_type}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*URL:*\n{url}"},
                    {"type": "mrkdwn", "text": f"*Detail:*\n{detail or 'N/A'}"},
                ]},
            ]
        }
        return self._send(payload)

    def send_summary(self, target: str, findings: List[Dict]) -> bool:
        counts = {}
        for f in findings:
            counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"), 0) + 1

        lines = "\n".join(f"{SEVERITY_EMOJI.get(s,'⚪')} {s}: {c}" for s, c in counts.items())
        payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text",
                    "text": "📋 OXHUNTER — Scan Complete"}},
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": f"*Target:* {target}\n*Total:* {len(findings)}\n\n{lines}"}},
            ]
        }
        return self._send(payload)

    def send_text(self, msg: str) -> bool:
        return self._send({"text": msg})


class DiscordAlerter:
    def __init__(self, webhook_url: str):
        self.url = webhook_url

    def _send(self, payload: Dict) -> bool:
        try:
            r = requests.post(self.url, json=payload, timeout=10)
            return r.status_code in [200, 204]
        except Exception as e:
            print(f"[!] Discord error: {e}")
            return False

    def send_vuln(self, vuln_type: str, severity: str,
                  url: str, detail: str = "") -> bool:
        color_map = {"CRITICAL": 0xFF0000, "HIGH": 0xFF6600,
                     "MEDIUM": 0xFFCC00, "LOW": 0x0099FF, "INFO": 0x00FF00}
        em = SEVERITY_EMOJI.get(severity, "⚪")
        payload = {
            "embeds": [{
                "title"      : f"{em} {severity} — {vuln_type}",
                "color"      : color_map.get(severity, 0xFFFFFF),
                "fields"     : [
                    {"name": "URL",    "value": url,            "inline": False},
                    {"name": "Detail", "value": detail or "N/A","inline": False},
                ],
                "footer": {"text": "OXHUNTER Security Scanner"},
            }]
        }
        return self._send(payload)

    def send_summary(self, target: str, findings: List[Dict]) -> bool:
        counts = {}
        for f in findings:
            counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"), 0) + 1
        desc = "\n".join(f"{SEVERITY_EMOJI.get(s,'⚪')} **{s}**: {c}" for s, c in counts.items())
        payload = {
            "embeds": [{
                "title"      : "📋 OXHUNTER Scan Complete",
                "description": f"**Target:** {target}\n**Total:** {len(findings)}\n\n{desc}",
                "color"      : 0x7289DA,
                "footer"     : {"text": "OXHUNTER Security Scanner"},
            }]
        }
        return self._send(payload)

    def send_text(self, msg: str) -> bool:
        return self._send({"content": msg})


# ── Unified Alert Manager ─────────────────────
class AlertManager:
    def __init__(self, slack_url: str = "", discord_url: str = ""):
        self.slack   = SlackAlerter(slack_url)   if slack_url   else None
        self.discord = DiscordAlerter(discord_url) if discord_url else None

    def alert_vuln(self, vuln_type: str, severity: str,
                   url: str, detail: str = ""):
        if self.slack:
            self.slack.send_vuln(vuln_type, severity, url, detail)
        if self.discord:
            self.discord.send_vuln(vuln_type, severity, url, detail)

    def alert_summary(self, target: str, findings: List[Dict]):
        if self.slack:
            self.slack.send_summary(target, findings)
        if self.discord:
            self.discord.send_summary(target, findings)

    def alert_critical_only(self, findings: List[Dict], target: str):  # BUG-014 FIX: target kept for API compatibility
        """Only alert for CRITICAL/HIGH findings."""
        _ = target  # BUG-014 FIX: suppress unused arg warning; kept for consistent API signature
        for f in findings:
            if f.get("severity") in ["CRITICAL", "HIGH"]:
                self.alert_vuln(f["vuln_type"], f["severity"],
                                f["url"], f.get("detail",""))
