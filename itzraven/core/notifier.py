"""
Notification System — sends alerts for scan events via Slack, Discord, Email, and Webhooks.

Subscribes to the event bus and forwards critical findings and scan status
to configured notification channels.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable

import httpx

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.core.event_bus import get_event_bus

logger = get_logger()
config = get_config()


@dataclass
class NotificationChannel:
    name: str
    type: str  # slack, discord, email, webhook
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    min_severity: str = "high"  # critical, high, medium, low, info

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "min_severity": self.min_severity,
        }


SEVERITY_LEVELS = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_EMOJIS = {
    "critical": ":fire:",
    "high": ":warning:",
    "medium": ":large_orange_diamond:",
    "low": ":information_source:",
    "info": ":book:",
}


class Notifier:
    """Sends notifications to configured channels on scan events."""

    def __init__(self):
        self._channels: Dict[str, NotificationChannel] = {}
        self._http = httpx.AsyncClient(timeout=10.0)
        self._subscribed = False

    def add_channel(self, channel: NotificationChannel):
        self._channels[channel.name] = channel
        logger.info(f"Notification channel added: {channel.name} ({channel.type})")

    def remove_channel(self, name: str) -> bool:
        return self._channels.pop(name, None) is not None

    def list_channels(self) -> List[dict]:
        return [c.to_dict() for c in self._channels.values()]

    def get_channel(self, name: str) -> Optional[NotificationChannel]:
        return self._channels.get(name)

    async def notify_finding(self, title: str, severity: str, description: str,
                             target: str = "", evidence: str = ""):
        tasks = []
        for channel in self._channels.values():
            if not channel.enabled:
                continue
            if SEVERITY_LEVELS.get(severity, 99) > SEVERITY_LEVELS.get(channel.min_severity, 99):
                continue
            tasks.append(self._send(channel, title, severity, description, target, evidence))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def notify_scan_start(self, target: str, mode: str):
        tasks = []
        for channel in self._channels.values():
            if not channel.enabled:
                continue
            tasks.append(self._send(
                channel, f"Scan Started: {target}",
                "info", f"Mode: {mode}", target,
            ))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def notify_scan_complete(self, target: str, finding_count: int, duration: float):
        tasks = []
        for channel in self._channels.values():
            if not channel.enabled:
                continue
            tasks.append(self._send(
                channel, f"Scan Complete: {target}",
                "info", f"Findings: {finding_count} | Duration: {duration:.1f}s", target,
            ))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send(self, channel: NotificationChannel, title: str, severity: str,
                    description: str, target: str, evidence: str = ""):
        try:
            if channel.type == "slack":
                await self._send_slack(channel, title, severity, description, target, evidence)
            elif channel.type == "discord":
                await self._send_discord(channel, title, severity, description, target, evidence)
            elif channel.type == "webhook":
                await self._send_webhook(channel, title, severity, description, target, evidence)
        except Exception as e:
            logger.error(f"Failed to send {channel.type} notification to {channel.name}: {e}")

    async def _send_slack(self, channel: NotificationChannel, title: str, severity: str,
                          description: str, target: str, evidence: str):
        webhook_url = channel.config.get("webhook_url")
        if not webhook_url:
            return
        emoji = SEVERITY_EMOJIS.get(severity, ":warning:")
        payload = {
            "text": f"{emoji} *[{severity.upper()}] {title}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *[{severity.upper()}] {title}*",
                    },
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": description}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Target:* {target}"}},
            ],
        }
        if evidence:
            payload["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Evidence:* `{evidence[:500]}`"},
            })
        await self._http.post(webhook_url, json=payload)

    async def _send_discord(self, channel: NotificationChannel, title: str, severity: str,
                            description: str, target: str, evidence: str):
        webhook_url = channel.config.get("webhook_url")
        if not webhook_url:
            return
        color_map = {"critical": 15548997, "high": 15105570, "medium": 16776960, "low": 3447003, "info": 8421504}
        embed = {
            "title": title,
            "description": description,
            "color": color_map.get(severity, 8421504),
            "fields": [
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Target", "value": target, "inline": True},
            ],
        }
        if evidence:
            embed["fields"].append({"name": "Evidence", "value": f"`{evidence[:500]}`"})
        payload = {"embeds": [embed]}
        await self._http.post(webhook_url, json=payload)

    async def _send_webhook(self, channel: NotificationChannel, title: str, severity: str,
                            description: str, target: str, evidence: str):
        url = channel.config.get("url")
        if not url:
            return
        payload = {
            "event": "finding",
            "severity": severity,
            "title": title,
            "description": description,
            "target": target,
            "evidence": evidence[:500],
        }
        headers = {"Content-Type": "application/json"}
        if channel.config.get("auth_header"):
            headers["Authorization"] = channel.config["auth_header"]
        await self._http.post(url, json=payload, headers=headers)

    def subscribe_to_events(self):
        if self._subscribed:
            return
        bus = get_event_bus()

        @bus.subscribe("finding.discovered")
        async def on_finding(event):
            await self.notify_finding(
                title=getattr(event, "title", "Finding"),
                severity=getattr(event, "severity", "info"),
                description=getattr(event, "description", ""),
                target=getattr(event, "target", ""),
                evidence=getattr(event, "evidence", ""),
            )

        @bus.subscribe("scan.started")
        async def on_scan_start(event):
            await self.notify_scan_start(
                target=getattr(event, "target", ""),
                mode=getattr(event, "mode", ""),
            )

        @bus.subscribe("scan.completed")
        async def on_scan_complete(event):
            await self.notify_scan_complete(
                target=getattr(event, "target", ""),
                finding_count=getattr(event, "total_findings", 0),
                duration=getattr(event, "duration", 0),
            )

        self._subscribed = True
        logger.info("Notifier subscribed to event bus")

    def close(self):
        import asyncio
        try:
            asyncio.create_task(self._http.aclose())
        except Exception:
            pass


_notifier: Optional[Notifier] = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
