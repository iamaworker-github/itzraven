"""Tests for the Notification System."""

import pytest
from itzraven.core.notifier import Notifier, NotificationChannel


def test_channel_creation():
    channel = NotificationChannel(
        name="test-slack",
        type="slack",
        config={"webhook_url": "https://hooks.slack.com/test"},
        min_severity="high",
    )
    assert channel.name == "test-slack"
    assert channel.type == "slack"
    assert channel.enabled is True


def test_notifier_add_remove():
    notifier = Notifier()
    channel = NotificationChannel(name="webhook1", type="webhook", config={"url": "https://example.com/hook"})
    notifier.add_channel(channel)
    channels = notifier.list_channels()
    assert len(channels) >= 1

    assert notifier.remove_channel("webhook1") is True
    assert notifier.remove_channel("nonexistent") is False


@pytest.mark.asyncio
async def test_notify_finding_no_crash():
    notifier = Notifier()
    await notifier.notify_finding(
        title="SQL Injection",
        severity="critical",
        description="SQLi found in login",
        target="https://example.com",
    )


def test_notifier_singleton():
    from itzraven.core.notifier import get_notifier
    n1 = get_notifier()
    n2 = get_notifier()
    assert n1 is n2


def test_channel_severity_filtering():
    notifier = Notifier()
    channel = NotificationChannel(name="critical-only", type="webhook", min_severity="critical")
    notifier.add_channel(channel)

    ch = notifier.get_channel("critical-only")
    assert ch is not None
    assert ch.min_severity == "critical"

    notifier.remove_channel("critical-only")
