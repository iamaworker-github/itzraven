"""
Strix-inspired TUI for Itzraven
Complete redesign matching Strix's UI/UX
"""

import asyncio
import time
import psutil
from datetime import datetime
from typing import Any, Optional, List, ClassVar, Dict

from itzraven.agents.llm_client import get_cost_tracker, LLMClient
from itzraven.core.config import get_config
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Static, Tree, Label, Input, Button, OptionList
from textual.widgets.option_list import Option
from textual.binding import Binding
from textual.reactive import reactive
from textual import events
from textual.widget import Widget
from textual.widgets.tree import TreeNode
from textual.screen import ModalScreen
from rich.text import Text
from rich.style import Style
from rich.console import Group
from rich.panel import Panel

from itzraven import __version__
from itzraven.agents.orchestrator import AgentOrchestrator, ScanResult
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger
from itzraven.core import EventBus, MEMORY_SYSTEM_AVAILABLE
from itzraven.core.events import (
    ScanStartedEvent,
    ScanCompletedEvent,
    AgentStartedEvent,
    AgentCompletedEvent,
    AgentProgressEvent,
    AgentThinkingEvent,
    FindingDiscoveredEvent,
    FindingValidatedEvent,
)
from itzraven.core import SessionManager
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core import MemoryManager

logger = get_logger()


class TargetInputScreen(ModalScreen[str]):
    """Modal screen for entering target IP/domain"""

    CSS = """
    TargetInputScreen {
        align: center middle;
    }

    #target_dialog {
        width: 60;
        height: auto;
        background: #0a0a0a;
        border: heavy #22c55e;
        padding: 2;
    }

    #target_title {
        width: 100%;
        height: auto;
        text-align: center;
        color: #22c55e;
        text-style: bold;
        margin-bottom: 1;
    }

    #target_description {
        width: 100%;
        height: auto;
        text-align: center;
        color: #a3a3a3;
        margin-bottom: 2;
    }

    #target_input {
        width: 100%;
        margin-bottom: 1;
    }

    #target_buttons {
        width: 100%;
        height: auto;
        align: center middle;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel", priority=True),
    ]

    def __init__(self, mode: str):
        super().__init__()
        self.mode = mode

    def compose(self) -> ComposeResult:
        mode_names = {
            "osint": "OSINT",
            "pentest": "PENTEST",
            "ctf": "CTF",
            "bugbounty": "BUG BOUNTY",
        }
        mode_name = mode_names.get(self.mode, self.mode.upper())

        with Vertical(id="target_dialog"):
            yield Static(f"ENTER TARGET - {mode_name} MODE", id="target_title")
            yield Static("Enter IP address or IP:PORT", id="target_description")
            yield Input(placeholder="e.g., 192.168.1.1 or 10.0.0.1:8080", id="target_input")
            with Horizontal(id="target_buttons"):
                yield Button("Start", id="start_btn", variant="success")
                yield Button("Cancel", id="cancel_btn", variant="error")

    def on_mount(self) -> None:
        """Focus the input when mounted"""
        self.query_one("#target_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "start_btn":
            target_input = self.query_one("#target_input", Input)
            if target_input.value.strip():
                self.dismiss(target_input.value.strip())
        elif event.button.id == "cancel_btn":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission (Enter key)"""
        if event.value.strip():
            self.dismiss(event.value.strip())

    def action_dismiss(self) -> None:
        """Dismiss without selection"""
        self.dismiss(None)


class ModeSelectionScreen(ModalScreen[str]):
    """Modal screen for selecting operation mode"""

    CSS = """
    ModeSelectionScreen {
        align: center middle;
    }

    #mode_dialog {
        width: 50;
        height: auto;
        background: #0a0a0a;
        border: heavy #22c55e;
        padding: 1;
    }

    #mode_title {
        width: 100%;
        height: auto;
        text-align: center;
        color: #22c55e;
        text-style: bold;
        margin-bottom: 1;
    }

    #mode_options {
        width: 100%;
        height: auto;
        background: transparent;
        border: none;
    }

    #mode_options:focus {
        border: none;
    }

    .option-list--option {
        padding: 0 2;
    }

    .option-list--option-highlighted {
        background: #1a1a1a;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel", priority=True),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="mode_dialog"):
            yield Static("SELECT MODE", id="mode_title")
            yield OptionList(
                Option("🟢 Pentest Mode", id="pentest"),
                Option("🟣 Bug Bounty Mode", id="bugbounty"),
                Option("🔵 CTF Mode", id="ctf"),
                Option("🔴 OSINT Mode", id="osint"),
                id="mode_options"
            )

    def on_mount(self) -> None:
        """Focus the option list when mounted"""
        self.query_one("#mode_options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle mode selection"""
        self.dismiss(event.option.id)

    def action_dismiss(self) -> None:
        """Dismiss without selection"""
        self.dismiss(None)


class ModeSplashScreen(Static):
    """Mode-specific splash screen with mode color — exact backup replica"""

    BANNER = (
        " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗\n"
        "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝\n"
        "███████║██████╔╝██║  ███╗██║   ██║███████╗\n"
        "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║\n"
        "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║\n"
        "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
    )

    MODE_COLORS = {
        "osint": "#dc2626",
        "pentest": "#22c55e",
        "ctf": "#3b82f6",
        "bugbounty": "#a855f7",
    }
    MODE_NAMES = {
        "osint": "OSINT",
        "pentest": "PENTEST",
        "ctf": "CTF",
        "bugbounty": "BUG BOUNTY",
    }

    def __init__(self, mode: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.mode = mode
        self._animation_step = 0
        self._animation_timer = None
        self._panel_static: Optional[Static] = None

    def compose(self) -> ComposeResult:
        self._animation_step = 0
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        panel_static = Static(panel, id="mode_splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return
        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        from rich.align import Align
        color = self.MODE_COLORS.get(self.mode, "#22c55e")
        mode_name = self.MODE_NAMES.get(self.mode, "MODE")
        welcome_text = Text("Welcome to ", style=Style(color="white", bold=True))
        welcome_text.append("Itzraven", style=Style(color=color, bold=True))
        welcome_text.append(" - ", style=Style(color="white", bold=True))
        welcome_text.append(f"{mode_name} Mode", style=Style(color=color, bold=True))
        welcome_text.append("!", style=Style(color="white", bold=True))
        content = Group(
            Align.center(Text(self.BANNER.strip("\n"), style=color, justify="center")),
            Align.center(Text(" ")),
            Align.center(welcome_text),
            Align.center(Text(f"v{__import__('itzraven').__version__}", style=Style(color="white", dim=True))),
            Align.center(Text("See Everything. Miss Nothing", style=Style(color="white", dim=True))),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
        )
        return Panel.fit(content, border_style=color, padding=(1, 6))

    def _build_start_line_text(self, phase: int) -> Text:
        mode_name = self.MODE_NAMES.get(self.mode, "MODE")
        full_text = f"Starting {mode_name} Mode"
        text_len = len(full_text)
        shine_pos = phase % (text_len + 8)
        line = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)
            if dist <= 1:
                line.append(char, style=Style(color="bright_white", bold=True))
            elif dist <= 3:
                line.append(char, style=Style(color="white", bold=True))
            elif dist <= 5:
                line.append(char, style=Style(color="#a3a3a3"))
            else:
                line.append(char, style=Style(color="#525252"))
        return line


class ModeIndicator(Static):
    """Display current active mode - Strix style"""

    MODE_COLORS = {
        "osint": "#dc2626",
        "pentest": "#22c55e",
        "ctf": "#3b82f6",
        "bugbounty": "#a855f7",
    }

    MODE_NAMES = {
        "osint": "OSINT",
        "pentest": "PENTEST",
        "ctf": "CTF",
        "bugbounty": "BUG BOUNTY",
    }

    def __init__(self, mode: str = "pentest", *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.current_mode = mode

    def render(self) -> Text:
        color = self.MODE_COLORS.get(self.current_mode, "#22c55e")
        name = self.MODE_NAMES.get(self.current_mode, "PENTEST")

        text = Text()
        text.append("Mode: ", style="#737373")
        text.append(name, style=Style(color=color, bold=True))
        return text

    def set_mode(self, mode: str) -> None:
        self.current_mode = mode
        self.refresh()


class HeaderBar(Horizontal):
    """Top header bar with mode selector, bird emoji, and safe mode indicator"""

    def compose(self) -> ComposeResult:
        yield Button("⚙ Modes", id="mode_button", variant="primary")
        yield Static("", id="header_spacer")  # Spacer to push mode indicator to right
        yield ModeIndicator(id="mode_indicator")
        yield Static("🦅", id="bird_indicator")
        yield Static("🟢 Safe Mode ON", id="safe_mode_indicator")


class SplashScreen(Static):
    """Strix-style splash screen with animated banner — exact backup replica"""

    PRIMARY_GREEN = "#22c55e"
    BANNER = (
        " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗\n"
        "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝\n"
        "███████║██████╔╝██║  ███╗██║   ██║███████╗\n"
        "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║\n"
        "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║\n"
        "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer = None
        self._panel_static: Optional[Static] = None
        self._version_text = ""
        self._set_version()

    def _set_version(self) -> None:
        try:
            from itzraven import __version__
            self._version_text = f"v{__version__}"
        except ImportError:
            self._version_text = ""

    def compose(self) -> ComposeResult:
        self._animation_step = 0
        start_line = self._build_start_line_text(0)
        panel = self._build_panel(start_line)
        panel_static = Static(panel, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return
        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        from rich.align import Align
        content = Group(
            Align.center(Text(self.BANNER.strip("\n"), style=self.PRIMARY_GREEN, justify="center")),
            Align.center(Text(" ")),
            Align.center(self._build_welcome_text()),
            Align.center(self._build_version_text()),
            Align.center(self._build_tagline_text()),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
        )
        return Panel.fit(content, border_style=self.PRIMARY_GREEN, padding=(1, 6))

    def _build_welcome_text(self) -> Text:
        text = Text("Welcome to ", style=Style(color="white", bold=True))
        text.append("Itzraven", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append(" v0.0.3", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append("!", style=Style(color="white", bold=True))
        return text

    def _build_version_text(self) -> Text:
        return Text(self._version_text, style=Style(color="white", dim=True))

    def _build_tagline_text(self) -> Text:
        return Text("See Everything Miss Noting !!!", style=Style(color="white", bold=True))

    def _build_start_line_text(self, phase: int) -> Text:
        full_text = "Starting Itzraven Security Scanner"
        text_len = len(full_text)
        shine_pos = phase % (text_len + 8)
        line = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)
            if dist <= 1:
                line.append(char, style=Style(color="bright_white", bold=True))
            elif dist <= 3:
                line.append(char, style=Style(color="white", bold=True))
            elif dist <= 5:
                line.append(char, style=Style(color="#a3a3a3"))
            else:
                line.append(char, style=Style(color="#525252"))
        return line


class VulnerabilityDetailScreen(ModalScreen[None]):
    """Minimal read-only vulnerability detail modal."""

    CSS = """
    VulnerabilityDetailScreen {
        align: center middle;
    }

    #vuln_detail_dialog {
        width: 90;
        height: 85%;
        background: #0a0a0a;
        border: heavy #22c55e;
        padding: 1 2;
    }

    #vuln_detail_title {
        width: 100%;
        text-align: center;
        color: #22c55e;
        text-style: bold;
        margin-bottom: 1;
    }

    #vuln_detail_content {
        height: 1fr;
        margin-bottom: 1;
    }

    .vuln_detail_line {
        color: #d4d4d4;
        margin-bottom: 1;
    }

    .vuln_detail_severity_critical {
        color: #dc2626;
        text-style: bold;
    }

    .vuln_detail_severity_high {
        color: #ea580c;
        text-style: bold;
    }

    .vuln_detail_severity_medium {
        color: #d97706;
        text-style: bold;
    }

    .vuln_detail_severity_low {
        color: #22c55e;
        text-style: bold;
    }

    .vuln_detail_severity_info {
        color: #3b82f6;
        text-style: bold;
    }

    .vuln_detail_section {
        color: #22c55e;
        text-style: bold;
        margin-top: 1;
        border-bottom: solid #333333;
    }

    .vuln_detail_code {
        color: #a3a3a3;
        background: #0f0f0f;
        padding: 0 1;
    }

    #close_vuln_detail {
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", priority=True),
    ]

    def __init__(self, vulnerability: Dict[str, Any]):
        super().__init__()
        self.vulnerability = vulnerability or {}

    def compose(self) -> ComposeResult:
        title = self._format_value(self.vulnerability.get("title")) or "Unknown finding"
        severity = self._format_value(self.vulnerability.get("severity")) or "unknown"
        category = self._format_value(self.vulnerability.get("category")) or "unknown"
        evidence = self._format_value(self.vulnerability.get("evidence")) or "N/A"
        description = self._format_value(self.vulnerability.get("description")) or "N/A"
        remediation = self._format_value(self.vulnerability.get("remediation"))

        cvss = self._format_value(self.vulnerability.get("cvss_score"))
        cwe = self._format_value(self.vulnerability.get("cwe_id"))
        poc = self._format_value(self.vulnerability.get("proof_of_concept"))
        confidence = self._format_value(self.vulnerability.get("confidence"))

        with Vertical(id="vuln_detail_dialog"):
            yield Static("VULNERABILITY DETAILS", id="vuln_detail_title")
            with VerticalScroll(id="vuln_detail_content"):
                yield Static(f"Title: {title}", classes="vuln_detail_line")
                yield Static(f"Severity: {severity}", classes=f"vuln_detail_severity_{severity.lower()}")
                yield Static(f"Category: {category}", classes="vuln_detail_line")
                if cvss:
                    yield Static(f"CVSS Score: {cvss}", classes="vuln_detail_line")
                if cwe:
                    yield Static(f"CWE ID: {cwe}", classes="vuln_detail_line")
                if confidence:
                    yield Static(f"Confidence: {confidence}", classes="vuln_detail_line")
                yield Static("", classes="vuln_detail_line")
                yield Static("DESCRIPTION", classes="vuln_detail_section")
                yield Static(f"{description}", classes="vuln_detail_line")
                yield Static("", classes="vuln_detail_line")
                yield Static("EVIDENCE", classes="vuln_detail_section")
                yield Static(f"{evidence}", classes="vuln_detail_line")
                if poc:
                    yield Static("", classes="vuln_detail_line")
                    yield Static("PROOF OF CONCEPT", classes="vuln_detail_section")
                    yield Static(f"{poc}", classes="vuln_detail_code")
                if remediation:
                    yield Static("", classes="vuln_detail_line")
                    yield Static("REMEDIATION", classes="vuln_detail_section")
                    yield Static(f"{remediation}", classes="vuln_detail_line")
            yield Button("Close", id="close_vuln_detail", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_vuln_detail":
            self.dismiss(None)

    def action_dismiss(self) -> None:
        self.dismiss(None)

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            return "; ".join(str(item).strip() for item in value if str(item).strip())
        if isinstance(value, dict):
            return "; ".join(f"{k}: {v}" for k, v in value.items())
        return str(value).strip()


class VulnerabilityItem(Static):
    """Clickable vulnerability item - Strix v0.6.0 style with CVSS"""

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#22c55e",
        "info": "#3b82f6",
    }

    def __init__(self, finding: Finding, **kwargs: Any) -> None:
        label = self._create_label(finding)
        super().__init__(label, **kwargs)
        self.finding = finding

    def on_click(self, event: events.Click) -> None:
        if hasattr(self, "finding") and self.finding:
            vulnerability_dict = self.finding.to_dict()
            self.app.push_screen(VulnerabilityDetailScreen(vulnerability_dict))

    def _create_label(self, finding: Finding) -> Text:
        severity = finding.severity.lower()
        color = self.SEVERITY_COLORS.get(severity, "#3b82f6")
        cvss = getattr(finding, "cvss_score", None)
        cwe = getattr(finding, "cwe_id", None)

        label = Text()
        label.append("● ", style=Style(color=color))
        label.append(f"[{severity.upper()}] ", style=Style(color=color, bold=True))
        label.append(f"{finding.title}", style=Style(color="#d4d4d4"))
        if cvss is not None:
            label.append(f"  CVSS:{cvss:.1f}", style=Style(color="#a3a3a3"))
        if cwe:
            label.append(f"  {cwe}", style=Style(color="#737373"))
        return label


class AgentsPanel(Vertical):
    """Agents status panel with specific agents display"""

    def compose(self) -> ComposeResult:
        yield Static("🤖 Agents [4/4]", id="agents_header")
        yield Static("● Subdomain Enum", id="agent_1")
        yield Static("● Port Scanner", id="agent_2")
        yield Static("● Content Discovery", id="agent_3")
        yield Static("● Tech Analysis", id="agent_4")
        yield Button("+ New Agent", id="new_agent_btn", variant="success")
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new_agent_btn":
            self.push_screen(ModeSelectionScreen(), self._handle_new_agent_selection)
    
    def _handle_new_agent_selection(self, mode: str | None) -> None:
        if mode:
            chat = self.query_one("#chat_display", ChatDisplay)
            chat.add_message(f"🔧 New agent selected: {mode}", "#22c55e", "system")


class SystemHealthPanel(Vertical):
    """System health monitoring panel — live via psutil"""

    def compose(self) -> ComposeResult:
        yield Static("💻 System Health", id="health_header")
        yield Static("● CPU: 0%", id="cpu_status")
        yield Static("● MEM: 0%", id="mem_status")
        yield Static("● NET: 0 B/s", id="net_status")

    def on_mount(self) -> None:
        self._prev_net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        self._prev_time = time.monotonic()
        self.set_interval(2.0, self._refresh)

    def _refresh(self) -> None:
        try:
            cpu = psutil.cpu_percent(interval=None)
            self.query_one("#cpu_status", Static).update(f"● CPU: {cpu:.0f}%")
        except Exception:
            pass
        try:
            mem = psutil.virtual_memory().percent
            self.query_one("#mem_status", Static).update(f"● MEM: {mem:.0f}%")
        except Exception:
            pass
        try:
            now = time.monotonic()
            cur = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
            elapsed = now - self._prev_time
            rate = (cur - self._prev_net) / elapsed if elapsed > 0 else 0
            self._prev_net = cur
            self._prev_time = now
            if rate >= 1_048_576:
                label = f"{rate / 1_048_576:.1f} MB/s"
            elif rate >= 1_024:
                label = f"{rate / 1_024:.0f} KB/s"
            else:
                label = f"{rate:.0f} B/s"
            self.query_one("#net_status", Static).update(f"● NET: {label}")
        except Exception:
            pass


class ResourcePanel(Vertical):
    """Resource usage panel — live via CostTracker + uptime + LLM status"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._start = time.monotonic()

    def compose(self) -> ComposeResult:
        yield Static("💎 Resources", id="resources_header")
        yield Static("● Tokens: 0", id="tokens_status")
        yield Static("● Cost: $0.0000", id="cost_status")
        yield Static("● Uptime: 0s", id="uptime_status")
        yield Static("● AI: Off", id="ai_status")
        yield Static("  Model: -", id="model_status")

    def on_mount(self) -> None:
        self.set_interval(2.0, self._refresh)

    def _refresh(self) -> None:
        try:
            tracker = get_cost_tracker()
            total = tracker.total_tokens
            cost = tracker.total_cost
            self.query_one("#tokens_status", Static).update(f"● Tokens: {total:,}")
            self.query_one("#cost_status", Static).update(f"● Cost: ${cost:.4f}")
        except Exception:
            pass
        try:
            elapsed = time.monotonic() - self._start
            h, rem = divmod(int(elapsed), 3600)
            m, s = divmod(rem, 60)
            self.query_one("#uptime_status", Static).update(f"● Uptime: {h}h {m}m {s}s")
        except Exception:
            pass
        try:
            cfg = get_config()
            if cfg.has_ai_enabled:
                client = LLMClient()
                model = client.model
                self.query_one("#ai_status", Static).update("● AI: On")
                self.query_one("#model_status", Static).update(f"  Model: {model}")
            else:
                self.query_one("#ai_status", Static).update("● AI: Off")
                self.query_one("#model_status", Static).update("  Model: -")
        except Exception:
            pass


class VulnerabilitiesPanel(VerticalScroll):
    """Scrollable live vulnerabilities panel — Strix v0.6.0 style

    Features:
    - Severity-grouped display (critical → info)
    - CVSS score per finding
    - Clickable items → detail modal
    - Live event-driven updates
    - Real-time count badge
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._vulnerabilities: list[Finding] = []
        self._header_mounted = False
        self._count_label: Optional[Static] = None

    def compose_header(self) -> None:
        if not self._header_mounted:
            header = Static("🐞 VULNERABILITIES", id="vuln_header")
            self.mount(header)
            self._count_label = Static("  0 findings", id="vuln_count")
            self.mount(self._count_label)
            self._header_mounted = True

    def update_vulnerabilities(self, vulnerabilities: list[Finding]) -> None:
        if self._vulnerabilities == vulnerabilities:
            return
        self._vulnerabilities = list(vulnerabilities)
        self._render_panel()

    def _render_panel(self) -> None:
        self.compose_header()

        for child in list(self.children):
            if isinstance(child, VulnerabilityItem):
                child.remove()

        if self._count_label:
            count = len(self._vulnerabilities)
            color = "#dc2626" if count > 0 else "#d4d4d4"
            self._count_label.update(f"  {count} findings", style=color)

        if not self._vulnerabilities:
            empty = Static("  No vulnerabilities found yet", id="vuln_empty")
            self.mount(empty)
            return

        sorted_vulns = sorted(
            self._vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.get(v.severity.lower(), 9),
        )

        for vuln in sorted_vulns:
            item = VulnerabilityItem(vuln, classes="vuln-item")
            self.mount(item)


class StatsDisplay(Static):
    """Strix-style statistics display panel"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.scan_duration = 0.0
        self.total_findings = 0
        self.agents_completed = 0
        self.agents_total = 0
        self.poc_processed = 0
        self.poc_validated = 0
        self.poc_failed = 0
        self.poc_skipped = 0
        self.poc_processed_ids: set[str] = set()
        self.remediation_processed = 0
        self.remediation_suggested = 0
        self.remediation_skipped = 0

    def render(self) -> Text:
        text = Text()
        muted = "#737373"
        green = "#22c55e"

        text.append("STATISTICS", style=Style(color=green, bold=True))
        text.append("\n")
        text.append("─" * 20, style="#333333")
        text.append("\n")

        # Duration
        text.append("  ⏱ ", style=muted)
        text.append(f"{self.scan_duration:.1f}s", style="#d4d4d4")
        text.append("\n")

        # Agents
        text.append("  🟢 ", style=muted)
        text.append(f"{self.agents_completed}/{self.agents_total} agents", style="#d4d4d4")
        text.append("\n")

        # Findings
        text.append("  🐞 ", style=muted)
        color = "#dc2626" if self.total_findings > 0 else "#d4d4d4"
        text.append(f"{self.total_findings} findings", style=color)
        text.append("\n")

        # PoC Validation
        text.append("  ✓ ", style=muted)
        text.append(f"P:{self.poc_processed} V:{self.poc_validated} F:{self.poc_failed} S:{self.poc_skipped}", style="#d4d4d4")

        return text


class ChatDisplay(Static):
    """Strix-style chat/output display area"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._messages: list[tuple[str, str, str, str]] = []

    def add_message(self, message: str, style: str = "#d4d4d4", msg_type: str = "normal") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._messages.append((timestamp, message, style, msg_type))
        self._update_display()

    def _update_display(self) -> None:
        text = Text()

        for i, (timestamp, message, style, msg_type) in enumerate(self._messages):
            if i > 0:
                text.append("\n")

            if msg_type == "goal":
                text.append("\n")
                text.append("── GOAL ", style=style)
                text.append("─" * 40, style="#333333")
                text.append("\n")
                text.append(message + "\n", style=Style(color="#d4d4d4", bold=True))
                text.append("─" * 50, style="#333333")

            elif msg_type == "section":
                text.append("\n")
                text.append("▔" * 55 + "\n", style="#333333")
                text.append(f"  {message}", style=Style(color=style, bold=True))
                text.append("\n" + "▁" * 55, style="#333333")

            elif msg_type == "system":
                text.append("  ⚡ ", style="#22c55e")
                text.append(message, style=Style(color=style, bold=True))

            else:
                text.append(message, style=style)

        self.update(text)

    def clear_messages(self) -> None:
        self._messages.clear()
        self.update(Text())


class ThinkingPanel(Static):
    """Real-time AI thinking/reasoning display with structured status"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._thoughts: List[Dict[str, str]] = []
        self._current_thought = ""
        self._max_visible = 6
        self._current_action = ""
        self._current_goal = ""
        self._current_reasoning = ""
        self._current_focus = ""
        self._current_next = ""

    def set_thought(self, agent: str, thought: str, thought_type: str = "reasoning", phase: str = "") -> None:
        self._current_thought = thought
        type_icons = {
            "analyzing": "🔍", "planning": "📋", "evaluating": "📊",
            "deciding": "🎯", "searching": "🌐", "reasoning": "🧠",
        }
        icon = type_icons.get(thought_type, "💭")
        entry = {
            "agent": agent, "thought": thought, "type": thought_type,
            "icon": icon, "phase": phase,
        }
        self._thoughts.append(entry)
        if len(self._thoughts) > self._max_visible * 2:
            self._thoughts = self._thoughts[-self._max_visible:]
        self._render()

    def update_state(self, *, action: str = "", goal: str = "", reasoning: str = "", focus: str = "", next_step: str = "") -> None:
        if action:
            self._current_action = action
        if goal:
            self._current_goal = goal
        if reasoning:
            self._current_reasoning = reasoning
        if focus:
            self._current_focus = focus
        if next_step:
            self._current_next = next_step
        self._render()

    def clear(self) -> None:
        self._thoughts.clear()
        self._current_thought = ""
        self._current_action = ""
        self._current_goal = ""
        self._current_reasoning = ""
        self._current_focus = ""
        self._current_next = ""
        self._render()

    def _render(self) -> None:
        text = Text()
        text.append("\n")
        text.append("THINKING", style=Style(color="#a855f7", bold=True))
        text.append("\n" + "─" * 50 + "\n", style="#333333")

        if self._current_action:
            text.append(f"⚡ {self._current_action}\n", style=Style(color="#f59e0b", bold=True))

        if self._current_goal:
            text.append(f"🎯 Goal: {self._current_goal}\n", style=Style(color="#22c55e"))

        if self._current_reasoning:
            text.append(f"💡 Reasoning: {self._current_reasoning}\n", style=Style(color="#c084fc"))

        if self._current_focus:
            text.append(f"🔍 Focus: {self._current_focus}\n", style=Style(color="#3b82f6"))

        if self._current_next:
            text.append(f"⏩ Next: {self._current_next}\n", style=Style(color="#a1a1aa"))

        if self._current_thought:
            text.append(f"🧠 {self._current_thought[:80]}\n", style=Style(color="#c084fc", italic=True))

        text.append("─" * 50, style="#333333")
        self.update(text)


class ItzravenStrixApp(App):
    """Strix-inspired Itzraven TUI Application"""

    CSS_PATH = "strix_styles.tcss"

    selected_agent_id: reactive[str | None] = reactive(default=None)
    show_splash: reactive[bool] = reactive(default=True)
    current_mode: reactive[str] = reactive(default="pentest")

    BINDINGS = [
        Binding("f1", "toggle_help", "Help", priority=True),
        Binding("f2", "show_mode_selector", "Modes", priority=True),
        Binding("f5", "toggle_sidebar", "Sidebar", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "quit", "Quit", priority=True),
    ]

    MODE_COLORS = {
        "osint": "#dc2626",      # RED
        "pentest": "#22c55e",    # GREEN
        "ctf": "#3b82f6",        # BLUE
        "bugbounty": "#a855f7",  # PURPLE
    }

    MODE_THEMES = {
        "osint": {"accent": "#dc2626", "bg": "#1a0a0a", "border": "#dc2626", "class": "theme-osint"},
        "pentest": {"accent": "#22c55e", "bg": "#0a1a0a", "border": "#22c55e", "class": "theme-pentest"},
        "ctf": {"accent": "#3b82f6", "bg": "#0a0a1a", "border": "#3b82f6", "class": "theme-ctf"},
        "bugbounty": {"accent": "#a855f7", "bg": "#0a001a", "border": "#a855f7", "class": "theme-bugbounty"},
    }

    def __init__(self, target: Optional[str] = None):
        super().__init__()
        self.target = target
        self.orchestrator: Optional[AgentOrchestrator] = None
        self.scan_result: Optional[ScanResult] = None
        self.scanning = False
        self.agent_nodes: dict[str, TreeNode] = {}
        self._scan_start_time: Optional[float] = None

        # Event Bus and Memory System (optional)
        self.event_bus: Optional[EventBus] = None
        self.memory_manager: Optional['MemoryManager'] = None
        self._event_subscriptions_setup = False

        # Mode-specific background tasks
        self.mode_tasks: dict[str, asyncio.Task] = {}
        self.mode_results: dict[str, ScanResult] = {}

        # Track visited modes (for splash screen)
        self.visited_modes: set[str] = set()

        # Per-mode targets (each mode gets its own target)
        self.mode_targets: dict[str, str] = {}

        # Store per-mode UI state
        self.mode_sessions: dict[str, dict] = {
            "osint": {"messages": [], "vulnerabilities": [], "stats": None},
            "pentest": {"messages": [], "vulnerabilities": [], "stats": None},
            "ctf": {"messages": [], "vulnerabilities": [], "stats": None},
            "bugbounty": {"messages": [], "vulnerabilities": [], "stats": None},
        }

        # Flag to show mode splash
        self.showing_mode_splash = False

        # Flag to track if we need initial mode selection
        self.needs_initial_setup = target is None

    def compose(self) -> ComposeResult:
        """Compose the UI — splash + hidden main UI (backup pattern)."""
        yield SplashScreen(id="splash_screen")
        yield self._build_main_ui()

    def _build_main_ui(self) -> Vertical:
        header_bar = HeaderBar(id="header_bar")
        agents_panel = AgentsPanel(id="agents_panel")
        vuln_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")
        health_panel = SystemHealthPanel(id="health_panel")
        resource_panel = ResourcePanel(id="resource_panel")
        stats_display = StatsDisplay(id="stats_display")
        stats_scroll = VerticalScroll(stats_display, id="stats_scroll")
        sidebar = Vertical(agents_panel, health_panel, resource_panel, vuln_panel, stats_scroll, id="sidebar", classes="-hidden")

        chat_display = ChatDisplay(id="chat_display")
        chat_history = VerticalScroll(chat_display, id="chat_history")
        chat_history.can_focus = True
        thinking_panel = ThinkingPanel(id="thinking_panel")
        input_field = Input(placeholder="", id="command_input")
        input_field.value = "itzraven@cockpit: "
        chat_input_container = Horizontal(input_field, id="chat_input_container")
        chat_area = Vertical(chat_history, thinking_panel, chat_input_container, id="chat_area_container", classes="-full-width")

        content_container = Horizontal(chat_area, sidebar, id="content_container")

        status_text = Static("F1:Help F2:Modes F5:Sidebar Ctrl+Q:Quit", id="status_bar_text")
        status_bar = Horizontal(status_text, id="status_bar")

        main_ui = Vertical(header_bar, content_container, status_bar, id="main_container")
        main_ui.display = False
        return main_ui

    def watch_show_splash(self, show_splash: bool) -> None:
        """Toggle between splash and main UI — exact backup logic."""
        if not self.is_mounted:
            return
        try:
            splash = self.query_one("#splash_screen")
            if not show_splash:
                splash.remove()
                main_ui = self.query_one("#main_container")
                main_ui.display = True
                self.call_after_refresh(self._initialize_scan)
        except Exception:
            pass

    def watch_current_mode(self, mode: str) -> None:
        """Watch for mode changes and update UI colors"""
        if not self.is_mounted:
            return

        try:
            # Check if UI is built
            try:
                mode_indicator = self.query_one("#mode_indicator", ModeIndicator)
            except:
                # UI not built yet, skip
                return

            mode_indicator.set_mode(mode)

            # Update terminal background color based on mode
            color = self.MODE_COLORS.get(mode, "#22c55e")

            # Update chat border color to match mode
            try:
                chat_history = self.query_one("#chat_history")
                chat_history.styles.border = ("round", color)
            except:
                # Chat not built yet
                pass

            # Log mode change
            try:
                chat = self.query_one("#chat_display", ChatDisplay)
                mode_names = {
                    "osint": "OSINT",
                    "pentest": "PENTEST",
                    "ctf": "CTF",
                    "bugbounty": "BUG BOUNTY",
                }
                chat.add_message(f"Switched to {mode_names.get(mode, mode.upper())} mode", color, "system")
            except:
                # Chat not ready yet
                pass

        except Exception as e:
            logger.error(f"Error updating mode: {e}")

    def _apply_mode_theme(self, mode: str) -> None:
        theme = self.MODE_THEMES.get(mode, self.MODE_THEMES["pentest"])
        if not self.is_mounted:
            return
        try:
            self.screen.styles.background = theme["bg"]
        except Exception:
            pass

    def on_mount(self) -> None:
        """Called when app is mounted"""
        self.title = "itzraven"

        # Initialize Event Bus
        self._initialize_event_bus()

        # Splash 3 sec animation then auto-show mode selector
        if self.needs_initial_setup:
            self.set_timer(3.0, self._show_initial_mode_selector)
        else:
            self.set_timer(1.5, self._hide_splash_screen)

    def _initialize_event_bus(self) -> None:
        """Initialize Event Bus and setup event subscriptions"""
        try:
            # Create Event Bus
            self.event_bus = EventBus()
            asyncio.create_task(self.event_bus.start())

            # Initialize Memory Manager if available
            if MEMORY_SYSTEM_AVAILABLE:
                try:
                    from itzraven.core import MemoryManager
                    self.memory_manager = MemoryManager(
                        neo4j_uri="bolt://localhost:7687",
                        neo4j_user="neo4j",
                        neo4j_password="itzraven_password_2026",
                        qdrant_host="localhost",
                        qdrant_port=6333,
                        redis_url="redis://localhost:6379/0",
                        event_bus=self.event_bus,
                    )
                    asyncio.create_task(self.memory_manager.initialize())
                    logger.info("Memory System initialized for UI")
                except Exception as e:
                    logger.warning(f"Memory System not available: {e}")
                    self.memory_manager = None

            # Setup event subscriptions
            self._setup_event_subscriptions()

            logger.info("Event Bus initialized for UI")
        except Exception as e:
            logger.error(f"Failed to initialize Event Bus: {e}")
            self.event_bus = None

    def _setup_event_subscriptions(self) -> None:
        """Setup event subscriptions for real-time UI updates"""
        if not self.event_bus or self._event_subscriptions_setup:
            return

        try:
            # Subscribe to scan events
            @self.event_bus.subscribe("scan.started")
            async def on_scan_started(event: ScanStartedEvent):
                self._handle_scan_started(event)

            @self.event_bus.subscribe("scan.completed")
            async def on_scan_completed(event: ScanCompletedEvent):
                self._handle_scan_completed(event)

            # Subscribe to agent events
            @self.event_bus.subscribe("agent.started")
            async def on_agent_started(event: AgentStartedEvent):
                self._handle_agent_started(event)

            @self.event_bus.subscribe("agent.completed")
            async def on_agent_completed(event: AgentCompletedEvent):
                self._handle_agent_completed(event)

            @self.event_bus.subscribe("agent.progress")
            async def on_agent_progress(event: AgentProgressEvent):
                self._handle_agent_progress(event)

            @self.event_bus.subscribe("agent.thinking")
            async def on_agent_thinking(event: AgentThinkingEvent):
                self._handle_agent_thinking(event)

            # Subscribe to finding events
            @self.event_bus.subscribe("finding.discovered")
            async def on_finding_discovered(event: FindingDiscoveredEvent):
                self._handle_finding_discovered(event)

            @self.event_bus.subscribe("finding.validated")
            async def on_finding_validated(event: FindingValidatedEvent):
                self._handle_finding_validated(event)

            self._event_subscriptions_setup = True
            logger.info("Event subscriptions setup complete")
        except Exception as e:
            logger.error(f"Failed to setup event subscriptions: {e}")

    def _handle_scan_started(self, event: ScanStartedEvent) -> None:
        """Handle scan started event"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(event.mode, "#22c55e")
            chat.add_message(f"  🟢 Scan started: {event.target}", color, "system")
        except Exception as e:
            logger.debug(f"Error handling scan started: {e}")

    def _handle_scan_completed(self, event: ScanCompletedEvent) -> None:
        """Handle scan completed event"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(event.mode, "#22c55e")
            status = "✅" if event.success else "❌"
            chat.add_message(
                f"{status} Scan completed: {event.total_findings} findings in {event.duration:.1f}s",
                color,
                "system"
            )
        except Exception as e:
            logger.debug(f"Error handling scan completed: {e}")

    def _handle_agent_started(self, event: AgentStartedEvent) -> None:
        """Handle agent started event"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(event.mode, "#22c55e")
            chat.add_message(f"  ⚪ Agent started: {event.agent_name}", color, "system")

            # Update agents tree
            self._update_agent_status_in_tree(event.agent_name, "running")
        except Exception as e:
            logger.debug(f"Error handling agent started: {e}")

    def _handle_agent_completed(self, event: AgentCompletedEvent) -> None:
        """Handle agent completed event"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(self.current_mode, "#22c55e")
            chat.add_message(
                f"  🟢 Agent completed: {event.agent_name} ({event.findings_count} findings)",
                color,
                "system"
            )

            # Update agents tree
            self._update_agent_status_in_tree(event.agent_name, "completed")

            # Update stats
            stats = self.query_one("#stats_display", StatsDisplay)
            stats.agents_completed += 1
            stats.total_findings += event.findings_count
            stats.refresh()
        except Exception as e:
            logger.debug(f"Error handling agent completed: {e}")

    def _handle_agent_thinking(self, event: AgentThinkingEvent) -> None:
        """Handle agent thinking event - updates the real-time thinking panel"""
        try:
            panel = self.query_one("#thinking_panel", ThinkingPanel)
            panel.set_thought(
                agent=event.agent_name,
                thought=event.thought,
                thought_type=event.thought_type,
                phase=event.phase,
            )
        except Exception:
            pass

    def _handle_agent_progress(self, event: AgentProgressEvent) -> None:
        try:
            msg = event.message or ""
            pct = int(event.progress) if event.progress else 0
            bar = "█" * (pct // 10) + "▒" * (10 - (pct // 10))

            # Only show milestone messages in chat (skip verbose iteration details)
            important_prefixes = ["🔍 Phase", "📌 Discovered", "🔬 Phase", "🧠 Phase", "✅ Scan", "🔴 CRITICAL", "🟡 Finding"]
            show_in_chat = any(msg.startswith(p) for p in important_prefixes) or not msg

            if show_in_chat:
                chat = self.query_one("#chat_display", ChatDisplay)
                chat.add_message(f"  {bar} {msg}", "#86efac", "system")

            phase_name = event.current_phase or "thinking"
            key = f"{event.agent_name}_{phase_name}"
            if key in self.agent_nodes:
                node = self.agent_nodes[key]
                node.set_label(f"⏳ {bar} {msg[:50]} ({pct}%)")
        except Exception as e:
            logger.debug(f"Error handling agent progress: {e}")

    def _update_agent_phase_progress(self, agent_name: str, phase: str, pct: int) -> None:
        try:
            key = f"{agent_name}_{phase}"
            if key in self.agent_nodes:
                node = self.agent_nodes[key]
                bar = "█" * (pct // 10) + "▒" * (10 - pct // 10)
                node.set_label(f"⏳ {bar} {phase} ({pct}%)")
        except Exception:
            pass

    def _handle_finding_discovered(self, event: FindingDiscoveredEvent) -> None:
        """Handle finding discovered event"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            stats = self.query_one("#stats_display", StatsDisplay)

            # Skip recon agent's individual findings - shown as clean summary in _run_mode_scan
            if "recon" in event.agent_name.lower():
                return

            severity_color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#d97706",
                "low": "#22c55e",
                "info": "#3b82f6",
            }.get(event.severity.lower(), "white")

            chat.add_message(
                f"  🐞 [{event.severity.upper()}] {event.title}",
                severity_color
            )

            # Best-effort live skipped tracking for findings without executable PoC.
            poc = (event.proof_of_concept or "").strip()
            if not poc:
                stats.poc_processed += 1
                stats.poc_skipped += 1
                stats.refresh()
            else:
                try:
                    compile(poc, "<poc>", "exec")
                except SyntaxError:
                    stats.poc_processed += 1
                    stats.poc_skipped += 1
                    stats.refresh()

            # Update vulnerabilities panel
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)

            # Create Finding object from event
            finding = Finding(
                title=event.title,
                description=event.description,
                severity=event.severity,
                category=event.category,
                evidence=event.evidence or "",
                proof_of_concept=event.proof_of_concept,
                remediation=event.remediation,
                confidence=event.confidence,
                agent_name=event.agent_name,
            )

            # Add to vulnerabilities panel
            current_vulns = list(vuln_panel._vulnerabilities)
            current_vulns.append(finding)
            vuln_panel.update_vulnerabilities(current_vulns)
            vuln_panel.remove_class("hidden")

        except Exception as e:
            logger.debug(f"Error handling finding discovered: {e}")

    def _handle_finding_validated(self, event: FindingValidatedEvent) -> None:
        """Handle finding validated event for live PoC counters."""
        try:
            stats = self.query_one("#stats_display", StatsDisplay)

            if event.finding_id in stats.poc_processed_ids:
                return
            stats.poc_processed_ids.add(event.finding_id)

            stats.poc_processed += 1
            if event.validation_result:
                stats.poc_validated += 1
            else:
                stats.poc_failed += 1
            stats.refresh()
        except Exception as e:
            logger.debug(f"Error handling finding validated: {e}")

    def _update_agent_status_in_tree(self, agent_name: str, status: str) -> None:
        """Update agent status in the tree — Strix-style Unicode indicators."""
        try:
            if agent_name in self.agent_nodes:
                node = self.agent_nodes[agent_name]
                indicators = {"running": "●", "completed": "◆", "failed": "◇"}
                icon = indicators.get(status, "○")
                current = str(node.label)
                name_part = current.split(" ", 1)[-1] if " " in current else agent_name
                node.set_label(f"{icon} {name_part}")
        except Exception as e:
            logger.debug(f"Error updating agent status: {e}")

    def _show_initial_mode_selector(self) -> None:
        """Show mode selector on initial startup - auto after splash"""
        try:
            splash = self.query_one("#splash_screen")
            splash.remove()
        except Exception:
            pass
        self.push_screen(ModeSelectionScreen(), self._handle_mode_selection_from_splash)

    def _handle_mode_selection_from_splash(self, mode: str | None) -> None:
        """Handle mode selection from initial splash"""
        if not mode:
            self.exit()
            return

        self.current_mode = mode
        self.visited_modes.add(mode)
        self.needs_initial_setup = False

        self._apply_mode_theme(mode)

        try:
            main_container = self.query_one("#main_container")
            for child in list(main_container.children):
                child.remove()
            main_container.display = True
        except Exception:
            main_container = Vertical(id="main_container")
            self.mount(main_container)

        mode_splash = ModeSplashScreen(mode, id="mode_splash_screen")
        main_container.mount(mode_splash)
        self.call_after_refresh(lambda: self.set_timer(2.0, lambda: self._hide_mode_splash_initial(mode)))

    def _handle_initial_mode_selection(self, mode: str | None) -> None:
        """Handle initial mode selection (before target is set)"""
        if not mode:
            self.exit()
            return

        self.current_mode = mode
        self.visited_modes.add(mode)
        self.needs_initial_setup = False

        self._show_mode_splash_for_initial_setup(self.current_mode)

    def _show_mode_splash_for_initial_setup(self, mode: str) -> None:
        """Show mode splash screen for initial setup"""
        try:
            try:
                main_container = self.query_one("#main_container")
                for child in list(main_container.children):
                    child.remove()
                main_container.display = True
            except Exception:
                main_container = Vertical(id="main_container")
                self.mount(main_container)
            mode_splash = ModeSplashScreen(mode, id="mode_splash_screen")
            main_container.mount(mode_splash)
            self.call_after_refresh(lambda: self.set_timer(1.5, lambda: self._hide_mode_splash_initial(mode)))
        except Exception as e:
            logger.error(f"Error showing initial mode splash: {e}")

    def _hide_mode_splash_initial(self, mode: str) -> None:
        """Hide initial mode splash and build UI"""
        try:
            splash = self.query_one("#mode_splash_screen")
            splash.remove()

            self._apply_mode_theme(mode)
            self._build_mode_ui()

            # Check if this mode already has a target
            if mode in self.mode_targets:
                self.call_after_refresh(lambda: self._initialize_mode_scan(mode))
            else:
                self.call_after_refresh(lambda: self._show_target_prompt(mode))

        except Exception as e:
            logger.error(f"Error hiding initial mode splash: {e}")

    def _show_target_prompt(self, mode: str) -> None:
        """Show prompt asking user to enter target"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            chat.clear_messages()
            try:
                thinking = self.query_one("#thinking_panel", ThinkingPanel)
                thinking.clear()
            except Exception:
                pass
            color = self.MODE_COLORS.get(mode, "#22c55e")

            mode_names = {
                "osint": "OSINT", "pentest": "PENTEST",
                "ctf": "CTF", "bugbounty": "BUG BOUNTY",
            }
            mode_name = mode_names.get(mode, mode.upper())

            chat.add_message(f"Itzraven {mode_name} Mode Initialized", color, "system")
            chat.add_message(f"Enter target in the input field below", color, "system")
            chat.add_message(f"Format: domain, IP, or IP:PORT", "#a3a3a3")

            input_field = self.query_one("#command_input", Input)
            input_field.placeholder = "Enter target and press Enter..."
            input_field.focus()

        except Exception as e:
            logger.error(f"Error showing target prompt: {e}")

    def _hide_splash_screen(self) -> None:
        """Hide splash and show main UI (with target already set)"""
        self.show_splash = False
        self.call_after_refresh(self._initialize_scan)

    def _initialize_scan(self) -> None:
        """Initialize and start the scan"""
        try:
            # Mark pentest as visited (default mode)
            self.visited_modes.add("pentest")

            chat = self.query_one("#chat_display", ChatDisplay)

            # System initialization messages
            chat.add_message("Itzraven Security Scanner Initialized", "#22c55e", "system")

            # Display GOAL in Strix style
            chat.add_message(f"Perform comprehensive security scan on: {self.target}", "#22c55e", "goal")

            # Section header for scan start
            chat.add_message("SCAN INITIALIZATION", "#22c55e", "section")
            chat.add_message("⚡ Loading security agents...", "#3b82f6")

            # Start scan for default mode (pentest)
            asyncio.create_task(self._run_mode_scan(self.current_mode))
        except Exception as e:
            logger.error(f"Failed to initialize scan: {e}")

    def _initialize_mode_scan(self, mode: str) -> None:
        """Initialize scan for a newly visited mode"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(mode, "#22c55e")

            # System initialization messages
            mode_names = {
                "osint": "OSINT",
                "pentest": "PENTEST",
                "ctf": "CTF",
                "bugbounty": "BUG BOUNTY",
            }
            mode_name = mode_names.get(mode, mode.upper())

            chat.add_message(f"{mode_name} Mode Initialized", color, "system")

            # Display GOAL
            mode_target = self.mode_targets.get(mode, self.target or "?")
            chat.add_message(f"Execute {mode_name} operations on: {mode_target}", color, "goal")

            # Section header
            chat.add_message("SCAN INITIALIZATION", color, "section")
            chat.add_message("⚡ Loading security agents...", "#3b82f6")

            # Start scan for this mode if not already running
            if mode not in self.mode_tasks or self.mode_tasks[mode].done():
                asyncio.create_task(self._run_mode_scan(mode))

        except Exception as e:
            logger.error(f"Failed to initialize mode scan: {e}")

    def action_toggle_help(self) -> None:
        """Show help dialog"""
        # Push the Strix‑style help screen
        from itzraven.ui.strix_style.help_screen import HelpScreen
        self.push_screen(HelpScreen())

    def action_show_mode_selector(self) -> None:
        """Show mode selection dialog"""
        self.push_screen(ModeSelectionScreen(), self._handle_mode_selection)

    def action_toggle_sidebar(self) -> None:
        try:
            sidebar = self.query_one("#sidebar")
            sidebar.toggle_class("-hidden")
            chat_area = self.query_one("#chat_area_container")
            chat_area.toggle_class("-full-width")
        except Exception:
            pass

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        """Handle confirmation to stop an agent — cancels via orchestrator."""
        logger.info(f"Stop agent requested: {agent_id}")
        if self.orchestrator:
            self.orchestrator.cancel_agent(agent_id)
        else:
            logger.warning("No orchestrator available to cancel agent")


    def _handle_mode_selection(self, mode: str | None) -> None:
        """Handle mode selection from dialog"""
        if not mode or mode == self.current_mode:
            return

        old_mode = self.current_mode

        self._save_current_session()
        self._apply_mode_theme(mode)
        self.current_mode = mode

        if mode not in self.visited_modes:
            self.visited_modes.add(mode)
            self.showing_mode_splash = True
            self.set_timer(0.1, lambda: self._show_mode_splash(mode))
        else:
            self.set_timer(0.1, lambda: self._restore_mode_session(mode))
            try:
                self.set_timer(0.2, lambda: self._notify_mode_restored(mode))
            except:
                pass

        if old_mode in self.visited_modes:
            try:
                self.set_timer(0.3, lambda: self._notify_background_continue(old_mode))
            except:
                pass

    def _notify_mode_restored(self, mode: str) -> None:
        """Notify that mode was restored"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(mode, "#22c55e")
            chat.add_message(
                f"Restored {mode.upper()} session",
                color,
                "system"
            )
        except:
            pass

    def _notify_background_continue(self, old_mode: str) -> None:
        """Notify that old mode continues in background"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            chat.add_message(
                f"{old_mode.upper()} continues in background",
                "#d97706",
                "system"
            )
        except:
            pass

    def _show_mode_splash(self, mode: str) -> None:
        """Show mode-specific splash screen"""
        try:
            main_container = self.query_one("#main_container")
            for child in list(main_container.children):
                child.remove()

            mode_splash = ModeSplashScreen(mode, id="mode_splash_screen")
            main_container.mount(mode_splash)

            self.set_timer(1.5, lambda: self._hide_mode_splash(mode))

        except Exception as e:
            logger.error(f"Error showing mode splash: {e}")

    def _hide_mode_splash(self, mode: str) -> None:
        """Hide mode splash and build UI for the mode"""
        try:
            splash = self.query_one("#mode_splash_screen")
            splash.remove()

            self.current_mode = mode
            self.showing_mode_splash = False
            self._apply_mode_theme(mode)
            self._build_mode_ui()

            if mode in self.mode_targets:
                self.call_after_refresh(lambda: self._initialize_mode_scan(mode))
            else:
                self.call_after_refresh(lambda: self._show_target_prompt(mode))

        except Exception as e:
            logger.error(f"Error hiding mode splash: {e}")

    def _save_current_session(self) -> None:
        """Save current mode's session state"""
        try:
            mode = self.current_mode
            chat = self.query_one("#chat_display", ChatDisplay)
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
            stats = self.query_one("#stats_display", StatsDisplay)

            # Save session data (including mode-specific target)
            mode_target = self.mode_targets.get(mode, "")
            self.mode_sessions[mode] = {
                "messages": list(chat._messages),
                "vulnerabilities": list(vuln_panel._vulnerabilities),
                "stats": {
                    "scan_duration": stats.scan_duration,
                    "total_findings": stats.total_findings,
                    "agents_completed": stats.agents_completed,
                    "agents_total": stats.agents_total,
                    "poc_processed": stats.poc_processed,
                    "poc_validated": stats.poc_validated,
                    "poc_failed": stats.poc_failed,
                    "poc_skipped": stats.poc_skipped,
                    "poc_processed_ids": list(stats.poc_processed_ids),
                },
                "target": mode_target,
            }

        except Exception as e:
            logger.error(f"Error saving session: {e}")

    def _restore_mode_session(self, mode: str) -> None:
        """Restore a mode's session state"""
        try:
            session = self.mode_sessions.get(mode, {})

            # Restore mode-specific target
            if "target" in session and session["target"]:
                self.mode_targets[mode] = session["target"]

            chat = self.query_one("#chat_display", ChatDisplay)
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
            stats = self.query_one("#stats_display", StatsDisplay)

            # Restore messages
            if "messages" in session:
                chat._messages = list(session["messages"])
                chat._update_display()

            # Restore vulnerabilities
            if "vulnerabilities" in session and session["vulnerabilities"]:
                vuln_panel.update_vulnerabilities(session["vulnerabilities"])
                vuln_panel.remove_class("hidden")

            # Restore stats
            if "stats" in session and session["stats"]:
                stats.scan_duration = session["stats"]["scan_duration"]
                stats.total_findings = session["stats"]["total_findings"]
                stats.agents_completed = session["stats"]["agents_completed"]
                stats.agents_total = session["stats"]["agents_total"]
                stats.poc_processed = session["stats"].get("poc_processed", 0)
                stats.poc_validated = session["stats"].get("poc_validated", 0)
                stats.poc_failed = session["stats"].get("poc_failed", 0)
                stats.poc_skipped = session["stats"].get("poc_skipped", 0)
                stats.poc_processed_ids = set(session["stats"].get("poc_processed_ids", []))
                stats.refresh()

        except Exception as e:
            logger.error(f"Error restoring session: {e}")

    def _build_mode_ui(self) -> None:
        """Build the main UI for current mode"""
        try:
            main_container = self.query_one("#main_container")

            header_bar = HeaderBar(id="header_bar")
            main_container.mount(header_bar)

            content_container = Horizontal(id="content_container")
            main_container.mount(content_container)

            chat_area_container = Vertical(id="chat_area_container")
            chat_display = ChatDisplay(id="chat_display")
            chat_history = VerticalScroll(chat_display, id="chat_history")
            chat_history.can_focus = True

            input_field = Input(placeholder="Type a command or message...", id="command_input")

            agents_tree = Tree("🤖 Agents", id="agents_tree")
            agents_tree.root.expand()
            agents_tree.show_root = True
            agents_tree.show_guide = True
            agents_tree.guide_depth = 4
            agents_tree.guide_style = "dashed"

            stats_display = StatsDisplay(id="stats_display")
            stats_scroll = VerticalScroll(stats_display, id="stats_scroll")

            vulnerabilities_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")
            health_panel = SystemHealthPanel(id="health_panel")
            resource_panel = ResourcePanel(id="resource_panel")

            sidebar = Vertical(agents_tree, health_panel, resource_panel, vulnerabilities_panel, stats_scroll, id="sidebar")

            content_container.mount(chat_area_container)
            content_container.mount(sidebar)

            chat_area_container.mount(chat_history)
            chat_area_container.mount(input_field)

            color = self.MODE_COLORS.get(self.current_mode, "#22c55e")
            chat_history.styles.border = ("round", color)
            self._apply_mode_theme(self.current_mode)

        except Exception as e:
            logger.error(f"Error building mode UI: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "mode_button":
            self.action_show_mode_selector()

    async def _run_mode_scan(self, mode: str) -> None:
        """Run scan for a specific mode in background - sequential with thinking phases"""
        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            color = self.MODE_COLORS.get(mode, "#22c55e")

            mode_names = {
                "osint": "OSINT",
                "pentest": "PENTEST",
                "ctf": "CTF",
                "bugbounty": "BUG BOUNTY",
            }
            mode_name = mode_names.get(mode, mode.upper())

            mode_target = self.mode_targets.get(mode, self.target or "")
            chat.add_message(f"Starting {mode_name} scan on {mode_target}", color, "system")
            chat.add_message(f"  🧠 Analyzing target...", "#a855f7", "system")

            scan_start = time.time()

            # Create mode-specific orchestrator with event bus
            from itzraven.cli import _create_mode_orchestrator
            orchestrator = _create_mode_orchestrator(
                target=mode_target,
                mode=mode,
                scan_depth="deep",
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
            )
            orchestrator.load_agents()
            self.orchestrator = orchestrator

            # Update agents tree - add agents ONE BY ONE as they execute
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.clear()
            self.agent_nodes.clear()

            mode_icons = {"osint": "🔴", "pentest": "🟢", "ctf": "🔵", "bugbounty": "🟣"}
            root_label = f"{mode_icons.get(mode, '🤖')} {mode_name} Agents"
            mode_root = agents_tree.root.add(root_label, expand=True)

            # Agent category lookup (for AI-based filtering)
            agent_categories = {
                "recon": "recon", "plan": "plan",
                "sqlinjection": "web", "xss": "web", "ssrf": "web",
                "commandinjection": "web", "authentication": "web", "idor": "web",
                "strixpentest": "web", "medusa": "web",
                "pocvalidator": "post", "remediation": "post",
                "websecurity": "web", "networksecurity": "network",
                "cloudsecurity": "cloud", "apisecurity": "api",
                "identityaccess": "identity", "codeanalysis": "code", "reconosint": "recon",
            }
            plan_agent = None
            other_agents = []
            for agent in orchestrator.agents:
                if "plan" in agent.name.lower():
                    plan_agent = agent
                else:
                    other_agents.append(agent)
            ordered_agents = ([plan_agent] if plan_agent else []) + other_agents

            # AI plan categories (updated after PlanAgent runs)
            ai_plan_categories = []

            # Show Testing Approach + run PlanAgent first
            chat.add_message(f"  ── Testing Approach ──", "#a855f7", "section")

            # Initialize thinking panel reference
            try:
                thinking_panel = self.query_one("#thinking_panel", ThinkingPanel)
            except Exception:
                thinking_panel = None

            # Shared data flowing between agents
            shared_endpoints: List[str] = []
            shared_technologies: List[str] = []

            for i, agent in enumerate(ordered_agents):
                agent.context = {
                    "scan_id": orchestrator.scan_id,
                    "target": mode_target,
                    "mode": mode,
                    "shared_endpoints": shared_endpoints,
                    "shared_technologies": shared_technologies,
                }

                # Show shared data from previous agents
                if i > 0 and (shared_endpoints or shared_technologies):
                    prev_agent = ordered_agents[i-1].name
                    comm_parts = []
                    if shared_technologies:
                        comm_parts.append(f"🖥️ {len(shared_technologies)} technologies")
                    if shared_endpoints:
                        comm_parts.append(f"🌐 {len(shared_endpoints)} endpoints")
                    chat.add_message(f"  🔄 ← {prev_agent} passed: {', '.join(comm_parts)}", "#f59e0b", "system")
                    if thinking_panel:
                        thinking_panel.update_state(
                            action=f"⬆️ RECEIVED DATA FROM {prev_agent.upper()}",
                            goal=f"Using {len(shared_endpoints)} discovered endpoints + {len(shared_technologies)} technologies",
                            reasoning="Cross-agent intelligence sharing",
                            focus=f"Testing discovered attack surface",
                            next_step="Running agent with shared context"
                        )

                # Add agent node to tree with thinking state
                agent_label = f"⏳ {agent.name}"
                agent_node = mode_root.add(agent_label, expand=True)
                self.agent_nodes[agent.name] = agent_node

                is_plan_agent = "plan" in agent.name.lower()
                is_recon_agent = "recon" in agent.name.lower() or "discover" in agent.name.lower()

                # Update thinking panel with real-time status
                if is_plan_agent:
                    chat.add_message(f"  🧠 AI Planning approach for {mode_target}...", "#a855f7", "system")
                    if thinking_panel:
                        thinking_panel.update_state(
                            action="AI PLANNING",
                            goal=f"Analyze {mode_target} and select optimal test strategy",
                            reasoning="Evaluating target type, technologies, and attack surface",
                            focus="Category selection: web, network, api, recon, cloud, code, identity",
                            next_step="Executing selected agents based on AI plan"
                        )
                    thinking_steps = ["Analyzing target", "Selecting test categories", "Preparing strategy"]
                else:
                    chat.add_message(f"  🧠 Spawning {agent.name}...", "#a855f7", "system")
                    if thinking_panel:
                        thinking_panel.update_state(
                            action=agent.name.upper(),
                            goal=f"Running {agent.name} against {mode_target}",
                            reasoning=f"Executing {agent.name} methodology",
                            focus=f"Agent: {agent.name}",
                            next_step="Collecting results and findings"
                        )
                    thinking_steps = ["Planning strategy", "Loading skills", "Preparing payloads"]

                # Show thinking sub-steps
                for step in thinking_steps:
                    step_node = agent_node.add(f"⏳ {step}")
                    self.agent_nodes[f"{agent.name}_{step}"] = step_node
                    if thinking_panel:
                        thinking_panel.update_state(
                            action=f"{agent.name.upper()} - {step.upper()}",
                            focus=step
                        )
                    await asyncio.sleep(0.2)
                    step_node.set_label(f"✅ {step}")

                # Update agent to running
                agent_label = f"⚡ {agent.name}"
                agent_node.set_label(agent_label)
                chat.add_message(f"  ▶ {agent.name}: Executing...", color, "system")
                if thinking_panel:
                    thinking_panel.update_state(
                        action=f"▶ {agent.name} EXECUTING",
                        goal=f"Running {agent.name} on {mode_target}",
                        focus="Agent execution in progress"
                    )

                # Run agent
                result = await agent.run()

                # Display AI plan after PlanAgent completes, then filter remaining agents
                if is_plan_agent:
                    plan_finding = result.findings[0] if result.findings else None
                    if plan_finding:
                        plan_title = plan_finding.get("title", "") if isinstance(plan_finding, dict) else getattr(plan_finding, "title", "")
                        plan_desc = plan_finding.get("description", "") if isinstance(plan_finding, dict) else getattr(plan_finding, "description", "")
                        if plan_desc:
                            chat.add_message(f"  📋 Plan: {plan_title}", "#f59e0b", "system")
                            chat.add_message(f"  {plan_desc}", "#d4d4d4")
                    plan_meta = result.metadata.get("plan") if hasattr(result, "metadata") else None
                    if plan_meta:
                        ai_plan_categories = [c.lower() for c in (plan_meta.get("categories", []) if isinstance(plan_meta, dict) else getattr(plan_meta, "categories", []))]
                        reason = plan_meta.get("reason", "") if isinstance(plan_meta, dict) else getattr(plan_meta, "reason", "")
                        if ai_plan_categories:
                            chat.add_message(f"  📂 AI Selected Categories: {', '.join(ai_plan_categories)}", "#f59e0b", "system")
                        if reason:
                            chat.add_message(f"  💡 Reasoning: {reason}", "#a3a3a3")
                    # Filter remaining agents based on AI plan
                    if ai_plan_categories:
                        before = len(ordered_agents) - 1
                        ordered_agents = [ordered_agents[0]]  # keep PlanAgent
                        for agent in other_agents:
                            key = agent.name.lower().replace(" ", "").replace("-", "").replace("_", "")
                            cat = agent_categories.get(key, "")
                            if cat == "post" or cat in ai_plan_categories or "recon" in key:
                                ordered_agents.append(agent)
                        skipped = before - (len(ordered_agents) - 1)
                        if skipped > 0:
                            chat.add_message(f"  🎯 AI skipped {skipped} irrelevant agents (not in: {ai_plan_categories})", "#d97706", "system")

                # Display verified endpoints and technologies after ReconAgent completes
                if is_recon_agent:
                    endpoints = result.metadata.get("endpoints", []) if hasattr(result, "metadata") else []
                    technologies = result.metadata.get("technologies", []) if hasattr(result, "metadata") else []
                    if isinstance(technologies, list) and technologies:
                        chat.add_message(f"  🖥️ Technologies Detected ({len(technologies)}):", "#3b82f6", "system")
                        for tech in technologies[:10]:
                            chat.add_message(f"    🏷️ {tech}", "#22c55e")
                        if len(technologies) > 10:
                            chat.add_message(f"    ... and {len(technologies)-10} more", "#a3a3a3")
                    if isinstance(endpoints, list) and endpoints:
                        chat.add_message(f"  🌐 Verified Endpoints ({len(endpoints)}):", "#3b82f6", "system")
                        for ep in endpoints[:15]:
                            ep_str = ep if isinstance(ep, str) else ep.get("url", str(ep))
                            chat.add_message(f"    ✅ {ep_str}", "#22c55e")
                        if len(endpoints) > 15:
                            chat.add_message(f"    ... and {len(endpoints)-15} more", "#a3a3a3")
                    if thinking_panel:
                        thinking_panel.update_state(
                            action="✅ RECON COMPLETE",
                            goal=f"Found {len(technologies)} technologies, {len(endpoints)} endpoints",
                            reasoning="Target reconnaissance finished",
                            focus="Results available in findings panel",
                            next_step="Moving to vulnerability scanning"
                        )

                # Extract shared data from this agent's results for next agents
                if hasattr(result, "metadata") and result.metadata:
                    ep = result.metadata.get("endpoints", [])
                    if isinstance(ep, list):
                        for e in ep:
                            e_str = e if isinstance(e, str) else (e.get("url", "") if isinstance(e, dict) else str(e))
                            if e_str and e_str not in shared_endpoints:
                                shared_endpoints.append(e_str)
                    tech = result.metadata.get("technologies", [])
                    if isinstance(tech, list):
                        for t in tech:
                            if t not in shared_technologies:
                                shared_technologies.append(t)

                # Show shared data summary for next agents
                if is_recon_agent and (shared_endpoints or shared_technologies):
                    chat.add_message(f"  🔄 → Passing {len(shared_endpoints)} endpoints, {len(shared_technologies)} technologies to next agents", "#f59e0b", "system")

                # Mark complete
                agent_label = f"✅ {agent.name} ({len(result.findings)} findings)"
                agent_node.set_label(agent_label)
                chat.add_message(f"  ✅ {agent.name}: Complete ({len(result.findings)} findings)", color, "system")

                orchestrator.results.append(result)
                orchestrator.all_findings.extend(result.findings)

            # Store result
            scan_duration = time.time() - scan_start
            scan_result = orchestrator._create_scan_result(
                datetime.fromtimestamp(scan_start),
                datetime.now()
            )
            self.mode_results[mode] = scan_result

            if mode == self.current_mode:
                self._update_display_for_mode(mode, scan_result, scan_duration)
                if thinking_panel:
                    thinking_panel.update_state(
                        action="✅ SCAN COMPLETE",
                        goal=f"{scan_result.total_findings} findings in {scan_duration:.1f}s",
                        reasoning=f"All agents completed for {mode_target}",
                        focus=f"{scan_result.total_findings} total findings",
                        next_step="Review findings in panel or switch modes"
                    )

        except Exception as e:
            try:
                chat = self.query_one("#chat_display", ChatDisplay)
                chat.add_message(f"{mode.upper()} scan error: {str(e)}", "#dc2626", "system")
            except Exception:
                pass
            logger.error(f"Mode {mode} scan failed: {e}", exc_info=True)

    def _update_agents_tree_sync(self, agents: List) -> None:
        """Update agents tree — Strix-style Unicode indicators."""
        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.clear()
            self.agent_nodes.clear()

            for agent in agents:
                vuln_count = len(agent.findings) if hasattr(agent, 'findings') else 0
                vuln_str = f" ({vuln_count})" if vuln_count > 0 else ""
                agent_label = f"● {agent.name}{vuln_str}"
                agent_node = agents_tree.root.add(agent_label, expand=True)
                self.agent_nodes[agent.name] = agent_node

                phase_labels = ["Scanning", "Analysis", "Reporting"]
                for task in phase_labels:
                    task_label = f"○ {task}"
                    task_node = agent_node.add(task_label)
                    self.agent_nodes[f"{agent.name}_{task}"] = task_node

        except Exception as e:
            logger.error(f"Error updating agents tree: {e}")

    def _mark_agents_completed_sync(self) -> None:
        """Mark all agents as completed in the tree"""
        try:
            # Update all agent nodes to show completion
            for key, node in self.agent_nodes.items():
                if "Phase" in key:
                    # Update phase nodes
                    current_label = str(node.label)
                    if current_label.startswith("⏳"):
                        new_label = current_label.replace("⏳", "✅")
                        node.set_label(new_label)
                elif "🤖" not in key:
                    # Update sub-task nodes
                    current_label = str(node.label)
                    if current_label.startswith("⏳"):
                        new_label = current_label.replace("⏳", "✅")
                        node.set_label(new_label)

        except Exception as e:
            logger.error(f"Error marking agents completed: {e}")

    def _update_display_for_mode(self, mode: str, result: ScanResult, duration: float) -> None:
        """Update UI display with mode-specific results"""
        try:
            stats = self.query_one("#stats_display", StatsDisplay)
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
            chat = self.query_one("#chat_display", ChatDisplay)

            stats.scan_duration = duration
            stats.total_findings = result.total_findings
            stats.agents_completed = len(result.agent_results)
            stats.agents_total = len(result.agent_results)

            def _safe_int(value: Any, default: int = 0) -> int:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return default

            poc_meta = (result.metadata or {}).get("poc_validation", {})
            stats.poc_processed = _safe_int(poc_meta.get("processed", 0))
            stats.poc_validated = _safe_int(poc_meta.get("validated", 0))
            stats.poc_failed = _safe_int(poc_meta.get("failed", 0))
            stats.poc_skipped = _safe_int(poc_meta.get("skipped", 0))

            remediation_meta = (result.metadata or {}).get("remediation", {})
            stats.remediation_processed = _safe_int(remediation_meta.get("processed", 0))
            stats.remediation_suggested = _safe_int(remediation_meta.get("suggested", 0))
            stats.remediation_skipped = _safe_int(remediation_meta.get("skipped", 0))
            stats.refresh()

            if stats.remediation_processed > 0:
                color = self.MODE_COLORS.get(mode, "#22c55e")
                chat.add_message("REMEDIATION SUMMARY", color, "section")
                chat.add_message(
                    f"Processed: {stats.remediation_processed} | Suggested: {stats.remediation_suggested} | Skipped: {stats.remediation_skipped}",
                    "white",
                )
                suggestions = remediation_meta.get("suggestions", [])
                if isinstance(suggestions, list):
                    for suggestion in suggestions[:3]:
                        title = suggestion.get("title", "Unknown finding")
                        suggested_fix = suggestion.get("suggested_fix", "N/A")
                        chat.add_message(f"🛠️ {title} → {suggested_fix}", "#a3a3a3")

                        patch_suggestion = suggestion.get("patch_suggestion")
                        if patch_suggestion:
                            chat.add_message(f"  PATCH: {patch_suggestion}", "#737373")

                        risk_notes = suggestion.get("risk_notes")
                        if isinstance(risk_notes, list):
                            risk_notes = "; ".join(str(note) for note in risk_notes if note)
                        if risk_notes:
                            chat.add_message(f"  RISK: {risk_notes}", "#737373")

            if result.all_findings:
                vuln_panel.update_vulnerabilities(result.all_findings)
                vuln_panel.remove_class("hidden")

                color = self.MODE_COLORS.get(mode, "#22c55e")
                chat.add_message("VULNERABILITIES DETECTED", color, "section")

                for finding in result.all_findings:
                    severity_color = {
                        "critical": "#dc2626",
                        "high": "#ea580c",
                        "medium": "#d97706",
                        "low": "#22c55e",
                        "info": "#3b82f6",
                    }.get(finding.severity.lower(), "white")

                    chat.add_message(
                        f"[{finding.severity.upper()}] {finding.title}",
                        severity_color
                    )

        except Exception as e:
            logger.error(f"Error updating display: {e}")

    def action_quit(self) -> None:
        """Show quit confirmation dialog"""
        from itzraven.ui.strix_style.quit_screen import QuitScreen
        self.push_screen(QuitScreen())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission"""
        if not event.value.strip():
            return

        try:
            chat = self.query_one("#chat_display", ChatDisplay)
            input_field = self.query_one("#command_input", Input)

            user_input = event.value.strip()

            if self.current_mode not in self.mode_targets:
                self.mode_targets[self.current_mode] = user_input
                self.target = user_input
                color = self.MODE_COLORS.get(self.current_mode, "#22c55e")

                chat.add_message(f"Target set: {user_input}", color, "system")
                chat.add_message("Starting scan...", color, "system")

                input_field.placeholder = "Type a command or message..."
                input_field.value = ""

                self.call_after_refresh(lambda: self._initialize_mode_scan(self.current_mode))
                return

            chat.add_message(f"You: {user_input}", "#3b82f6", "system")

            command = user_input.lower()

            if command in ["help", "/help", "?"]:
                chat.add_message("HELP", "#22c55e", "section")
                chat.add_message("Available commands:", "#22c55e")
                chat.add_message("  /help      Show this help message", "white")
                chat.add_message("  /status    Show scan status", "white")
                chat.add_message("  /findings  List all findings", "white")
                chat.add_message("  /chain     Show agent execution chain", "white")
                chat.add_message("  /validate  Show PoC validation summary", "white")
                chat.add_message("  /cost      Show estimated token/API cost", "white")
                chat.add_message("  /surface   Show attack surface summary", "white")
                chat.add_message("  /clear     Clear chat history", "white")
                chat.add_message("  /quit      Exit application", "white")

            elif command in ["status", "/status"]:
                chat.add_message("STATUS", "#22c55e", "section")
                if self.scan_result:
                    stats = self.query_one("#stats_display", StatsDisplay)
                    chat.add_message(f"Duration: {stats.scan_duration:.1f}s", "white")
                    chat.add_message(f"Agents: {stats.agents_completed}/{stats.agents_total}", "white")
                    chat.add_message(f"Findings: {stats.total_findings}", "white")
                    chat.add_message(
                        f"PoC: P={stats.poc_processed} V={stats.poc_validated} F={stats.poc_failed} S={stats.poc_skipped}",
                        "white",
                    )
                else:
                    chat.add_message("Scan in progress...", "#d97706", "system")

            elif command in ["findings", "/findings"]:
                if self.scan_result and self.scan_result.all_findings:
                    chat.add_message("FINDINGS", "#22c55e", "section")
                    chat.add_message(f"Total: {len(self.scan_result.all_findings)} vulnerabilities", "#22c55e")
                    for i, finding in enumerate(self.scan_result.all_findings, 1):
                        severity_color = {
                            "critical": "#dc2626",
                            "high": "#ea580c",
                            "medium": "#d97706",
                            "low": "#22c55e",
                            "info": "#3b82f6",
                        }.get(finding.severity.lower(), "white")
                        chat.add_message(f"  {i}. [{finding.severity.upper()}] {finding.title}", severity_color)
                else:
                    chat.add_message("No findings yet", "#3b82f6", "system")

            elif command in ["clear", "/clear"]:
                chat._messages.clear()
                chat._update_display()
                chat.add_message("Chat cleared", "#22c55e", "system")

            elif command in ["chain", "/chain"]:
                chat.add_message("AGENT EXECUTION CHAIN", "#22c55e", "section")
                if self.agent_nodes:
                    for agent_name, node in self.agent_nodes.items():
                        label = str(node.label)
                        chat.add_message(f"  {label}", "#d4d4d4")
                else:
                    chat.add_message("  No agents deployed yet", "#737373")

            elif command in ["validate", "/validate"]:
                chat.add_message("PoC VALIDATION SUMMARY", "#22c55e", "section")
                stats = self.query_one("#stats_display", StatsDisplay)
                if stats.poc_processed > 0:
                    chat.add_message(f"  Processed: {stats.poc_processed}", "white")
                    chat.add_message(f"  Validated: {stats.poc_validated}", "#22c55e")
                    chat.add_message(f"  Failed:    {stats.poc_failed}", "#dc2626")
                    chat.add_message(f"  Skipped:   {stats.poc_skipped}", "#d97706")
                else:
                    chat.add_message("  No PoC validations yet", "#737373")

            elif command in ["cost", "/cost"]:
                chat.add_message("ESTIMATED COST", "#22c55e", "section")
                stats = self.query_one("#stats_display", StatsDisplay)
                total = (stats.poc_processed + stats.poc_validated +
                         stats.poc_failed + stats.poc_skipped)
                chat.add_message(f"  Total operations: {total}", "white")
                chat.add_message(f"  Duration: {stats.scan_duration:.1f}s", "white")
                chat.add_message("  Cost tracking: N/A (local mode)", "#d97706")

            elif command in ["surface", "/surface"]:
                chat.add_message("ATTACK SURFACE", "#22c55e", "section")
                surface_target = self.mode_targets.get(self.current_mode, self.target or 'Not set')
                chat.add_message(f"  Target: {surface_target}", "white")
                chat.add_message(f"  Mode: {self.current_mode.upper()}", "white")
                agents_count = len(self.agent_nodes)
                chat.add_message(f"  Active agents: {agents_count}", "white")
                stats = self.query_one("#stats_display", StatsDisplay)
                chat.add_message(f"  Findings: {stats.total_findings}", "#dc2626" if stats.total_findings > 0 else "white")

            elif command in ["quit", "/quit", "exit"]:
                self.action_quit()

            else:
                chat.add_message(f"Unknown command: {user_input}", "#d97706", "system")
                chat.add_message("Type 'help' for available commands", "#3b82f6")

            # Clear input
            input_field.value = ""

        except Exception as e:
            logger.error(f"Error processing input: {e}", exc_info=True)


def run_strix_ui(target: Optional[str] = None):
    """Run the Strix-inspired UI"""
    app = ItzravenStrixApp(target)
    app.run()


if __name__ == "__main__":
    run_strix_ui(None)  # No default target - user will enter it
