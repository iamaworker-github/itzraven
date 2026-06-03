"""
Help screen modal (Strix-style).
Shows keyboard shortcuts and a searchable command list.
"""

from textual.widgets import Static, Input
from textual.containers import VerticalScroll, Vertical
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.containers import Horizontal
from rich.text import Text
from rich.style import Style


HELP_DATA = {
    "Keyboard Shortcuts": [
        ("F1", "Toggle this help screen"),
        ("F2", "Open mode selector (Pentest/Bug Bounty/CTF/OSINT)"),
        ("F5", "Toggle sidebar visibility (narrow/wide chat)"),
        ("Ctrl+Q / Ctrl+C", "Quit application"),
        ("Esc", "Close modal / Stop agent"),
        ("Enter", "Submit command / Send message"),
        ("Tab", "Switch between panels"),
        ("↑ / ↓", "Navigate tree/list items"),
    ],
    "Slash Commands": [
        ("/help or ?", "Display this help screen"),
        ("/status", "Show current scan status & statistics"),
        ("/findings", "List all discovered vulnerabilities"),
        ("/chain", "Show agent execution chain with progress"),
        ("/validate", "Show PoC validation summary"),
        ("/cost", "Show estimated token/API cost (local mode)"),
        ("/surface", "Show current attack surface summary"),
        ("/clear", "Clear chat history"),
        ("/quit or exit", "Exit application"),
    ],
    "UI Panels": [
        ("Agents Tree (sidebar)", "Live agent status & phase progress bars"),
        ("Vulnerabilities", "Clickable finding list sorted by severity"),
        ("Stats Display", "Real-time scan metrics & counters"),
        ("Chat History", "Scrollable command output & agent logs"),
        ("Command Input", "Type commands or enter scan targets"),
    ],
    "Agent Indicators": [
        ("⚪ Agent", "Agent is starting up / idle"),
        ("⚡ Agent", "Agent is actively running"),
        ("🟢 Agent", "Agent completed successfully"),
        ("🔴 Agent", "Agent failed or errored"),
        ("⏳ Phase", "Phase in progress (with progress bar)"),
        ("✅ Phase", "Phase completed successfully"),
        ("● Finding", "Discovered vulnerability (color = severity)"),
    ],
}


class HelpScreen(ModalScreen):
    """Modal help screen displayed with the F1 key."""

    CSS = """
    HelpScreen {
        align: center middle;
    }

    #help_dialog {
        width: 80;
        height: 90%;
        background: #0a0a0a;
        border: heavy #22c55e;
        padding: 1 2;
    }

    #help_title {
        width: 100%;
        text-align: center;
        color: #22c55e;
        text-style: bold;
        margin-bottom: 1;
    }

    #help_search {
        width: 100%;
        margin-bottom: 1;
        background: #0f0f0f;
        border: solid #333333;
        color: #d4d4d4;
    }

    #help_search:focus {
        border: solid #22c55e;
    }

    #help_scroll {
        height: 1fr;
        margin-bottom: 1;
    }

    #help_footer {
        width: 100%;
        text-align: center;
        color: #737373;
        text-style: dim;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", priority=True),
        Binding("f1", "dismiss", "Close", priority=True),
    ]

    def __init__(self):
        super().__init__()
        self._filter = ""

    def compose(self):
        yield Vertical(
            Static("ITZRAVEN HELP", id="help_title"),
            Input(placeholder="Search commands or shortcuts...", id="help_search"),
            VerticalScroll(id="help_scroll"),
            Static("Esc / F1 to close  |  Type to search", id="help_footer"),
            id="help_dialog",
        )

    def on_mount(self):
        self._render_help()

    def _render_help(self, filter_text: str = ""):
        try:
            scroll = self.query_one("#help_scroll", VerticalScroll)
            scroll.remove_children()
        except Exception:
            return

        filter_lower = filter_text.lower()
        has_content = False

        for section, items in HELP_DATA.items():
            filtered = []
            for key, desc in items:
                if not filter_lower or filter_lower in key.lower() or filter_lower in desc.lower():
                    filtered.append((key, desc))
            if not filtered:
                continue
            has_content = True

            section_static = Static(f"\n  {section}", id="")
            section_static.styles.color = "#22c55e"
            section_static.styles.text_style = "bold"
            section_static.styles.border = ("solid", "#333333")
            scroll.mount(section_static)

            for key, desc in filtered:
                txt = Text()
                txt.append("    ", style="#333333")
                txt.append(key, style=Style(color="#86efac", bold=True))
                txt.append("  ", style="#333333")
                txt.append(desc, style=Style(color="#d4d4d4"))
                item = Static(txt, id="")
                item.styles.padding = (0, 1)
                scroll.mount(item)

        if not has_content:
            empty = Static("  No matching commands found", id="")
            empty.styles.color = "#737373"
            scroll.mount(empty)

    def on_input_changed(self, event: Input.Changed):
        self._filter = event.value
        self._render_help(self._filter)

    def on_key(self, _: "textual.events.Key") -> None:
        pass

    def action_dismiss(self) -> None:
        self.app.pop_screen()
