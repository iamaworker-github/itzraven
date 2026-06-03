"""
Quit confirmation modal — exact replica of 10.png design.
Shows "Quit Itzraven" title, "Are you sure you want to quit?" message,
and Cancel / Quit buttons. Ctrl+C or Ctrl+Q triggers this dialog.
"""

from textual.containers import Vertical, Horizontal
from textual.widgets import Label, Button
from textual.screen import ModalScreen
from textual.binding import Binding


class QuitScreen(ModalScreen):
    """Modal quit confirmation — exact replica of reference image."""

    CSS = """
    QuitScreen {
        align: center middle;
        background: #000000 80%;
    }

    #quit_dialog {
        width: 50;
        height: auto;
        background: #0d0d0d;
        border: heavy #22c55e;
        padding: 2 3;
    }

    #quit_title {
        width: 100%;
        height: auto;
        text-align: center;
        color: #22c55e;
        text-style: bold;
        margin-bottom: 1;
        padding: 0;
    }

    #quit_message {
        width: 100%;
        height: auto;
        text-align: center;
        color: #a3a3a3;
        margin-bottom: 2;
        padding: 0;
    }

    #quit_buttons {
        width: 100%;
        height: auto;
        align: center middle;
    }

    #quit_button_cancel {
        width: 14;
        margin: 0 1;
        background: #1a1a1a;
        color: #a3a3a3;
        border: round #333333;
    }

    #quit_button_cancel:hover {
        background: #262626;
        border: round #22c55e;
    }

    #quit_button_cancel:focus {
        background: #262626;
        border: heavy #22c55e;
    }

    #quit_button_quit {
        width: 14;
        margin: 0 1;
        background: #dc2626;
        color: #ffffff;
        border: round #ef4444;
    }

    #quit_button_quit:hover {
        background: #b91c1c;
        border: heavy #ef4444;
    }

    #quit_button_quit:focus {
        background: #b91c1c;
        border: heavy #ef4444;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel_quit", "Cancel", priority=True),
    ]

    def compose(self):
        with Vertical(id="quit_dialog"):
            yield Label("Quit Itzraven", id="quit_title")
            yield Label("Are you sure you want to quit?", id="quit_message")
            with Horizontal(id="quit_buttons"):
                yield Button("Cancel", id="quit_button_cancel")
                yield Button("Quit", id="quit_button_quit")

    def on_button_pressed(self, event):
        if event.button.id == "quit_button_quit":
            self.app.pop_screen()
            self.app.exit()
        elif event.button.id == "quit_button_cancel":
            self.app.pop_screen()

    def action_cancel_quit(self):
        self.app.pop_screen()
