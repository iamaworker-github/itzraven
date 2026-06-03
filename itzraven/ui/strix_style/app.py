"""
Phase 1 Strix‑style UI entry point.
We simply delegate to the full Itzraven Strix implementation for now.
Later phases will replace this with a custom UI built from the modular components.
"""

from itzraven.ui.strix_app import run_strix_ui as _run_strix_ui

def run_strix_ui(target: str | None = None):
    """Public helper used by the CLI.

    Args:
        target: Optional target string passed from the CLI.
    """
    _run_strix_ui(target)
