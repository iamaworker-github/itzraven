"""
Strix‑style UI package for Itzraven.
Provides modular components that replicate Strix's TUI experience.
Only a minimal subset is implemented for Phase 1.
"""

# Exported symbols – currently only splash and the placeholder Strix app
__all__ = ["splash", "app", "run_strix_ui"]

# Re‑export the run helper for the CLI.
from .app import run_strix_ui
