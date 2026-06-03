"""Textual UI exports for Itzraven."""


def run_strix_ui(*args, **kwargs):
    from itzraven.ui.strix_app import run_strix_ui as _run_strix_ui
    return _run_strix_ui(*args, **kwargs)
