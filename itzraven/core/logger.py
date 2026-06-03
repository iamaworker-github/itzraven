"""
Logging system for Itzraven
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
from rich.logging import RichHandler
from rich.console import Console


def _get_console() -> Console:
    """Create Console with safe defaults to avoid terminal detection hangs."""
    return Console(force_terminal=False, color_system="truecolor", _environ={})


console = _get_console()


class ItzravenLogger:
    """Custom logger for Itzraven with rich formatting"""

    def __init__(self, name: str, log_file: Optional[Path] = None, verbose: bool = False):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        # Remove existing handlers
        self.logger.handlers.clear()

        # Rich console handler
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_formatter = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler (if log file specified)
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(f"[dim]{message}[/dim]")

    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(f"[cyan]{message}[/cyan]")

    def success(self, message: str) -> None:
        """Log success message"""
        self.logger.info(f"[green]✓[/green] {message}")

    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(f"[yellow]⚠[/yellow] {message}")

    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(f"[red]✗[/red] {message}")

    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(f"[bold red]🔥[/bold red] {message}")


# Global logger instance
_logger: Optional[ItzravenLogger] = None


def get_logger(name: str = "itzraven", log_file: Optional[Path] = None, verbose: bool = False) -> ItzravenLogger:
    """Get or create logger instance"""
    global _logger
    if _logger is None:
        _logger = ItzravenLogger(name, log_file, verbose)
    return _logger


def setup_logging(output_dir: Path, verbose: bool = False) -> ItzravenLogger:
    """Setup logging with output directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = output_dir / f"itzraven_{timestamp}.log"
    return get_logger(log_file=log_file, verbose=verbose)
