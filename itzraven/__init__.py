"""
Itzraven - AI-Powered Security Testing Platform
See Everything. Miss Nothing.
"""

__version__ = "2.0.0"
__author__ = "Itzraven Security Team"
__description__ = "AI-Powered Security Testing Platform"

from itzraven.core.config import Config
from itzraven.core.logger import get_logger

__all__ = ["Config", "get_logger", "__version__"]
