"""
Bug Bounty Mode - specialized classes for bug bounty workflows
"""

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import Finding

logger = get_logger()

from itzraven.agents.bugbounty.scope_analyzer import ScopeAnalyzer
from itzraven.agents.bugbounty.duplicate_checker import DuplicateChecker
from itzraven.agents.bugbounty.report_drafter import ReportDrafter
from itzraven.agents.bugbounty.chain_builder import ChainBuilder
from itzraven.agents.bugbounty.quality_checker import QualityChecker

__all__ = [
    "ScopeAnalyzer",
    "DuplicateChecker",
    "ReportDrafter",
    "ChainBuilder",
    "QualityChecker",
    "logger",
]
