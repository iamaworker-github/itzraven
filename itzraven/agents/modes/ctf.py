from typing import Optional, List
from itzraven.agents.modes.base import ModeOrchestrator
from itzraven.agents.advanced_ctf_agent import AdvancedCTFAgent
from itzraven.agents.recon_agent import ReconAgent
from itzraven.core.event_bus import EventBus
from itzraven.core import MEMORY_SYSTEM_AVAILABLE
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager


class CTFOrchestrator(ModeOrchestrator):
    mode_name = "ctf"

    def __init__(
        self,
        target: str,
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scan_depth: str = "deep",
    ):
        super().__init__(target, event_bus, memory_manager, scan_depth=scan_depth)

    def load_agents(self) -> None:
        self.add_agent(AdvancedCTFAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))

    def get_report_template(self) -> str:
        return "ctf_writeup"

    def get_output_subdir(self) -> str:
        return "ctf"
