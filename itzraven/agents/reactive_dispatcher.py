"""
Reactive Agent Dispatcher — Dynamically spawns specialized agents based on detected technologies.
Uses technology fingerprinting to determine CMS, framework, and infrastructure,
then dispatches appropriate CMS-specific, stack-specific, and API agents.
"""

from typing import Dict, List, Optional, Set, Type, Callable
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.technology_detector import TechProfile, TechnologyDetector, get_tech_detector
from itzraven.agents.base_agent import BaseAgent
from itzraven.agents.cms.wordpress_agent import WordPressAgent
from itzraven.agents.cms.drupal_agent import DrupalAgent
from itzraven.agents.cms.joomla_agent import JoomlaAgent
from itzraven.agents.cms.magento_agent import MagentoAgent
from itzraven.agents.cms.prestashop_agent import PrestaShopAgent
from itzraven.agents.cms.moodle_agent import MoodleAgent
from itzraven.agents.stack.php_agent import PHPAgent
from itzraven.agents.stack.nodejs_agent import NodeJSAgent
from itzraven.agents.stack.flask_agent import FlaskAgent
from itzraven.agents.stack.aspnet_agent import ASPNetAgent
from itzraven.agents.stack.springboot_agent import SpringBootAgent
from itzraven.agents.stack.ruby_agent import RubyAgent

logger = get_logger()


@dataclass
class AgentTrigger:
    """Maps a technology trigger to an agent factory."""
    trigger_key: str  # e.g., "cms:wordpress", "framework:spring", "api:graphql"
    agent_class: Type[BaseAgent]
    agent_name: str
    description: str = ""
    min_confidence: float = 0.3
    priority: int = 10  # Lower = higher priority


# Registry of all reactive agent triggers
AGENT_TRIGGERS: List[AgentTrigger] = [
    # CMS Agents
    AgentTrigger("cms:wordpress", WordPressAgent, "WordPress Agent", "WordPress CMS vulnerability scanner", priority=1),
    AgentTrigger("cms:drupal", DrupalAgent, "Drupal Agent", "Drupal CMS vulnerability scanner", priority=1),
    AgentTrigger("cms:joomla", JoomlaAgent, "Joomla Agent", "Joomla CMS vulnerability scanner", priority=1),
    AgentTrigger("cms:magento", MagentoAgent, "Magento Agent", "Magento CMS vulnerability scanner", priority=1),
    AgentTrigger("cms:prestashop", PrestaShopAgent, "PrestaShop Agent", "PrestaShop CMS vulnerability scanner", priority=1),
    AgentTrigger("cms:moodle", MoodleAgent, "Moodle Agent", "Moodle LMS vulnerability scanner", priority=1),
    # Stack / Framework Agents
    AgentTrigger("lang:php", PHPAgent, "PHP Stack Agent", "PHP-specific vulnerability scanner", priority=2),
    AgentTrigger("lang:nodejs", NodeJSAgent, "NodeJS Stack Agent", "NodeJS-specific vulnerability scanner", priority=2),
    AgentTrigger("framework:flask", FlaskAgent, "Flask Stack Agent", "Flask-specific vulnerability scanner", priority=2),
    AgentTrigger("framework:aspnet", ASPNetAgent, "ASP.NET Stack Agent", "ASP.NET-specific vulnerability scanner", priority=2),
    AgentTrigger("framework:spring", SpringBootAgent, "Spring Boot Agent", "Spring/Spring Boot vulnerability scanner", priority=2),
    AgentTrigger("lang:ruby", RubyAgent, "Ruby Stack Agent", "Ruby/Rails-specific vulnerability scanner", priority=2),
]


class ReactiveDispatcher:
    """
    Dispatches specialized agents based on technology fingerprinting.
    Scans target → detects technologies → spawns matching agents.
    """

    def __init__(self, tech_detector: Optional[TechnologyDetector] = None):
        self.detector = tech_detector or get_tech_detector()
        self._spawned_agents: Dict[str, BaseAgent] = {}

    async def fingerprint_target(self, target: str, deep: bool = True) -> TechProfile:
        return await self.detector.fingerprint(target, deep=deep)

    def get_matching_triggers(self, profile: TechProfile) -> List[AgentTrigger]:
        triggers = profile.get_agent_triggers()
        matched: List[AgentTrigger] = []

        for trigger in AGENT_TRIGGERS:
            if trigger.trigger_key in triggers:
                # Check confidence
                for tech in profile.technologies:
                    if trigger.trigger_key in (
                        f"cms:{tech.name.lower()}",
                        f"framework:{tech.name.lower()}",
                        f"lang:{tech.name.lower()}",
                        f"api:{tech.name.lower()}",
                    ):
                        if tech.confidence >= trigger.min_confidence:
                            matched.append(trigger)
                            break

        matched.sort(key=lambda t: t.priority)
        return matched

    def spawn_agent(self, trigger: AgentTrigger, target: str, **kwargs) -> BaseAgent:
        agent = trigger.agent_class(target=target, **kwargs)
        agent_id = f"{trigger.trigger_key}::{agent.name}"
        self._spawned_agents[agent_id] = agent
        logger.info(f"🔄 Reactive Dispatch: Spawned {agent.name} (trigger: {trigger.trigger_key})")
        return agent

    async def dispatch_for_target(self, target: str, deep_fingerprint: bool = True, **kwargs) -> List[BaseAgent]:
        profile = await self.fingerprint_target(target, deep=deep_fingerprint)
        triggers = self.get_matching_triggers(profile)

        if not triggers:
            logger.info(f"ℹ No technology-specific agents triggered for {target}")
            return []

        agents: List[BaseAgent] = []
        for trigger in triggers:
            agent = self.spawn_agent(trigger, target, **kwargs)
            agents.append(agent)

        logger.info(f"🔄 Reactive Dispatch: {len(agents)} agent(s) spawned for {target}")
        return agents

    def get_spawned_agents(self) -> List[BaseAgent]:
        return list(self._spawned_agents.values())

    def has_agent(self, agent_name: str) -> bool:
        return any(a.name == agent_name for a in self._spawned_agents.values())

    def clear(self):
        self._spawned_agents.clear()
        self.detector.clear_cache()


_dispatcher_instance: Optional[ReactiveDispatcher] = None


def get_reactive_dispatcher() -> ReactiveDispatcher:
    global _dispatcher_instance
    if _dispatcher_instance is None:
        _dispatcher_instance = ReactiveDispatcher()
    return _dispatcher_instance
