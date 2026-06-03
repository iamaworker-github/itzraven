"""
Rules of Engagement — Professional pentest engagement setup workflow.
Decepticon-inspired: RoE document, engagement scoping, methodology selection.
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()

ENGAGEMENT_TYPES = {
    "webapp": "Web Application Pentest",
    "network": "Network Infrastructure Pentest",
    "mobile": "Mobile Application Pentest",
    "api": "API Security Assessment",
    "cloud": "Cloud Security Assessment",
    "red_team": "Red Team Exercise",
    "bug_bounty": "Bug Bounty Hunting",
}

METHODOLOGY_MAP = {
    "webapp": ["OWASP Top 10", "OSSTMM", "PTES"],
    "network": ["PTES", "OSSTMM", "NIST SP 800-115"],
    "mobile": ["OWASP Mobile Top 10", "MASVS"],
    "api": ["OWASP API Security Top 10"],
    "cloud": ["CSA CCM", "CIS Benchmarks"],
    "red_team": ["MITRE ATT&CK", "CTID"],
    "bug_bounty": ["Custom Bug Bounty Methodology"],
}


@dataclass
class RoE:
    client_name: str = ""
    engagement_type: str = "webapp"
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    start_date: str = ""
    end_date: str = ""
    methodology: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    contacts: Dict[str, str] = field(default_factory=dict)

    def validate(self) -> List[str]:
        issues = []
        if not self.client_name:
            issues.append("Client name is required")
        if not self.scope:
            issues.append("At least one in-scope target required")
        if self.engagement_type not in ENGAGEMENT_TYPES:
            issues.append(f"Unknown engagement type: {self.engagement_type}")
        return issues


class RulesOfEngagement:
    def __init__(self):
        self.roe = RoE()

    def create(self, client: str, eng_type: str = "webapp", targets: Optional[List[str]] = None) -> RoE:
        self.roe = RoE(
            client_name=client,
            engagement_type=eng_type,
            scope=targets or [],
            methodology=METHODOLOGY_MAP.get(eng_type, ["OWASP Top 10"]),
            start_date=datetime.now().strftime("%Y-%m-%d"),
            end_date=(datetime.now() + timedelta(days=14)).strftime("%Y-%m-%d"),
            rules=[
                f"Only test targets listed in in-scope section",
                "All testing must be passive where possible",
                "Critical findings must be reported within 24 hours",
                "No social engineering without explicit approval",
                "No denial of service attacks",
                "Data exfiltration limited to proof-of-concept only",
                "All findings must include reproducible PoC",
            ],
            contacts={"emergency": "", "technical": ""},
        )
        logger.info(f"Created RoE for {client} ({ENGAGEMENT_TYPES.get(eng_type, eng_type)})")
        return self.roe

    def generate_doc(self) -> str:
        r = self.roe
        lines = [
            "# Rules of Engagement",
            "",
            f"**Client:** {r.client_name}",
            f"**Engagement Type:** {ENGAGEMENT_TYPES.get(r.engagement_type, r.engagement_type)}",
            f"**Period:** {r.start_date} to {r.end_date}",
            f"**Methodology:** {', '.join(r.methodology)}",
            "",
            "## In-Scope",
        ]
        for s in r.scope:
            lines.append(f"- {s}")
        lines.extend(["", "## Out-of-Scope"])
        for o in r.out_of_scope:
            lines.append(f"- {o}")
        lines.extend(["", "## Rules"])
        for rule in r.rules:
            lines.append(f"- {rule}")
        return "\n".join(lines)

    def load_from_dict(self, data: Dict[str, Any]) -> RoE:
        self.roe = RoE(
            client_name=data.get("client", ""),
            engagement_type=data.get("type", "webapp"),
            scope=data.get("scope", []),
            out_of_scope=data.get("out_of_scope", []),
            methodology=data.get("methodology", METHODOLOGY_MAP.get(data.get("type", "webapp"), [])),
            dates=data.get("dates", {}),
        )
        return self.roe


def get_roe() -> RulesOfEngagement:
    return RulesOfEngagement()
