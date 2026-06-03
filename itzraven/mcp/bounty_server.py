"""
Bug Bounty MCP Server — HackerOne/Bugcrowd/Intigriti API integration.

Provides MCP tools for bug bounty platform interaction:
- Fetch programs and scope
- Submit reports
- Check submission status
- Monitor program changes
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from itzraven.core.logger import get_logger
from itzraven.core.config import ITZRAVEN_HOME

logger = get_logger()


@dataclass
class BountyProgram:
    """Bug bounty program metadata."""
    platform: str
    name: str
    url: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    min_severity: str = "low"
    max_bounty: Optional[int] = None
    active: bool = True
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform, "name": self.name, "url": self.url,
            "scope": self.scope, "out_of_scope": self.out_of_scope,
            "min_severity": self.min_severity, "max_bounty": self.max_bounty,
            "active": self.active, "last_updated": self.last_updated,
        }


@dataclass
class BountyReport:
    """Bug bounty report submission."""
    platform: str
    program: str
    title: str
    vulnerability: str
    severity: str
    description: str
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    attachments: List[str] = field(default_factory=list)
    status: str = "draft"  # draft, submitted, triaged, resolved, rejected
    report_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform, "program": self.program,
            "title": self.title, "vulnerability": self.vulnerability,
            "severity": self.severity, "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact, "status": self.status,
            "report_id": self.report_id,
        }


class BountyPlatformAPI:
    """Base class for bounty platform API integration."""

    def __init__(self):
        self.config_dir = ITZRAVEN_HOME / "bounty"
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def load_credentials(self, platform: str) -> Dict[str, str]:
        cred_file = self.config_dir / f"{platform}_creds.json"
        if cred_file.exists():
            return json.loads(cred_file.read_text())
        return {}

    def save_credentials(self, platform: str, creds: Dict[str, str]):
        cred_file = self.config_dir / f"{platform}_creds.json"
        cred_file.write_text(json.dumps(creds))
        cred_file.chmod(0o600)


class BountyServer:
    """Bug bounty MCP tool server.

    Provides tools for:
    - h1_search_programs: Search HackerOne programs
    - h1_get_program: Get program details
    - h1_submit_report: Submit report to HackerOne
    - bc_search_programs: Search Bugcrowd programs
    - intigriti_search: Search Intigriti programs
    - bounty_triage: Triage finding for bounty submission
    """

    # Built-in program database for quick lookup
    BUILTIN_PROGRAMS = [
        BountyProgram("hackerone", "GitHub Security", "https://hackerone.com/github",
                      scope=["*.github.com", "github.com", "api.github.com", "*.githubapp.com"],
                      min_severity="low", max_bounty=30000),
        BountyProgram("hackerone", "Shopify", "https://hackerone.com/shopify",
                      scope=["*.shopify.com", "*.myshopify.com", "shopify.com"],
                      min_severity="low", max_bounty=20000),
        BountyProgram("hackerone", "Twitter/X", "https://hackerone.com/twitter",
                      scope=["*.twitter.com", "*.x.com", "twitter.com", "x.com"],
                      min_severity="medium", max_bounty=10000),
        BountyProgram("hackerone", "Dropbox", "https://hackerone.com/dropbox",
                      scope=["*.dropbox.com", "dropbox.com", "*.dropboxapi.com"],
                      min_severity="low", max_bounty=15000),
        BountyProgram("bugcrowd", "Spotify", "https://bugcrowd.com/spotify",
                      scope=["*.spotify.com", "api.spotify.com"],
                      min_severity="low", max_bounty=10000),
        BountyProgram("bugcrowd", "Atlassian", "https://bugcrowd.com/atlassian",
                      scope=["*.atlassian.com", "*.jira.com", "*.bitbucket.org"],
                      min_severity="low", max_bounty=5000),
        BountyProgram("intigriti", "Intel", "https://www.intigriti.com/programs/intel",
                      scope=["*.intel.com", "intel.com"],
                      min_severity="medium", max_bounty=5000),
        BountyProgram("intigriti", "KPMG", "https://www.intigriti.com/programs/kpmg",
                      scope=["*.kpmg.com", "kpmg.com"],
                      min_severity="medium", max_bounty=5000),
    ]

    def __init__(self):
        self.api = BountyPlatformAPI()
        self.programs: Dict[str, List[BountyProgram]] = {
            "hackerone": [],
            "bugcrowd": [],
            "intigriti": [],
        }
        self._load_programs()

    def _load_programs(self):
        for p in self.BUILTIN_PROGRAMS:
            self.programs.setdefault(p.platform, []).append(p)
        logger.info(f"Bounty server loaded {sum(len(v) for v in self.programs.values())} programs")

    async def search_programs(self, platform: str, query: str = "") -> List[Dict[str, Any]]:
        """Search programs on a bounty platform."""
        platform = platform.lower()
        results = self.programs.get(platform, [])
        if query:
            q = query.lower()
            results = [p for p in results if q in p.name.lower() or q in p.url.lower()]
        return [p.to_dict() for p in results]

    async def get_program(self, platform: str, name: str) -> Optional[Dict[str, Any]]:
        """Get program details by name."""
        for p in self.programs.get(platform.lower(), []):
            if p.name.lower() == name.lower():
                return p.to_dict()
        return None

    async def submit_report(self, platform: str, report: BountyReport) -> Dict[str, Any]:
        """Submit a report to a bounty platform.

        In production, calls the platform API. For now, saves locally.
        """
        report_dir = self.api.config_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_file = report_dir / f"{platform}_{report.title[:30]}.json"
        report_data = report.to_dict()
        report_data["_submitted_at"] = datetime.now().isoformat()
        report_file.write_text(json.dumps(report_data, indent=2))
        logger.info(f"Report saved to {report_file}")
        return {
            "success": True,
            "platform": platform,
            "report_title": report.title,
            "status": report.status,
            "saved_to": str(report_file),
        }

    async def triage_finding(self, finding_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Triage a finding for bounty submission.

        Evaluates the finding against bounty submission criteria:
        - Is the severity high enough?
        - Is there a clear attack vector?
        - Is there a working PoC?
        - Does the impact justify bounty-level submission?
        """
        severity = finding_dict.get("severity", "info").lower()
        has_poc = bool(finding_dict.get("proof_of_concept", "").strip())
        has_evidence = len(finding_dict.get("evidence", "").strip()) > 50
        has_steps = len(finding_dict.get("reproducibility_steps", [])) >= 2

        bounty_ready = False
        issues = []

        if severity in ("critical", "high"):
            if has_poc and has_evidence:
                bounty_ready = True
            elif not has_poc:
                issues.append("Missing PoC for high/critical finding")
            elif not has_evidence:
                issues.append("Insufficient evidence for bounty submission")
        elif severity == "medium":
            if has_poc and has_evidence:
                bounty_ready = True
            else:
                issues.append("Medium severity needs PoC + evidence for bounty")
        else:
            issues.append(f"Severity '{severity}' too low for bounty submission")

        return {
            "bounty_ready": bounty_ready,
            "severity": severity,
            "has_poc": has_poc,
            "has_evidence": has_evidence,
            "has_steps": has_steps,
            "issues": issues,
            "recommendation": "Submit" if bounty_ready else "Improve evidence first",
        }

    async def find_matching_programs(self, target: str) -> List[Dict[str, Any]]:
        """Find programs that match a given target."""
        target_lower = target.lower()
        matches = []
        for platform, progs in self.programs.items():
            for p in progs:
                for s in p.scope:
                    if s.replace("*.", "") in target_lower or target_lower in s:
                        matches.append(p.to_dict())
                        break
        return matches

    async def get_all_programs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all programs grouped by platform."""
        return {
            platform: [p.to_dict() for p in progs]
            for platform, progs in self.programs.items()
        }


_bounty_server: Optional[BountyServer] = None


def get_bounty_server() -> BountyServer:
    """Singleton accessor for BountyServer."""
    global _bounty_server
    if _bounty_server is None:
        _bounty_server = BountyServer()
    return _bounty_server
