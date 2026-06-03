"""
NucleiAgent — Runs nuclei templates on discovered URLs for CVE/vulnerability scanning.
Uses AI to select relevant templates based on technologies detected.
"""
import asyncio
import json
import subprocess
from typing import Optional, List, Dict, Any
from pathlib import Path

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.llm_client import LLMClient
from itzraven.core.logger import get_logger

logger = get_logger()

TECH_TEMPLATE_MAP = {
    "nginx": ["nginx", "tech-detection"],
    "apache": ["apache", "tomcat"],
    "php": ["php", "phpmyadmin", "lfi"],
    "wordpress": ["wordpress", "wp-plugin"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "react": ["react", "nodejs"],
    "vue": ["vue"],
    "angular": ["angular"],
    "node": ["nodejs", "express"],
    "python": ["python", "django", "flask", "fastapi"],
    "java": ["java", "spring", "struts"],
    "go": ["golang"],
    "ruby": ["ruby", "rails"],
    "mysql": ["mysql", "sql-injection"],
    "postgresql": ["postgresql"],
    "mongodb": ["mongodb", "nosql"],
    "redis": ["redis"],
    "jwt": ["jwt", "auth"],
    "graphql": ["graphql"],
    "api": ["api", "swagger", "graphql"],
    "cloudflare": ["cloudflare"],
    "aws": ["aws", "s3", "cloudfront"],
}

DEFAULT_TEMPLATES = ["cves", "vulnerabilities", "misconfiguration", "exposed-panels"]


class NucleiAgent(BaseAgent):
    """Scans URLs with nuclei templates. AI selects relevant templates."""

    def __init__(self, target: str, event_bus=None, memory_manager=None, urls: Optional[List[str]] = None, technologies: Optional[List[str]] = None):
        super().__init__("Nuclei Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.urls = urls or [target]
        self.technologies = technologies or []
        self.llm = LLMClient()
        self.selected_templates: List[str] = []
        self.scan_results: List[Dict] = []

    async def execute(self) -> AgentResult:
        if not self._check_nuclei():
            logger.warning("nuclei not installed, skipping")
            return AgentResult(self.name, AgentStatus.FAILED, [], 0, "nuclei not installed")

        await self._ai_select_templates()
        await self._run_nuclei()

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            findings=self.findings, execution_time=0,
            metadata={
                "templates_used": self.selected_templates,
                "total_urls_scanned": len(self.urls),
                "findings_count": len(self.findings),
                "scan_results": self.scan_results[:50],
            },
        )

    def _check_nuclei(self) -> bool:
        try:
            r = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
            return r.returncode == 0
        except Exception:
            return False

    async def _ai_select_templates(self) -> None:
        tech_lower = [t.lower() for t in self.technologies]
        matched = set()
        for tech in tech_lower:
            for key, templates in TECH_TEMPLATE_MAP.items():
                if key in tech:
                    matched.update(templates)
        self.selected_templates = list(matched) if matched else DEFAULT_TEMPLATES.copy()
        try:
            prompt = f"""Target: {self.target}
Technologies detected: {', '.join(self.technologies) or 'unknown'}
Available nuclei templates include: {', '.join(sorted(matched)) if matched else ', '.join(DEFAULT_TEMPLATES)}

Select 3-5 most relevant nuclei template categories for this target.
Return ONLY a JSON list: ["template1", "template2", "template3"]"""
            resp = await self.llm.generate(prompt=prompt, max_tokens=200, temperature=0.3)
            from itzraven.core.json_utils import extract_json_safe
            ai_templates = extract_json_safe(resp.content.strip(), [])
            if isinstance(ai_templates, list) and ai_templates:
                self.selected_templates = list(dict.fromkeys(self.selected_templates + ai_templates))[:8]
        except Exception:
            pass
        logger.info(f"{self.name}: Selected templates: {self.selected_templates}")

    async def _run_nuclei(self) -> None:
        urls_file = "/tmp/nuclei_urls.txt"
        output_file = "/tmp/nuclei_results.jsonl"
        try:
            with open(urls_file, "w") as f:
                for url in self.urls[:200]:
                    f.write(url + "\n")

            cmd = ["nuclei", "-l", urls_file, "-jsonl", "-o", output_file,
                   "-stats", "-silent", "-timeout", "10"]
            cmd.extend(self.format_auth_args())
            for template in self.selected_templates:
                cmd.extend(["-t", template])
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=180)
                except asyncio.TimeoutError:
                    proc.kill()

                if Path(output_file).exists():
                    with open(output_file) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    entry = json.loads(line)
                                    self.scan_results.append(entry)
                                    self._add_finding_from_nuclei(entry)
                                except json.JSONDecodeError:
                                    continue
                    Path(output_file).unlink(missing_ok=True)
            except Exception as e:
                logger.debug(f"Nuclei scan failed: {e}")

        except Exception as e:
            logger.error(f"{self.name}: Failed: {e}")
        finally:
            Path(urls_file).unlink(missing_ok=True)

    def _add_finding_from_nuclei(self, entry: Dict) -> None:
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        sev = severity_map.get(entry.get("info", {}).get("severity", "").lower(), "info")
        name = entry.get("info", {}).get("name", entry.get("template-id", "unknown"))
        matched = entry.get("matched-at", entry.get("host", self.target))
        extract = entry.get("extracted-results", [])
        ext_str = ", ".join(extract[:3]) if extract else ""
        desc = entry.get("info", {}).get("description", "")
        template_id = entry.get("template-id", "")
        cve = ""
        if "classification" in entry.get("info", {}):
            cve = ", ".join(entry["info"]["classification"].get("cve-id", []))
        self.add_finding(Finding(
            title=f"[Nuclei] {name}" + (f" ({cve})" if cve else ""),
            description=desc or f"Nuclei template {template_id} matched on {matched}",
            severity=sev, category="nuclei",
            evidence=f"URL: {matched}\nExtracted: {ext_str}\nTemplate: {template_id}",
            confidence=0.85,
        ))
