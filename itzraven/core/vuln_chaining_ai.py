"""
AI-Powered Vulnerability Chaining — LLM finds attack chains from low/medium findings
to build high-severity exploit paths automatically.
"""

import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient
from itzraven.agents.base_agent import Finding

logger = get_logger()


class ChainSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackChain:
    id: str
    name: str
    description: str
    severity: ChainSeverity
    steps: List[Dict]
    prerequisite_findings: List[str]
    confidence: float
    exploit_script: Optional[str] = None
    remediation: str = ""
    verified: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "steps": len(self.steps),
            "prerequisites": self.prerequisite_findings,
            "confidence": round(self.confidence, 3),
            "verified": self.verified,
        }


class VulnChainingAI:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self.chains: List[AttackChain] = []
        self._executed_chains: Dict[str, bool] = {}

    @classmethod
    def get_instance(cls) -> "VulnChainingAI":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def discover_chains(self, findings: List[Finding]) -> List[AttackChain]:
        if len(findings) < 2:
            return []

        finding_dicts = [
            {"title": f.title, "severity": f.severity, "category": f.category,
             "description": f.description[:200], "evidence": f.evidence[:200]}
            for f in findings
        ]

        prompt = (
            "Analyze these security findings and identify ATTACK CHAINS — "
            "sequences where multiple low/medium severity issues combine "
            "to create a critical/high severity exploit path.\n\n"
            f"Findings ({len(finding_dicts)}):\n{json.dumps(finding_dicts, indent=2)}\n\n"
            "For each attack chain, output:\n"
            "{\n"
            '  "chains": [\n'
            '    {\n'
            '      "name": "chain name",\n'
            '      "description": "how the chain works",\n'
            '      "severity": "critical/high/medium",\n'
            '      "prerequisite_findings": ["finding titles needed"],\n'
            '      "steps": [{"step": 1, "action": "what to do", "detail": "how to execute"}],\n'
            '      "confidence": 0.0-1.0,\n'
            '      "remediation": "how to fix"\n'
            '    }\n'
            "  ]\n"
            "}\n"
            "Consider: SSRF+InternalScan, SQLi+DataExfil, XSS+SessionHijack, "
            "IDOR+PrivEsc, LFI+RCE, SubdomainTakeover+Phishing, etc."
        )
        system = (
            "You are an expert in vulnerability chaining. You know how seemingly "
            "low-risk issues combine into critical exploits. Be creative but realistic."
        )

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=2000, task="vuln_chaining")
            raw = resp.content
            if isinstance(raw, str):
                raw = json.loads(raw)
            parsed = raw if isinstance(raw, dict) else json.loads(raw)
        except Exception as e:
            logger.debug(f"Vuln chaining parse failed: {e}")
            return []

        new_chains = []
        for chain_data in parsed.get("chains", []):
            import uuid
            chain = AttackChain(
                id=f"chain_{uuid.uuid4().hex[:8]}",
                name=chain_data.get("name", "Unknown chain"),
                description=chain_data.get("description", ""),
                severity=ChainSeverity(chain_data.get("severity", "medium")),
                steps=chain_data.get("steps", []),
                prerequisite_findings=chain_data.get("prerequisite_findings", []),
                confidence=float(chain_data.get("confidence", 0.5)),
                remediation=chain_data.get("remediation", ""),
            )
            self.chains.append(chain)
            new_chains.append(chain)
            logger.info(f"VulnChain: {chain.name} ({chain.severity.value}, confidence={chain.confidence:.2f})")

        return new_chains

    async def generate_exploit(self, chain: AttackChain) -> Optional[str]:
        prompt = (
            f"Generate a working Python exploit script for this attack chain:\n\n"
            f"Name: {chain.name}\n"
            f"Description: {chain.description}\n"
            f"Steps: {json.dumps(chain.steps, indent=2)}\n\n"
            "Output a complete Python script that:\n"
            "1. Checks prerequisites are met\n"
            "2. Executes each step in sequence\n"
            "3. Extracts results\n"
            "4. Handles errors gracefully\n"
            "Output ONLY the Python code, no explanations."
        )
        system = "You are an exploit developer. Generate working, safe Python exploit code."
        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=2500, task="exploit_generation")
            code = resp.content.strip()
            if code.startswith("```"):
                code = code.split("```")[1]
                if code.startswith("python"):
                    code = code[6:].strip()
            chain.exploit_script = code
            chain.verified = True
            return code
        except Exception as e:
            logger.debug(f"Exploit generation failed: {e}")
            return None

    async def try_chain(self, chain: AttackChain, target: str) -> Dict:
        if not chain.exploit_script:
            await self.generate_exploit(chain)

        import tempfile, subprocess, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(chain.exploit_script.replace("TARGET", target))
            f.write(f"\n\n# Auto-generated by Itzraven VulnChainingAI\n")
            script_path = f.name

        try:
            result = subprocess.run(["python3", script_path], capture_output=True, text=True, timeout=30)
            success = result.returncode == 0
            self._executed_chains[chain.id] = success
            return {
                "success": success,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:500],
            }
        except subprocess.TimeoutExpired:
            self._executed_chains[chain.id] = False
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            self._executed_chains[chain.id] = False
            return {"success": False, "error": str(e)}
        finally:
            os.unlink(script_path)

    def get_viable_chains(self, min_confidence: float = 0.4) -> List[AttackChain]:
        return [c for c in self.chains if c.confidence >= min_confidence and c.id not in self._executed_chains]

    def get_summary(self) -> dict:
        return {
            "total_chains": len(self.chains),
            "executed": sum(1 for v in self._executed_chains.values() if v),
            "failed": sum(1 for v in self._executed_chains.values() if not v),
            "pending": len(self.get_viable_chains()),
            "chains": [c.to_dict() for c in self.chains],
        }


get_vuln_chaining = VulnChainingAI.get_instance
