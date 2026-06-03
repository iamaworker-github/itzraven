"""
Chain Builder - discovers A -> B -> C exploit chains from findings
"""

from typing import List, Dict, Any, Optional, Tuple

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import Finding

logger = get_logger()

CAPABILITY_MATRIX: Dict[str, List[str]] = {
    "xss": ["csrf", "session_hijack", "ato", "data_exfiltration"],
    "csrf": ["ato", "privilege_escalation", "data_modification"],
    "idor": ["privilege_escalation", "admin_access", "data_exfiltration"],
    "sqli": ["rce", "data_exfiltration", "auth_bypass", "privilege_escalation"],
    "ssrf": ["internal_access", "rce", "port_scan", "cloud_metadata"],
    "rce": ["full_compromise", "persistence", "lateral_movement"],
    "privilege_escalation": ["admin_access", "full_compromise"],
    "auth_bypass": ["privilege_escalation", "admin_access", "ato"],
    "open_redirect": ["phishing", "oauth_token_theft", "ssrf"],
    "prototype_pollution": ["xss", "rce", "dos"],
    "insecure_deserialization": ["rce", "sql_injection", "dos"],
    "file_upload": ["rce", "xss", "stored_xss"],
    "ssti": ["rce", "data_exfiltration"],
    "xxe": ["ssrf", "rce", "data_exfiltration"],
}


class ChainBuilder:
    def __init__(self, capability_matrix: Optional[Dict[str, List[str]]] = None):
        self.matrix = capability_matrix or CAPABILITY_MATRIX

    def build_chains(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        categories = [f.category.lower() for f in findings]

        for i, source in enumerate(findings):
            src_cat = source.category.lower()
            unlocked = self.matrix.get(src_cat, [])

            for j, pivot in enumerate(findings):
                if i == j:
                    continue
                piv_cat = pivot.category.lower()
                if piv_cat not in unlocked:
                    continue

                sink_cats = self.matrix.get(piv_cat, [])
                for k, sink in enumerate(findings):
                    if k in (i, j):
                        continue
                    if sink.category.lower() in sink_cats:
                        chains.append(self._build_chain(source, pivot, sink))

        chains.sort(key=lambda c: c["risk_score"], reverse=True)

        if chains:
            logger.success(f"Discovered {len(chains)} exploit chains")
        else:
            logger.info("No exploit chains discovered from current findings")

        return chains

    def get_chain_suggestions(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        categories_present = {f.category.lower() for f in findings}
        suggestions: List[Dict[str, Any]] = []

        for src_cat, unlocked in self.matrix.items():
            if src_cat not in categories_present:
                continue
            for missing_cat in unlocked:
                if missing_cat not in categories_present:
                    suggestions.append({
                        "from": src_cat,
                        "to": missing_cat,
                        "description": (
                            f"Finding of type '{src_cat}' present — "
                            f"adding '{missing_cat}' could enable chaining"
                        ),
                        "potential_impact": self._estimate_impact([src_cat, missing_cat]),
                    })

        return suggestions

    def generate_chain_report(self, chains: List[Dict[str, Any]]) -> str:
        if not chains:
            return "# Exploit Chain Analysis\n\nNo exploit chains were identified."

        lines: List[str] = [
            "# Exploit Chain Analysis",
            "",
            f"**Total chains discovered:** {len(chains)}",
            "",
            "---",
            "",
        ]

        for i, chain in enumerate(chains, 1):
            source = chain["source"]
            pivot = chain["pivot"]
            sink = chain["sink"]

            lines.append(f"## Chain {i}: {source['title']} → {pivot['title']} → {sink['title']}")
            lines.append("")
            lines.append(f"**Risk Score:** {chain['risk_score']}/10")
            lines.append("")
            lines.append("### Chain Steps")
            lines.append(f"1. **Entry:** {source['category']} — {source['title']} ({source['severity']})")
            lines.append(f"2. **Pivot:** {pivot['category']} — {pivot['title']} ({pivot['severity']})")
            lines.append(f"3. **Sink:** {sink['category']} — {sink['title']} ({sink['severity']})")
            lines.append("")
            lines.append("### Description")
            lines.append(
                f"An attacker can exploit the {source['category']} vulnerability to "
                f"trigger a {pivot['category']} weakness, ultimately leading to a "
                f"{sink['category']} compromise."
            )
            lines.append("")
            lines.append(f"### Impact")
            lines.append(chain["impact"])
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines).strip()

    @staticmethod
    def _build_chain(source: Finding, pivot: Finding, sink: Finding) -> Dict[str, Any]:
        severity_weights = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}
        s_w = severity_weights.get(source.severity.lower(), 5)
        p_w = severity_weights.get(pivot.severity.lower(), 5)
        k_w = severity_weights.get(sink.severity.lower(), 5)
        risk_score = round((s_w + p_w + k_w) / 3, 1)

        return {
            "source": {
                "title": source.title,
                "category": source.category,
                "severity": source.severity,
                "finding_id": source.finding_id,
            },
            "pivot": {
                "title": pivot.title,
                "category": pivot.category,
                "severity": pivot.severity,
                "finding_id": pivot.finding_id,
            },
            "sink": {
                "title": sink.title,
                "category": sink.category,
                "severity": sink.severity,
                "finding_id": sink.finding_id,
            },
            "risk_score": risk_score,
            "impact": (
                f"An attacker chains {source.category} → {pivot.category} → {sink.category} "
                f"to achieve a combined risk score of {risk_score}/10."
            ),
        }

    @staticmethod
    def _estimate_impact(categories: List[str]) -> str:
        if "rce" in categories or "full_compromise" in categories:
            return "Complete system compromise"
        if "admin_access" in categories or "privilege_escalation" in categories:
            return "Unauthorized administrative access"
        if "data_exfiltration" in categories:
            return "Sensitive data exfiltration"
        if "ato" in categories:
            return "Account takeover"
        return "Significant security breach"
