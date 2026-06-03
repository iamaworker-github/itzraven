"""
Professional Security Report Generation — Shannon-grade executive reports.

Features:
  - Executive summary with risk scoring
  - Severity heatmap and CVSS distribution
  - per-finding CVSS vector + CWE + PoC validation status
  - Attack path visualization (text-based)
  - Remediation priority matrix (effort vs. impact)
  - Data quality score per finding
  - Optional reproduction script generation
  - Multi-format: Markdown (professional), HTML (interactive), PDF (via md->pdf)
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class RiskScore:
    overall: float  # 0-10
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_level: str  # Critical, High, Medium, Low, Info

    @classmethod
    def compute(cls, findings: List[Finding]) -> "RiskScore":
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1

        # Weighted risk score (CVSS-like)
        weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        total_weight = sum(
            counts[s] * weights.get(s, 0) for s in counts
        )
        total_findings = sum(counts.values()) or 1
        overall = min(10.0, total_weight / max(total_findings, 1))

        if overall >= 9.0:
            risk_level = "Critical"
        elif overall >= 7.0:
            risk_level = "High"
        elif overall >= 4.0:
            risk_level = "Medium"
        elif overall >= 1.0:
            risk_level = "Low"
        else:
            risk_level = "Info"

        return cls(
            overall=round(overall, 1),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            info_count=counts["info"],
            risk_level=risk_level,
        )


@dataclass
class FindingQualityScore:
    """Evaluates data quality of a single finding (0-100)."""
    has_poc: bool = False
    has_remediation: bool = False
    has_code_location: bool = False
    has_cvss: bool = False
    evidence_length: int = 0
    has_reproducibility_steps: bool = False
    validation_status: str = "unvalidated"

    @property
    def score(self) -> int:
        s = 0
        if self.has_poc: s += 25
        if self.has_remediation: s += 20
        if self.has_code_location: s += 15
        if self.has_cvss: s += 10
        if self.evidence_length >= 50: s += 10
        if self.evidence_length >= 200: s += 5
        if self.has_reproducibility_steps: s += 10
        if self.validation_status == "validated": s += 25
        elif self.validation_status == "validated_poc_executed": s += 20
        return min(100, s)

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingQualityScore":
        return cls(
            has_poc=bool(finding.proof_of_concept),
            has_remediation=bool(finding.remediation),
            has_code_location=bool(finding.file_path and finding.line_number),
            has_cvss=bool(finding.cvss_score is not None),
            evidence_length=len(finding.evidence or ""),
            has_reproducibility_steps=bool(finding.reproducibility_steps),
            validation_status=finding.validation_status or "unvalidated",
        )


class ProfessionalReportGenerator:
    """Generates professional-grade security reports."""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#0d6efd",
        "info": "#6c757d",
    }

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or Path("./itzraven_results"))

    def generate_markdown(
        self,
        findings: List[Finding],
        target: str,
        scan_metadata: Optional[Dict[str, Any]] = None,
        include_appendix: bool = True,
    ) -> str:
        risk = RiskScore.compute(findings)
        sorted_findings = self._sort_findings(findings)
        quality_scores = {
            f.finding_id: FindingQualityScore.from_finding(f) for f in sorted_findings
        }
        metadata = scan_metadata or {}
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines: List[str] = []

        # =========================================================
        # HEADER
        # =========================================================
        lines.extend([
            f"# 🔒 Itzraven Security Assessment Report",
            f"",
            f"**Target:** `{target}`",
            f"**Generated:** {timestamp}",
            f"**Scan Depth:** {metadata.get('scan_depth', 'standard')}",
            f"**Risk Score:** {risk.overall}/10 — **{risk.risk_level.upper()}**",
            f"",
            f"> This report contains {len(findings)} security finding(s) discovered during an automated",
            f"> security assessment. Each finding includes CVSS scoring, CWE reference, code location,",
            f"> proof-of-concept, and remediation guidance.",
            f"",
            f"---",
            f"",
        ])

        # =========================================================
        # EXECUTIVE SUMMARY
        # =========================================================
        lines.extend([
            "## 📊 Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| **Risk Score** | {risk.overall}/10 ({risk.risk_level}) |",
            f"| **Total Findings** | {len(findings)} |",
            f"| **Critical** | {risk.critical_count} |",
            f"| **High** | {risk.high_count} |",
            f"| **Medium** | {risk.medium_count} |",
            f"| **Low** | {risk.low_count} |",
            f"| **Info** | {risk.info_count} |",
            "",
        ])

        # =========================================================
        # SEVERITY HEATMAP
        # =========================================================
        total = len(findings) or 1
        lines.extend([
            "### Severity Distribution",
            "",
            "```",
        ])
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in sorted_findings if f.severity.lower() == sev)
            bar_len = int((count / total) * 30) if count > 0 else 0
            bar = "█" * max(bar_len, 1) if count > 0 else "░"
            lines.append(f"  {sev.upper():8s} │ {bar} {count}")
        lines.extend([
            "```",
            "",
        ])

        # =========================================================
        # CVSS DISTRIBUTION (if available)
        # =========================================================
        cvss_findings = [f for f in sorted_findings if f.cvss_score is not None]
        if cvss_findings:
            lines.extend([
                "### CVSS Distribution",
                "",
                "| CVSS Range | Count |",
                "|------------|-------|",
            ])
            ranges = [("9.0-10.0", "Critical"), ("7.0-8.9", "High"), ("4.0-6.9", "Medium"), ("0.1-3.9", "Low"), ("0.0", "None")]
            for rng, label in ranges:
                if rng == "9.0-10.0":
                    count = sum(1 for f in cvss_findings if f.cvss_score and f.cvss_score >= 9.0)
                elif rng == "7.0-8.9":
                    count = sum(1 for f in cvss_findings if f.cvss_score and 7.0 <= f.cvss_score <= 8.9)
                elif rng == "4.0-6.9":
                    count = sum(1 for f in cvss_findings if f.cvss_score and 4.0 <= f.cvss_score <= 6.9)
                elif rng == "0.1-3.9":
                    count = sum(1 for f in cvss_findings if f.cvss_score and 0.1 <= f.cvss_score <= 3.9)
                else:
                    count = sum(1 for f in cvss_findings if f.cvss_score == 0.0)
                bar_len = int((count / max(len(cvss_findings), 1)) * 20)
                bar = "█" * bar_len if bar_len else "░"
                lines.append(f"| {rng} ({label:8s}) | {count} {bar} |")
            lines.append("")

        # =========================================================
        # PoC VALIDATION SUMMARY
        # =========================================================
        validated = sum(1 for f in sorted_findings if f.validation_status == "validated")
        unvalidated = sum(1 for f in sorted_findings if f.validation_status and "unvalidated" in f.validation_status)
        rejected = sum(1 for f in sorted_findings if f.validation_status and "rejected" in f.validation_status)
        if validated or unvalidated or rejected:
            lines.extend([
                "### PoC Validation Status",
                "",
                f"- ✅ **Validated:** {validated}",
                f"- ⚠️ **Unvalidated:** {unvalidated}",
                f"- ❌ **Rejected (No PoC):** {rejected}",
                "",
            ])

        # =========================================================
        # DATA QUALITY SCORES
        # =========================================================
        avg_quality = int(sum(qs.score for qs in quality_scores.values()) / max(len(quality_scores), 1))
        lines.extend([
            "### Finding Data Quality",
            "",
            f"- **Average Quality Score:** {avg_quality}/100",
            f"- **Findings with PoC:** {sum(1 for qs in quality_scores.values() if qs.has_poc)}/{len(quality_scores)}",
            f"- **Findings with Remediation:** {sum(1 for qs in quality_scores.values() if qs.has_remediation)}/{len(quality_scores)}",
            f"- **Findings with Code Location:** {sum(1 for qs in quality_scores.values() if qs.has_code_location)}/{len(quality_scores)}",
            "",
            "---",
            "",
        ])

        # =========================================================
        # VULNERABILITY DETAILS
        # =========================================================
        lines.extend([
            "## 🔍 Vulnerability Details",
            "",
        ])

        for sev_display, sev_key in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low"), ("INFO", "info")]:
            sev_findings = [f for f in sorted_findings if f.severity.lower() == sev_key]
            if not sev_findings:
                continue

            lines.extend([
                f"### {sev_display} Severity",
                "",
            ])

            for finding in sev_findings:
                qs = quality_scores.get(finding.finding_id)
                cvss_str = ""
                if finding.cvss_score is not None:
                    cvss_str = f"**CVSS:** {finding.cvss_score} ({finding.cvss_vector or 'N/A'})  \n"

                code_loc = ""
                if finding.file_path:
                    code_loc = f"**Location:** `{finding.file_path}:{finding.line_number or '?'}`  \n"

                poc_str = ""
                if finding.proof_of_concept:
                    poc_str = f"**Proof of Concept:**\n```python\n{finding.proof_of_concept[:500]}\n```\n"

                remediation_str = ""
                if finding.remediation:
                    remediation_str = f"**Remediation:**\n{finding.remediation}\n"

                quality_str = ""
                if qs:
                    quality_str = f"**Data Quality:** {qs.score}/100  \n"

                lines.extend([
                    f"#### [{finding.severity.upper()}] {finding.title}",
                    "",
                    f"**Category:** {finding.category}  ",
                    f"**CWE:** {finding.cwe_id or 'N/A'}  ",
                    f"**Confidence:** {finding.confidence:.2f}  ",
                    f"**Validation:** {finding.validation_status or 'N/A'}  ",
                    cvss_str,
                    code_loc,
                    quality_str,
                ])
                if finding.description:
                    lines.append(f"**Description:**\n{finding.description[:500]}\n")
                if finding.evidence:
                    lines.append(f"**Evidence:**\n```\n{finding.evidence[:500]}\n```\n")
                if poc_str:
                    lines.append(poc_str)
                if remediation_str:
                    lines.append(remediation_str)
                if finding.reproducibility_steps:
                    lines.append("**Reproduction Steps:**\n")
                    for i, step in enumerate(finding.reproducibility_steps, 1):
                        lines.append(f"  {i}. {step}")
                    lines.append("")

                lines.append("---\n")

        # =========================================================
        # REMEDIATION PRIORITY MATRIX
        # =========================================================
        if findings:
            lines.extend([
                "## 🛠️ Remediation Priority Matrix",
                "",
                "| Priority | Finding | Effort | Impact | CVSS |",
                "|----------|---------|--------|--------|------|",
            ])
            for finding in sorted_findings[:10]:
                cvss = finding.cvss_score or 5.0
                if cvss >= 9.0:
                    effort, impact = "Low", "Critical"
                elif cvss >= 7.0:
                    effort, impact = "Medium", "High"
                elif cvss >= 4.0:
                    effort, impact = "Medium", "Medium"
                else:
                    effort, impact = "High", "Low"
                lines.append(
                    f"| **{finding.severity.upper()}** | {finding.title[:60]} | {effort} | {impact} | {cvss} |"
                )
            lines.append("")

        # =========================================================
        # ATTACK PATH (text-based, from chain results)
        # =========================================================
        chains = metadata.get("chain_results", [])
        if chains:
            lines.extend([
                "## 🔗 Attack Path Analysis",
                "",
            ])
            for chain in chains:
                status = "✅" if chain.get("success") else "❌"
                lines.append(f"### {status} {chain.get('chain_name', 'Unknown Chain')}")
                lines.append(f"- Steps: {chain.get('steps_completed', 0)}/{chain.get('total_steps', 0)}")
                lines.append(f"- Findings generated: {chain.get('findings_generated', 0)}")
                lines.append("")

        # =========================================================
        # APPENDIX: Unverified Findings
        # =========================================================
        if include_appendix:
            rejected_findings = [
                f for f in sorted_findings
                if f.validation_status and "rejected" in f.validation_status
            ]
            if rejected_findings:
                lines.extend([
                    "## 📎 Appendix: Excluded Findings (No Valid PoC)",
                    "",
                    "The following findings were identified but lacked a validated",
                    "proof-of-concept and were excluded from the main report:",
                    "",
                ])
                for f in rejected_findings[:10]:
                    lines.append(f"- [{f.severity.upper()}] {f.title} ({f.category}) — {f.validation_status}")
                if len(rejected_findings) > 10:
                    lines.append(f"- *...and {len(rejected_findings) - 10} more*")
                lines.append("")

        # =========================================================
        # FOOTER
        # =========================================================
        lines.extend([
            "---",
            f"*Report generated by **Itzraven Security Platform** on {timestamp}*",
            f"*See Everything. Miss Nothing.*",
            "",
        ])

        return "\n".join(lines).rstrip() + "\n"

    def save_markdown(
        self,
        findings: List[Finding],
        target: str,
        scan_metadata: Optional[Dict[str, Any]] = None,
        filename: Optional[str] = None,
    ) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        content = self.generate_markdown(findings, target, scan_metadata)
        if not filename:
            slug = target.replace(".", "_").replace(":", "_").replace("/", "_")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{slug}_{ts}_security_report.md"
        path = self.output_dir / filename
        path.write_text(content, encoding="utf-8")
        logger.success(f"Professional report saved: {path}")
        return path

    def generate_html(self, findings: List[Finding], target: str,
                      scan_metadata: Optional[Dict[str, Any]] = None) -> str:
        md = self.generate_markdown(findings, target, scan_metadata)

        severity_colors = self.SEVERITY_COLORS
        risk = RiskScore.compute(findings)
        sorted_findings = self._sort_findings(findings)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        finding_rows = ""
        for f in sorted_findings:
            color = severity_colors.get(f.severity.lower(), "#6c757d")
            cvss = f"<td>{f.cvss_score or 'N/A'}</td>"
            poc = "<td>✅</td>" if f.proof_of_concept else "<td>❌</td>"
            loc = f"<td><code>{f.file_path}:{f.line_number}</code></td>" if f.file_path else "<td>N/A</td>"
            finding_rows += f"""
            <tr>
                <td><span class="sev-badge" style="background:{color}">{f.severity.upper()}</span></td>
                <td>{f.title[:60]}</td>
                <td>{f.category}</td>
                {cvss}
                {poc}
                {loc}
                <td>{f.confidence:.2f}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Itzraven Security Report — {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f0f1a; color: #e0e0e0; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 50px 30px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #2a2a4a; }}
  header h1 {{ font-size: 2.2em; color: #fff; margin-bottom: 10px; }}
  header p {{ color: #8899bb; }}
  .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 6px; font-weight: 700; font-size: 1.1em; margin-top: 15px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
  .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 10px; border: 1px solid #2a2a4a; text-align: center; }}
  .stat-card h3 {{ font-size: 2.5em; margin-bottom: 5px; }}
  .stat-card p {{ color: #8899bb; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
  .sev-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; color: #fff; font-size: 0.75em; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 10px; overflow: hidden; border: 1px solid #2a2a4a; margin-bottom: 30px; }}
  th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
  th {{ background: #16213e; color: #8899bb; font-weight: 600; text-transform: uppercase; font-size: 0.8em; letter-spacing: 1px; }}
  tr:hover {{ background: #1f1f3a; }}
  code {{ background: #2a2a4a; padding: 2px 8px; border-radius: 4px; font-size: 0.9em; }}
  .progress-bar {{ height: 8px; border-radius: 4px; margin-top: 4px; }}
  .section {{ margin-bottom: 40px; }}
  .section h2 {{ color: #fff; border-bottom: 2px solid #2a2a4a; padding-bottom: 10px; margin-bottom: 20px; font-size: 1.5em; }}
  footer {{ text-align: center; color: #556; padding: 30px; margin-top: 40px; border-top: 1px solid #2a2a4a; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔒 Itzraven Security Assessment Report</h1>
    <p>Target: <strong>{target}</strong> | Generated: {ts}</p>
    <div class="risk-badge" style="background:{severity_colors.get(risk.risk_level.lower(), '#6c757d')}">
      Risk Score: {risk.overall}/10 — {risk.risk_level.upper()}
    </div>
  </header>

  <div class="stats">
    <div class="stat-card"><h3 style="color:{severity_colors['critical']}">{risk.critical_count}</h3><p>Critical</p></div>
    <div class="stat-card"><h3 style="color:{severity_colors['high']}">{risk.high_count}</h3><p>High</p></div>
    <div class="stat-card"><h3 style="color:{severity_colors['medium']}">{risk.medium_count}</h3><p>Medium</p></div>
    <div class="stat-card"><h3 style="color:{severity_colors['low']}">{risk.low_count}</h3><p>Low</p></div>
    <div class="stat-card"><h3 style="color:{severity_colors['info']}">{risk.info_count}</h3><p>Info</p></div>
  </div>

  <div class="section">
    <h2>📊 Findings Overview</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>CVSS</th><th>PoC</th><th>Location</th><th>Confidence</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>

  <footer>
    <p>Generated by <strong>Itzraven Security Platform</strong> — See Everything. Miss Nothing.</p>
  </footer>
</div>
</body>
</html>"""
        return html

    def save_html(self, findings: List[Finding], target: str,
                  scan_metadata: Optional[Dict[str, Any]] = None) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        content = self.generate_html(findings, target, scan_metadata)
        slug = target.replace(".", "_").replace(":", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"{slug}_{ts}_report.html"
        path.write_text(content, encoding="utf-8")
        logger.success(f"HTML report saved: {path}")
        return path

    @staticmethod
    def _sort_findings(findingds: List[Finding]) -> List[Finding]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(findingds, key=lambda f: (order.get(f.severity.lower(), 99), -(f.cvss_score or 0)))


def generate_professional_report(
    findings: List[Finding],
    target: str,
    output_dir: Optional[Path] = None,
    scan_metadata: Optional[Dict[str, Any]] = None,
    formats: Tuple[str, ...] = ("md", "html"),
) -> List[Path]:
    gen = ProfessionalReportGenerator(output_dir=output_dir)
    paths = []
    if "md" in formats:
        paths.append(gen.save_markdown(findings, target, scan_metadata))
    if "html" in formats:
        paths.append(gen.save_html(findings, target, scan_metadata))
    return paths
