import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import Finding

logger = get_logger()


class ReportGenerator:
    """Generates security scan reports in JSON (SARIF), Markdown, and HTML formats."""

    def __init__(self, output_dir: Optional[Path] = None):
        config = get_config()
        self.output_dir = Path(output_dir or config.get("output_dir") or "./itzraven_results")

    def save_report(self, findings: List[Finding], target: str,
                    format: str = "json", template: Optional[str] = None) -> Path:
        """Generate and save a report in the specified format.

        Args:
            findings: List of Finding objects
            target: The scan target (URL, domain, IP, etc.)
            format: One of 'sarif', 'json', 'markdown', 'md', 'html'
            template: Optional markdown template path or preset name

        Returns:
            Path to the saved report file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        target_slug = target.replace(".", "_").replace(":", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        format = format.lower()
        if format in ("sarif", "json"):
            data = self.generate_sarif(findings, target)
            ext = "sarif" if format == "sarif" else "json"
            file_path = self.output_dir / f"{target_slug}_{timestamp}.{ext}"
            file_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

        elif format in ("markdown", "md"):
            content = self.generate_markdown(findings, target, template)
            file_path = self.output_dir / f"{target_slug}_{timestamp}.md"
            file_path.write_text(content, encoding="utf-8")

        elif format == "html":
            content = self.generate_html(findings, target)
            file_path = self.output_dir / f"{target_slug}_{timestamp}.html"
            file_path.write_text(content, encoding="utf-8")

        else:
            raise ValueError(f"Unsupported report format: {format}. Supported: sarif, json, markdown, md, html")

        logger.success(f"Report saved: {file_path}")
        return file_path

    def generate_sarif(self, findings: List[Finding], target: str) -> Dict[str, Any]:
        """Generate a SARIF v2.1.0 compliant report."""
        sarif_runs = []
        run = {
            "tool": {
                "driver": {
                    "name": "Itzraven",
                    "version": "2.0.0",
                    "informationUri": "https://opencode.ai",
                    "rules": [],
                }
            },
            "results": [],
            "artifacts": [],
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now().isoformat(),
            }],
        }

        rule_ids: Dict[str, int] = {}
        rules_list = []

        for finding in findings:
            rule_id = f"{finding.category}/{finding.severity}"
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rule_ids)
                rules_list.append({
                    "id": rule_id,
                    "name": finding.category.replace("_", " ").title(),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": self._sarif_level(finding.severity)},
                    "helpUri": "",
                    "properties": {
                        "severity": finding.severity,
                        "category": finding.category,
                        "confidence": finding.confidence,
                    },
                })

            result = {
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "message": {"text": finding.title},
                "level": self._sarif_level(finding.severity),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target,
                        },
                        "region": {
                            "snippet": {"text": finding.evidence[:200]},
                        },
                    }
                }],
                "properties": {
                    "severity": finding.severity,
                    "category": finding.category,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation or "",
                    "confidence": finding.confidence,
                },
            }
            if finding.proof_of_concept:
                result["properties"]["proof_of_concept"] = finding.proof_of_concept

            run["results"].append(result)

        run["tool"]["driver"]["rules"] = rules_list
        sarif_runs.append(run)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": sarif_runs,
        }

    def generate_markdown(self, findings: List[Finding], target: str,
                          template: Optional[str] = None) -> str:
        """Generate a Markdown report. Optionally use a template file."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 99))

        lines: List[str] = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if template:
            template_path = Path(template)
            if template_path.exists():
                try:
                    tpl = template_path.read_text(encoding="utf-8")
                    lines = self._render_template(tpl, findings, target, timestamp)
                    return "\n".join(lines)
                except Exception as e:
                    logger.warning(f"Template load failed: {e}. Using default template.")

        lines.extend([
            f"# Itzraven Security Scan Report",
            f"",
            f"- **Target:** `{target}`",
            f"- **Generated:** {timestamp}",
            f"- **Total Findings:** {len(findings)}",
            f"",
        ])

        severity_counts = {}
        for f in sorted_findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts:
            lines.extend(["## Summary", ""])
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    lines.append(f"- **{sev.upper()}**: {count}")
            lines.append("")

        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in sorted_findings if f.severity.lower() == sev]
            if not sev_findings:
                continue
            lines.extend([f"## {sev.upper()} Severity Findings", ""])
            for finding in sev_findings:
                lines.extend([
                    f"### {finding.title}",
                    f"",
                    f"- **Category:** {finding.category}",
                    f"- **Confidence:** {finding.confidence:.2f}",
                    f"- **Evidence:** `{finding.evidence[:300]}`",
                ])
                if finding.proof_of_concept:
                    lines.append(f"- **PoC:** `{finding.proof_of_concept[:200]}`")
                if finding.remediation:
                    lines.append(f"- **Remediation:** {finding.remediation}")
                lines.append("")

        lines.extend([
            "---",
            f"_Generated by Itzraven on {timestamp}_",
            "",
        ])

        return "\n".join(lines)

    def generate_html(self, findings: List[Finding], target: str) -> str:
        """Generate an HTML report."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 99))

        severity_counts = {}
        for f in sorted_findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#0d6efd",
            "info": "#6c757d",
        }

        findings_rows = ""
        for finding in sorted_findings:
            color = severity_colors.get(finding.severity.lower(), "#6c757d")
            poc = f"<code>{finding.proof_of_concept[:200]}</code>" if finding.proof_of_concept else ""
            remediation = f"<p><strong>Remediation:</strong> {finding.remediation}</p>" if finding.remediation else ""
            findings_rows += f"""
            <tr>
                <td><span class="badge" style="background:{color}">{finding.severity.upper()}</span></td>
                <td>{finding.title}</td>
                <td>{finding.category}</td>
                <td>{finding.confidence:.2f}</td>
                <td><code>{finding.evidence[:200]}</code></td>
                <td>{poc}</td>
                <td>{remediation}</td>
            </tr>"""

        summary_rows = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            color = severity_colors.get(sev, "#6c757d")
            bar_width = (count / max(len(findings), 1)) * 100
            summary_rows += f"""
            <tr>
                <td><strong style="color:{color}">{sev.upper()}</strong></td>
                <td>{count}</td>
                <td><div class="progress-bar" style="width:{bar_width:.1f}%;background:{color}"></div></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Itzraven Security Report — {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #212529; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px 20px; text-align: center; border-radius: 8px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2em; margin-bottom: 5px; }}
        header p {{ color: #aaa; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card h3 {{ font-size: 2em; margin-bottom: 5px; }}
        .stat-card p {{ color: #666; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f1f3f5; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: 600; }}
        .progress-bar {{ height: 20px; border-radius: 4px; min-width: 2px; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; word-break: break-all; }}
        .summary-table {{ margin-bottom: 30px; }}
        footer {{ text-align: center; color: #666; padding: 20px; margin-top: 30px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Itzraven Security Scan Report</h1>
            <p>Target: <strong>{target}</strong> | Generated: {timestamp} | Findings: <strong>{len(findings)}</strong></p>
        </header>

        <div class="stats">
            <div class="stat-card" style="border-top: 3px solid #dc3545;">
                <h3 style="color:#dc3545;">{severity_counts.get('critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card" style="border-top: 3px solid #fd7e14;">
                <h3 style="color:#fd7e14;">{severity_counts.get('high', 0)}</h3>
                <p>High</p>
            </div>
            <div class="stat-card" style="border-top: 3px solid #ffc107;">
                <h3 style="color:#ffc107;">{severity_counts.get('medium', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card" style="border-top: 3px solid #0d6efd;">
                <h3 style="color:#0d6efd;">{severity_counts.get('low', 0)}</h3>
                <p>Low</p>
            </div>
            <div class="stat-card" style="border-top: 3px solid #6c757d;">
                <h3 style="color:#6c757d;">{severity_counts.get('info', 0)}</h3>
                <p>Info</p>
            </div>
        </div>

        <h2>Severity Distribution</h2>
        <table class="summary-table">
            <thead><tr><th>Severity</th><th>Count</th><th>Distribution</th></tr></thead>
            <tbody>{summary_rows}</tbody>
        </table>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Title</th><th>Category</th><th>Confidence</th><th>Evidence</th><th>PoC</th><th>Remediation</th></tr>
            </thead>
            <tbody>{findings_rows}</tbody>
        </table>

        <footer>Generated by <strong>Itzraven</strong> — See Everything. Miss Nothing.</footer>
    </div>
</body>
</html>"""
        return html

    def _sarif_level(self, severity: str) -> str:
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        return mapping.get(severity.lower(), "note")

    def _render_template(self, template: str, findings: List[Finding],
                         target: str, timestamp: str) -> List[str]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 99))

        severity_counts = {}
        for f in sorted_findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        template = template.replace("{{TARGET}}", target)
        template = template.replace("{{TIMESTAMP}}", timestamp)
        template = template.replace("{{TOTAL_FINDINGS}}", str(len(findings)))
        template = template.replace("{{CRITICAL_COUNT}}", str(severity_counts.get("critical", 0)))
        template = template.replace("{{HIGH_COUNT}}", str(severity_counts.get("high", 0)))
        template = template.replace("{{MEDIUM_COUNT}}", str(severity_counts.get("medium", 0)))
        template = template.replace("{{LOW_COUNT}}", str(severity_counts.get("low", 0)))
        template = template.replace("{{INFO_COUNT}}", str(severity_counts.get("info", 0)))

        findings_md = ""
        for finding in sorted_findings:
            poc = f"\n  - PoC: `{finding.proof_of_concept[:200]}`" if finding.proof_of_concept else ""
            remediation = f"\n  - Remediation: {finding.remediation}" if finding.remediation else ""
            findings_md += (
                f"### [{finding.severity.upper()}] {finding.title}\n"
                f"  - Category: {finding.category}\n"
                f"  - Confidence: {finding.confidence}\n"
                f"  - Evidence: {finding.evidence[:300]}"
                f"{poc}{remediation}\n\n"
            )
        template = template.replace("{{FINDINGS}}", findings_md)

        return template.split("\n")
