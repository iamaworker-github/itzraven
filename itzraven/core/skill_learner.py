"""
ItzravenSkillLearner — Self-improving skill system.
Automatically generates new skills from successful findings.
Hermes-inspired: skills get better the more they're used.
"""
import asyncio
import json
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from itzraven.core.logger import get_logger
from itzraven.core.memory import get_memory

logger = get_logger()

SKILLS_LEARNED_DIR = Path(__file__).parent.parent.parent / "itzraven" / "skills" / "learned"
TEMPLATE = """---
name: "{name}"
description: "{description}"
category: {category}
tags: [{tags}]
relevance: 9
source: "auto-generated from finding"
---

# {name}

## Description
{description}

## Technique
{technique}

## Payload
```
{payload}
```

## Remediation
{remediation}

## Auto-Generated
This skill was automatically created from a real finding during pentesting.
"""


class SkillLearner:
    def __init__(self):
        self.memory = get_memory()
        SKILLS_LEARNED_DIR.mkdir(parents=True, exist_ok=True)
        self._learned_names: set = set()
        self._load_existing()

    def _load_existing(self):
        for f in SKILLS_LEARNED_DIR.glob("*.md"):
            self._learned_names.add(f.stem)

    def learn_from_finding(self, finding: Dict[str, Any]) -> Optional[str]:
        title = finding.get("title", "")
        severity = finding.get("severity", "info")
        category = finding.get("category", "general")
        evidence = finding.get("evidence", "")
        poc = finding.get("proof_of_concept", "")
        remediation = finding.get("remediation", "")
        agent = finding.get("agent_name", "unknown")

        if severity.lower() not in ("critical", "high"):
            return None

        name = self._slugify(title)
        if name in self._learned_names:
            return self._increment_usage(name)

        tags = f'"auto-learned", "{category}", "{severity}"'
        content = TEMPLATE.format(
            name=name,
            description=f"Auto-generated skill from {agent}: {title}",
            category=category,
            tags=tags,
            technique=evidence[:500],
            payload=poc[:300],
            remediation=remediation[:300],
        )

        filepath = SKILLS_LEARNED_DIR / f"{name}.md"
        filepath.write_text(content)
        self._learned_names.add(name)

        self.memory.record_technique(
            technique_name=name,
            category=category,
            description=title,
            payload=poc,
        )

        logger.info(f"🧠 Learned new skill: {name} from {title}")
        return name

    def _increment_usage(self, name: str) -> str:
        filepath = SKILLS_LEARNED_DIR / f"{name}.md"
        if filepath.exists():
            content = filepath.read_text()
            content = re.sub(r"(usage_count:\s*)(\d+)", lambda m: f"{m.group(1)}{int(m.group(2)) + 1}", content)
            filepath.write_text(content)
        from itzraven.core.memory import get_memory
        mem = get_memory()
        mem_path = mem.db_path
        if mem_path.exists():
            try:
                import sqlite3
                conn = sqlite3.connect(str(mem_path))
                conn.execute(
                    "UPDATE skills_learned SET usage_count = usage_count + 1 WHERE skill_name = ?",
                    (name,),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
        return name

    def _slugify(self, title: str) -> str:
        name = title.lower()
        name = re.sub(r"[^a-z0-9]+", "-", name)
        name = name.strip("-")
        name = name[:80]
        slug = f"learned-{name}"
        return slug

    async def learn_from_h1_disclosures(self, max_reports: int = 20) -> int:
        """Fetch latest HackerOne disclosed reports from HuggingFace dataset,
        extract vulnerability patterns and auto-generate new skills.

        Uses curl to fetch the HuggingFace dataset viewer API for
        'trufflesecurity/hackerone_vulnerability_reports'.
        Returns the number of new skills generated.
        """
        hf_api = "https://huggingface.co/api/datasets/trufflesecurity/hackerone_vulnerability_reports/parquet/default/train"
        count = 0
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-L", "-H", "Accept: application/json",
                f"{hf_api}?rows={max_reports}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data = json.loads(stdout.decode())

            rows = []
            if isinstance(data, dict):
                rows = data.get("rows", [])
            elif isinstance(data, list):
                rows = data[:max_reports]

            for row in rows:
                try:
                    if isinstance(row, dict) and "row" in row:
                        row = row["row"]
                    title = row.get("title", "") or row.get("vulnerability_information", "") or ""
                    weakness = row.get("weakness", {}).get("name", "") if isinstance(row.get("weakness"), dict) else ""
                    severity = row.get("severity", "high")
                    remediation = row.get("remediation", "") or ""
                    payload = row.get("payload", "") or row.get("proof_of_concept", "") or ""

                    if not title:
                        continue
                    if severity not in ("critical", "high", "medium"):
                        continue

                    name = self._slugify(f"h1-{title[:60]}")
                    if name in self._learned_names:
                        continue

                    tags = f'"h1-disclosure", "{weakness or 'general'}", "{severity}"'
                    content = TEMPLATE.format(
                        name=name,
                        description=f"H1 disclosure skill: {title[:200]}",
                        category=weakness or "general",
                        tags=tags,
                        technique=f"Vulnerability type: {weakness}\nTitle: {title[:500]}",
                        payload=payload[:300] or "See H1 disclosure for PoC",
                        remediation=remediation[:300] or "Refer to HackerOne disclosed report",
                    )

                    filepath = SKILLS_LEARNED_DIR / f"{name}.md"
                    filepath.write_text(content)
                    self._learned_names.add(name)
                    count += 1
                    logger.info(f"📚 Learned skill from H1 disclosure: {name}")
                except Exception as exc:
                    logger.debug(f"Failed to process H1 report: {exc}")
                    continue
        except Exception as exc:
            logger.warning(f"H1 disclosure fetch failed: {exc}")

        logger.info(f"H1 skill generator: generated {count} new skills from {max_reports} disclosures")
        return count

    def get_all_learned(self) -> List[Dict]:
        results = []
        for f in SKILLS_LEARNED_DIR.glob("*.md"):
            results.append({"name": f.stem, "path": str(f), "created": datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
        return results


_learner_instance: Optional[SkillLearner] = None


def get_skill_learner() -> SkillLearner:
    global _learner_instance
    if _learner_instance is None:
        _learner_instance = SkillLearner()
    return _learner_instance
