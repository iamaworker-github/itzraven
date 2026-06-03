"""
Generate segregated .md skill files from claudskills.com security skills catalog.
- Filters out Chinese-language skills
- Organizes by subcategory directories
- Creates proper YAML frontmatter for SkillsEngine compatibility
"""
import json
import re
import os
import sys
from pathlib import Path
from collections import Counter

SKILLS_DIR = Path(__file__).parent.parent / "itzraven" / "skills" / "claudskills"
JSON_PATH = Path(__file__).parent.parent / "security_skills.json"

CHINESE_PATTERN = re.compile(r'[\u4e00-\u9fff\u3400-\u4dbf]')

# Map claudskills subcategories to pentest-relevant categories
PENTEST_CATEGORY_MAP = {
    "web-security": "web-security",
    "network-security": "network-security",
    "red-team": "red-team",
    "appsec-tools": "appsec",
    "appsec-build": "appsec",
    "threat-hunting": "threat-hunting",
    "identity-access": "identity-access",
    "compliance": "compliance",
    "malware-analysis": "malware-analysis",
    "forensics": "forensics",
    "cloud-security": "cloud-security",
    "crypto-keymgmt": "cryptography",
    "zero-trust": "zero-trust",
    "incident-response": "incident-response",
    "ot-ics-security": "ot-security",
    "security-misc": "security",
}


def is_chinese(text: str) -> bool:
    matches = CHINESE_PATTERN.findall(text)
    if not matches:
        return False
    ratio = len(matches) / max(len(text), 1)
    return ratio > 0.15


def slug_to_name(slug: str) -> str:
    name = slug.replace("-", " ").replace("_", " ").title()
    return name


def generate_skills():
    if not JSON_PATH.exists():
        print(f"ERROR: {JSON_PATH} not found. Download security_skills.json first.")
        sys.exit(1)

    with open(JSON_PATH) as f:
        data = json.load(f)

    print(f"Total skills in JSON: {len(data)}")

    filtered = []
    chinese_skipped = 0
    for s in data:
        name = s.get("name", "")
        desc = s.get("description", "")
        if is_chinese(name) or is_chinese(desc):
            chinese_skipped += 1
            continue
        filtered.append(s)

    print(f"Chinese skills skipped: {chinese_skipped}")
    print(f"Non-Chinese skills: {len(filtered)}")

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)

    subcat_counts = Counter()
    total_generated = 0

    for s in filtered:
        subcategory = s.get("subcategory", "security-misc")
        sub_dir = SKILLS_DIR / subcategory
        sub_dir.mkdir(parents=True, exist_ok=True)

        slug = s.get("slug", "unnamed")
        name = s.get("name", slug)
        description = s.get("description", "")
        tags = s.get("tags", [])
        source_url = s.get("source_url", "")
        author = s.get("author", "")
        license_val = s.get("license", "")
        category = PENTEST_CATEGORY_MAP.get(subcategory, "security")

        # Determine if this skill is highly relevant for pentesting
        pentest_keywords = [
            "exploit", "vulnerability", "injection", "sqli", "xss", "ssrf",
            "csrf", "rce", "lfi", "rfi", "pentest", "penetration", "red team",
            "buffer overflow", "privilege escalation", "idor", "auth bypass",
            "authentication", "owasp", "malware", "reverse engineering",
            "forensic", "sqlmap", "nmap", "burp", "metasploit", "cve",
            "zero day", "phishing", "social engineering", "wireless",
            "cloud security", "container escape", "k8s security",
            "api security", "graphql", "jwt", "oauth", "saml",
        ]
        desc_lower = description.lower()
        name_lower = name.lower()
        relevance_score = sum(
            1 for kw in pentest_keywords
            if kw in desc_lower or kw in name_lower
        )

        content_parts = [f"# {name}\n"]
        content_parts.append(f"\n## Description\n{description}\n")
        if tags:
            content_parts.append(f"\n## Tags\n{', '.join(tags)}\n")
        if source_url:
            content_parts.append(f"\n## Source\n{source_url}\n")
        content_parts.append(f"\n## Relevance Score\n{relevance_score}\n")

        tags_yaml = json.dumps(tags) if tags else "[]"

        frontmatter = (
            "---\n"
            f'name: "{name}"\n'
            f'description: "{description[:200].replace(chr(34), chr(39))}"\n'
            f"category: {category}\n"
            f"subcategory: {subcategory}\n"
            f"tags: {tags_yaml}\n"
            f"relevance: {relevance_score}\n"
            f"source: \"{source_url}\"\n"
            f'author: "{author}"\n'
            f'license: "{license_val}"\n'
            "---\n"
        )

        md_content = frontmatter + "\n".join(content_parts)

        filepath = sub_dir / f"{slug}.md"
        filepath.write_text(md_content, encoding="utf-8")
        subcat_counts[subcategory] += 1
        total_generated += 1

    print(f"\n=== Generation Complete ===")
    print(f"Total .md files generated: {total_generated}")
    print(f"\nBy subcategory:")
    for subcat, count in sorted(subcat_counts.items(), key=lambda x: -x[1]):
        dir_path = SKILLS_DIR / subcat
        print(f"  {subcat}: {count} files ({dir_path})")


if __name__ == "__main__":
    generate_skills()
