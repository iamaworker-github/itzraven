"""
SkillRegistry — Fast skill index with O(1) tag-based & category-based lookup.
Pre-indexes all 3417 claudskills + 92 base skills by vulnerability type, tech stack, and category.
"""
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from itzraven.skills.engine import Skill, get_skills_engine
from itzraven.core.logger import get_logger

logger = get_logger()

TAG_INDEX: Dict[str, List[str]] = {
    "sqli": ["sqli", "sql-injection", "sql_injection", "sql injection", "sqlmap"],
    "xss": ["xss", "cross-site", "cross site", "scripting"],
    "ssrf": ["ssrf", "server-side request", "server side request"],
    "command-injection": ["command injection", "cmdi", "rce", "remote code", "code execution"],
    "idor": ["idor", "insecure direct", "access control", "privilege escalation"],
    "auth": ["authentication", "auth bypass", "login bypass", "oauth", "jwt", "session"],
    "xxe": ["xxe", "xml external entity"],
    "csrf": ["csrf", "cross-site request", "cross site request", "xsrf"],
    "path-traversal": ["path traversal", "lfi", "rfi", "directory traversal", "file inclusion"],
    "api": ["api security", "graphql", "rest api", "api testing", "openapi"],
    "cloud": ["cloud", "aws", "azure", "gcp", "s3", "iam", "cloudformation"],
    "container": ["container", "docker", "kubernetes", "k8s", "pod", "cluster"],
    "network": ["network", "port scan", "nmap", "firewall", "dns", "tcp", "udp"],
    "mobile": ["mobile", "android", "ios", "swift", "kotlin"],
    "malware": ["malware", "ransomware", "trojan", "backdoor", "rootkit"],
    "forensics": ["forensic", "memory dump", "disk image", "volatility", "autopsy"],
    "crypto": ["cryptography", "encryption", "tls", "ssl", "cipher", "hash"],
    "osint": ["osint", "recon", "reconnaissance", "subdomain", "whois", "dns enumeration"],
    "compliance": ["compliance", "gdpr", "hipaa", "pci", "sox", "audit"],
    "zero-trust": ["zero trust", "zta", "beyondcorp"],
    "red-team": ["red team", "c2", "command and control", "phishing", "social engineering"],
    "wireless": ["wireless", "wifi", "bluetooth", "rfid"],
    "iot": ["iot", "firmware", "embedded", "smart device"],
    "secret-scan": ["secret", "credentials", "api key", "token leak", "hardcoded"],
    "code-review": ["code review", "static analysis", "sast", "semgrep", "sonarqube"],
    "dep-check": ["dependency", "supply chain", "sbom", "package"],
    "hackerone": ["hackerone", "h1", "bug bounty", "real world", "bounty"],
    "request-smuggling": ["request smuggling", "http smuggling", "cl.te", "te.cl", "cache poison"],
    "prototype-pollution": ["prototype pollution", "proto pollution", "__proto__", "lodash"],
    "business-logic": ["business logic", "logic bug", "logic error", "price manipulation", "rate limiting"],
    "account-takeover": ["account takeover", "ato", "oath", "saml bypass", "password reset"],
    "info-disclosure": ["info disclosure", "information leak", "data leak", "pii", "source code exposure"],
}

CATEGORY_TECH_MAP: Dict[str, List[str]] = {
    "web-security": ["sqli", "xss", "ssrf", "command-injection", "idor", "auth", "xxe", "csrf", "path-traversal", "api", "request-smuggling", "prototype-pollution", "business-logic", "hackerone"],
    "network-security": ["network", "wireless", "iot"],
    "red-team": ["red-team", "phishing", "c2"],
    "identity-access": ["auth", "zero-trust", "secret-scan", "account-takeover", "hackerone"],
    "threat-hunting": ["osint", "forensics", "malware"],
    "appsec": ["code-review", "dep-check", "secret-scan"],
    "cloud-security": ["cloud", "container", "iam"],
    "malware-analysis": ["malware", "forensics"],
    "compliance": ["compliance"],
    "crypto-keymgmt": ["crypto"],
    "forensics": ["forensics"],
    "zero-trust": ["zero-trust"],
    "incident-response": ["forensics", "malware"],
    "ot-ics-security": ["network", "iot"],
}


class SkillRegistry:
    def __init__(self, engine=None):
        self.engine = engine or get_skills_engine()
        self._by_tag: Dict[str, List[Skill]] = defaultdict(list)
        self._by_category: Dict[str, List[Skill]] = defaultdict(list)
        self._by_subcategory: Dict[str, List[Skill]] = defaultdict(list)
        self._tag_to_name: Dict[str, str] = {}
        self._built = False

        for tag, keywords in TAG_INDEX.items():
            for kw in keywords:
                self._tag_to_name[kw] = tag

    def build_index(self) -> int:
        if self._built:
            return len(self.engine._skills_cache)
        self.engine.load_all()
        self.engine.load_claudskills()
        self.engine.load_h1_reports()
        self.engine.load_learned_skills()

        for skill in self.engine._skills_cache.values():
            cat = skill.category
            subcat = skill.metadata.get("subcategory", "")
            self._by_category[cat].append(skill)
            if subcat:
                self._by_subcategory[subcat].append(skill)

            text = (skill.name + " " + skill.description + " " + skill.content[:300]).lower()
            for tag_keywords in TAG_INDEX.values():
                for kw in tag_keywords:
                    if kw in text:
                        self._by_tag[kw].append(skill)
                        break

        self._built = True
        total = len(self.engine._skills_cache)
        logger.info(f"Registry built: {total} skills indexed across {len(self._by_tag)} tag groups")
        return total

    def get_by_tag(self, tag: str, max_count: int = 5) -> List[Skill]:
        self.build_index()
        tag_lower = tag.lower().replace(" ", "-").replace("_", "-")

        # Direct key match in TAG_INDEX
        for group_name, keywords in TAG_INDEX.items():
            if tag_lower == group_name or tag_lower in keywords:
                all_skills = []
                seen_names = set()
                # Collect from all keywords in this tag group
                for kw in keywords:
                    for s in self._by_tag.get(kw, []):
                        if s.name not in seen_names:
                            all_skills.append(s)
                            seen_names.add(s.name)

                def sort_key(s):
                    base = s.metadata.get("relevance", None)
                    if isinstance(base, str):
                        try:
                            base = int(base)
                        except (ValueError, TypeError):
                            base = 0
                    if base is None or not isinstance(base, (int, float)):
                        base = 0
                    bonus = 3 if s.name.startswith("h1-") else 0
                    return (base + bonus, s.name)

                all_skills = sorted(all_skills, key=sort_key, reverse=True)
                return all_skills[:max_count]

        # Fallback: check all indexed keywords
        matched_skills = []
        seen = set()
        for kw, skills in self._by_tag.items():
            if tag_lower in kw or kw in tag_lower:
                for s in skills:
                    if s.name not in seen:
                        matched_skills.append(s)
                        seen.add(s.name)
        if matched_skills:
            matched_skills.sort(key=lambda s: s.metadata.get("relevance", 0) or 0, reverse=True)
            return matched_skills[:max_count]
        return []

    def get_by_category(self, category: str, max_count: int = 8) -> List[Skill]:
        self.build_index()
        cat_lower = category.lower().replace(" ", "-").replace("_", "-")
        skills = self._by_category.get(cat_lower, [])
        if not skills:
            skills = self._by_subcategory.get(cat_lower, [])
        return skills[:max_count]

    def get_by_target_type(self, target_type: str, scan_depth: str = "deep") -> Dict[str, List[Skill]]:
        self.build_index()
        depth_limits = {"quick": 3, "standard": 5, "deep": 8}
        limit = depth_limits.get(scan_depth, 5)

        type_to_tags: Dict[str, List[str]] = {
            "url": ["sqli", "xss", "ssrf", "command-injection", "idor", "auth", "xxe", "csrf", "path-traversal", "api"],
            "domain": ["osint", "network", "subdomain", "dns"],
            "ip": ["network", "port-scan", "service-enum"],
            "directory": ["code-review", "secret-scan", "dep-check", "sast"],
            "git_repo": ["code-review", "secret-scan", "dep-check", "supply-chain"],
        }

        tags = type_to_tags.get(target_type, ["sqli", "xss", "auth"])
        result: Dict[str, List[Skill]] = {}
        seen: Set[str] = set()
        for tag in tags:
            skills = self.get_by_tag(tag, limit)
            tag_skills = []
            for s in skills:
                if s.name not in seen:
                    tag_skills.append(s)
                    seen.add(s.name)
            if tag_skills:
                result[tag] = tag_skills
        return result

    def summary(self) -> Dict:
        self.build_index()
        return {
            "total_indexed": len(self.engine._skills_cache),
            "tag_groups": len(self._by_tag),
            "categories": {k: len(v) for k, v in self._by_category.items()},
        }


_registry_instance: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = SkillRegistry()
    return _registry_instance
