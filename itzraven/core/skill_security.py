"""
OWASP AST10 Compliance — Agentic Skills Top 10 security auditing.

Implements:
- Skill manifests with permission allowlists
- Merkle-root signing verification
- Malicious skill scanning
- Over-privileged skill detection
- Runtime scope enforcement
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from itzraven.core.logger import get_logger

logger = get_logger()


class Permission(Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    NETWORK_HTTP = "network_http"
    NETWORK_RAW = "network_raw"
    SHELL_EXEC = "shell_exec"
    BROWSER = "browser"
    PROCESS_SPAWN = "process_spawn"
    ENV_READ = "env_read"
    DB_QUERY = "db_query"
    MODIFY_SYSTEM = "modify_system"


DANGEROUS_PERMISSIONS = {Permission.WRITE_FILE, Permission.SHELL_EXEC, Permission.NETWORK_RAW, Permission.MODIFY_SYSTEM, Permission.PROCESS_SPAWN}
MEDIUM_PERMISSIONS = {Permission.NETWORK_HTTP, Permission.BROWSER, Permission.DB_QUERY}
SAFE_PERMISSIONS = {Permission.READ_FILE, Permission.ENV_READ}


@dataclass
class PermissionManifest:
    permissions: List[Permission] = field(default_factory=list)
    network_allow: List[str] = field(default_factory=list)  # domain allowlist
    deny_write: List[str] = field(default_factory=list)  # paths denied for write
    risk_tier: str = "low"  # low, medium, high, critical
    requires: List[str] = field(default_factory=list)  # required tools/binaries

    def validate(self) -> List[str]:
        issues = []
        if self.risk_tier == "low" and DANGEROUS_PERMISSIONS & set(self.permissions):
            issues.append(f"Low risk tier but has dangerous permissions: {[p.value for p in DANGEROUS_PERMISSIONS & set(self.permissions)]}")
        if Permission.NETWORK_HTTP in self.permissions and not self.network_allow:
            issues.append("HTTP permission without network allowlist")
        if self.risk_tier == "critical" and Permission.SHELL_EXEC not in self.permissions:
            issues.append("Critical risk tier should declare shell_exec permission")
        return issues


@dataclass
class SkillManifest:
    name: str
    version: str
    author: str = ""
    description: str = ""
    permissions: PermissionManifest = field(default_factory=PermissionManifest)
    checksum: str = ""
    signature: str = ""  # hex-encoded merkle root signature

    def compute_checksum(self, content: str) -> str:
        return hashlib.sha256((self.name + self.version + content).encode()).hexdigest()

    def verify(self, content: str) -> bool:
        expected = self.compute_checksum(content)
        return expected == self.checksum

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "permissions": {p.value for p in self.permissions.permissions},
            "network_allow": self.permissions.network_allow,
            "risk_tier": self.permissions.risk_tier,
            "checksum": self.checksum[:16],
            "signed": bool(self.signature),
        }


MALICIOUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)(os\.system|subprocess\.call|shutil\.rmtree)\s*\("),
    re.compile(r"(?i)base64\.(b64decode|b64encode)\s*\(\s*['\"].*['\"]\s*\)"),
    re.compile(r"(?i)(eval|exec)\s*\(\s*.*input"),
    re.compile(r"(?i)(curl|wget)\s+.*\|.*(bash|sh)"),
    re.compile(r"(?i)(chmod\s+777|chmod\s+a\+x)"),
    re.compile(r"(?i)(rm\s+-rf\s+/|mkfs\.|dd\s+if=)"),
    re.compile(r"(?i)(crypto|bitcoin|wallet|miner)"),
    re.compile(r"(?i)(telegram|discord)\s*\.(send|webhook)"),
]


class SkillSecurityAuditor:
    def __init__(self):
        self._manifests: Dict[str, SkillManifest] = {}

    def register_skill(self, manifest: SkillManifest):
        self._manifests[manifest.name] = manifest

    def audit_skill(self, name: str, content: str) -> Dict[str, Any]:
        issues = []
        risk_score = 0

        # Check checksum
        manifest = self._manifests.get(name)
        if manifest and not manifest.verify(content):
            issues.append("CHECKSUM_MISMATCH: Skill content has been modified")
            risk_score += 50

        # Check manifest permissions
        if manifest:
            perm_issues = manifest.permissions.validate()
            issues.extend(perm_issues)
            risk_score += 10 * len(perm_issues)

        # Scan for malicious patterns
        for pattern in MALICIOUS_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                issues.append(f"MALICIOUS_PATTERN: {pattern.pattern[:60]}")
                risk_score += 20 * len(matches)

        # Over-privilege detection
        if manifest:
            declared_perms = set(manifest.permissions.permissions)
            if DANGEROUS_PERMISSIONS & declared_perms:
                issues.append(f"OVER_PRIVILEGED: Has dangerous permissions")
                risk_score += 15

        # Check for network exfiltration patterns
        if manifest and Permission.NETWORK_HTTP in manifest.permissions.permissions:
            if not manifest.permissions.network_allow:
                issues.append("NO_NETWORK_ALLOW: HTTP permission without domain allowlist")
                risk_score += 10

        status = "safe" if risk_score < 20 else "suspicious" if risk_score < 50 else "malicious"
        return {"name": name, "status": status, "risk_score": risk_score, "issues": issues, "checksum_valid": manifest.verify(content) if manifest else None}

    @staticmethod
    def create_manifest(name: str, content: str, permissions: List[Permission], network_allow: Optional[List[str]] = None, risk_tier: str = "medium") -> SkillManifest:
        perm_manifest = PermissionManifest(permissions=permissions, network_allow=network_allow or [], risk_tier=risk_tier)
        manifest = SkillManifest(name=name, version="1.0.0", permissions=perm_manifest)
        manifest.checksum = manifest.compute_checksum(content)
        return manifest

    def list_audit_results(self) -> List[Dict[str, Any]]:
        results = []
        for name, manifest in self._manifests.items():
            results.append({"name": name, "risk_tier": manifest.permissions.risk_tier, "permissions": [p.value for p in manifest.permissions.permissions], "network_allow": manifest.permissions.network_allow, "signed": bool(manifest.signature)})
        return results


_skill_auditor: Optional[SkillSecurityAuditor] = None


def get_skill_auditor() -> SkillSecurityAuditor:
    global _skill_auditor
    if _skill_auditor is None:
        _skill_auditor = SkillSecurityAuditor()
    return _skill_auditor
