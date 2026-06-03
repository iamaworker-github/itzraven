"""
Safety/Ethics Rules Engine — src-hunter style red lines.

Prevents agents from taking destructive actions, scanning out-of-scope
targets, or generating malicious code without authorization.

Integrated into the agent execution pipeline via BaseAgent.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse


@dataclass
class SafetyViolation:
    """Record of a safety rule violation."""
    rule: str
    severity: str  # "block", "warn", "info"
    message: str
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule, "severity": self.severity,
            "message": self.message, "details": self.details,
        }


class SafetyRules:
    """Safety rules engine with src-hunter style red lines.

    Rules organized by category:
    - DESTRUCTIVE: Prevent damaging actions (DDoS, data destruction)
    - SCOPE: Enforce scope boundaries
    - LEGAL: Block illegal activities
    - ETHICAL: Ethical boundaries for responsible disclosure
    - MALICIOUS: Prevent malicious code generation
    """

    # ====================================================================
    # DESTRUCTIVE — Actions that could damage systems
    # ====================================================================
    DESTRUCTIVE_PATTERNS = [
        # SQL destructive
        (r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE)\b", "SQL destructive operation"),
        (r"\bTRUNCATE\s+(TABLE|DATABASE)\b", "SQL truncate operation"),
        (r"\bDELETE\s+FROM\s+\w+\s*(?!.*\bWHERE\b)", "Unconditional DELETE operation"),
        (r"\bALTER\s+(TABLE|DATABASE|USER)\b", "SQL ALTER destructive operation"),
        (r"\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)", "Unconditional UPDATE operation"),
        # OS destructive
        (r"\brm\s+-[rf]", "Recursive force delete"),
        (r"\bdd\s+if=", "Raw disk write operation"),
        (r"\bmkfs\.", "Filesystem format operation"),
        (r"\bfdisk\b", "Partition manipulation"),
        (r"\bformat\b", "Format command"),
        (r"\bdel\s+/[fsq]", "Force delete Windows"),
        (r"\b(?:shutdown|reboot|halt|poweroff)\s", "System shutdown/reboot"),
        # DDoS
        (r"(?:LOIC|HOIC|Slowloris|Hping|hping3)\s", "DDoS tool usage"),
        (r"\bSYN\s+flood\b", "SYN flood attack"),
        (r"\bDDoS\b", "DDoS attack"),
        (r"\bstress\s+-t\s+\d+\s+-c\s+\d+", "Stress testing tool"),
        # Data destruction
        (r"\b(?:wipe|shred|srm|sfill)\s", "Secure deletion tool"),
        (r"\bbasilisk\b", "Data destruction tool"),
        (r"\bdban\b", "Disk wipe tool"),
    ]

    # ====================================================================
    # SCOPE — Target scope enforcement
    # ====================================================================
    OUT_OF_SCOPE_DOMAINS = [
        "google.com", "facebook.com", "twitter.com", "x.com",
        "youtube.com", "instagram.com", "linkedin.com", "reddit.com",
        "microsoft.com", "apple.com", "amazon.com", "github.com",
        "gitlab.com", "whatsapp.com", "cloudflare.com",
        "akamai.com", "fastly.com", "cloudfront.net",
    ]

    # ====================================================================
    # LEGAL — Legally prohibited activities
    # ====================================================================
    LEGAL_BLOCK_PATTERNS = [
        # Unauthorized access
        (r"\bunauthorized\s+access\b", "Unauthorized access"),
        (r"\bhacking\s+government\b", "Government system hacking"),
        (r"\bhack\s+(?:into|the)\s+(?:bank|financial|gov|government)", "Financial/gov hacking"),
        # Stolen data
        (r"\b(?:stolen|leaked|breached)\s+(?:database|dump|data)", "Stolen data usage"),
        (r"\bsell\s+(?:credit|card|ssn|dumps|fullz)", "Selling stolen financial data"),
        # Malware distribution
        (r"\b(?:ransomware|ransom)\s+(?:as\s+a\s+service|builder)", "RaaS promotion"),
        (r"\b(?:spread|distribut(e|ing))\s+(?:malware|virus|ransomware)", "Malware distribution"),
        # Phishing
        (r"\bphishing\s+(?:kit|campaign|page|template)", "Phishing kit usage"),
        (r"\b(?:mass|bulk)\s+(?:phishing|spam)", "Mass phishing/spam"),
    ]

    # ====================================================================
    # ETHICAL — Responsible disclosure boundaries
    # ====================================================================
    ETHICAL_BLOCK_PATTERNS = [
        # No responsible disclosure
        (r"\b(?:sell|auction)\s+(?:0day|zeroday|exploit|vulnerability)", "Selling exploits"),
        (r"\b(?:public\s+disclosure|full\s+disclosure)\s+(?:without|no)\s+", "Full disclosure without notice"),
        (r"\b(?:extort|blackmail)\s", "Extortion/blackmail"),
        # No authorization
        (r"\bhunt\s+(?:without|no)\s+(?:permission|authorization|consent)", "Hunting without permission"),
        (r"\btesting\s+(?:without\s+)?bug\s+bounty\s+program\b", "Testing without program"),
        (r"\bbounty\s+(?:without\s+)?scope\b", "Bounty without scope"),
    ]

    # ====================================================================
    # MALICIOUS — Prevent malicious code generation
    # ====================================================================
    MALICIOUS_CODE_PATTERNS = [
        # Backdoors/shells
        (r"(?:backdoor|back\s*door)\s+creation", "Backdoor creation"),
        (r"\b(?:bind|reverse)\s+shell\b", "Reverse/bind shell generation"),
        # Keyloggers
        (r"\b(?:keylog|key\s*log)", "Keylogger creation"),
        # Credential theft
        (r"\b(?:credential\s+steal|password\s+grab|pwdump|mimikatz)", "Credential theft tool"),
        # Worm/virus
        (r"\b(?:worm|virus)\s+creation\b", "Worm/virus creation"),
        (r"\bself[- ]?replicat(?:e|ing)\b", "Self-replicating code"),
    ]

    def __init__(self, scope: Optional[List[str]] = None):
        self.scope = [s.lower() for s in (scope or [])]
        self.violations: List[SafetyViolation] = []
        self.blocked: bool = False

    def check_text(self, text: str, context: str = "") -> List[SafetyViolation]:
        """Check text against all safety rules.

        Args:
            text: The text to check (agent instruction, code, etc.)
            context: Optional context description for error messages

        Returns:
            List of SafetyViolations (empty = safe)
        """
        violations = []
        text_lower = text.lower()

        # Check destructive patterns
        for pattern, desc in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                violations.append(SafetyViolation(
                    rule="destructive_action",
                    severity="block",
                    message=f"Destructive action blocked: {desc}",
                    details=f"Pattern matched in {context}",
                ))

        # Check legal patterns
        for pattern, desc in self.LEGAL_BLOCK_PATTERNS:
            if re.search(pattern, text_lower):
                violations.append(SafetyViolation(
                    rule="legal_violation",
                    severity="block",
                    message=f"Legal violation blocked: {desc}",
                    details=f"Pattern matched in {context}",
                ))

        # Check ethical patterns
        for pattern, desc in self.ETHICAL_BLOCK_PATTERNS:
            if re.search(pattern, text_lower):
                violations.append(SafetyViolation(
                    rule="ethical_violation",
                    severity="block",
                    message=f"Ethical boundary: {desc}",
                    details=f"Pattern matched in {context}",
                ))

        # Check malicious code patterns
        for pattern, desc in self.MALICIOUS_CODE_PATTERNS:
            if re.search(pattern, text_lower):
                violations.append(SafetyViolation(
                    rule="malicious_code",
                    severity="block",
                    message=f"Malicious code blocked: {desc}",
                    details=f"Pattern matched in {context}",
                ))

        self.violations.extend(violations)
        if any(v.severity == "block" for v in violations):
            self.blocked = True
        return violations

    def check_target(self, target: str) -> Optional[SafetyViolation]:
        """Check if target is in scope.

        Returns a SafetyViolation if out of scope, None if allowed.
        """
        target_lower = target.lower()
        parsed = urlparse(target)
        domain = parsed.netloc or target_lower
        domain = domain.split(":")[0]  # remove port
        domain = domain.lstrip("www.")

        # If scope defined, check against it
        if self.scope:
            in_scope = any(s in domain for s in self.scope)
            if not in_scope:
                return SafetyViolation(
                    rule="out_of_scope",
                    severity="block",
                    message=f"Target {target} is outside defined scope",
                    details=f"Scope: {self.scope}",
                )
            return None

        # No scope defined — check against known non-bounty domains
        for banned in self.OUT_OF_SCOPE_DOMAINS:
            if banned in domain or domain in banned:
                return SafetyViolation(
                    rule="out_of_scope",
                    severity="warn",
                    message=f"Target {target} appears to be a known platform ({banned})",
                    details="Verify you have authorization before testing",
                )

        return None

    def check_url(self, url: str) -> Optional[SafetyViolation]:
        """Check if a URL is safe to access/fuzz."""
        return self.check_target(url)

    def check_command(self, command: str) -> List[SafetyViolation]:
        """Check shell commands before execution."""
        violations = []

        destructive_commands = [
            (r"\brm\s+-[rf]\s+/", "Root-level recursive delete"),
            (r"\bdd\s+if=.*\s+of=/dev/", "Raw disk write"),
            (r"\bmkfs\.\w+\s+/dev/", "Filesystem format"),
            (r"\b>?\s*/dev/(?:sda|sdb|sdc|nvme)", "Direct disk access"),
            (r"\bchmod\s+-R\s+0{4}\s+/", "Remove all permissions recursively"),
            (r"\bchown\s+-R\s+\w+:\w+\s+/", "Change ownership recursively root"),
        ]
        for pattern, desc in destructive_commands:
            if re.search(pattern, command):
                violations.append(SafetyViolation(
                    rule="destructive_command",
                    severity="block",
                    message=f"Destructive command blocked: {desc}",
                    details=f"Command: {command[:100]}",
                ))

        self.violations.extend(violations)
        if any(v.severity == "block" for v in violations):
            self.blocked = True
        return violations

    def check_code(self, code: str, language: str = "") -> List[SafetyViolation]:
        """Check generated code for safety issues."""
        violations = []

        # Check for injected malicious imports
        dangerous_modules = [
            "pynput", "keyboard", "mouse",  # keyloggers
            "socket",  # when combined with reverse shell patterns
            "ctypes",  # when used for memory manipulation
        ]

        if language == "python":
            for mod in dangerous_modules:
                if f"import {mod}" in code or f"from {mod}" in code:
                    violations.append(SafetyViolation(
                        rule="dangerous_import",
                        severity="warn",
                        message=f"Dangerous import detected: {mod}",
                        details=f"Only use if explicitly authorized",
                    ))

        self.violations.extend(violations)
        return violations

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all safety checks."""
        block_count = sum(1 for v in self.violations if v.severity == "block")
        warn_count = sum(1 for v in self.violations if v.severity == "warn")
        return {
            "total_violations": len(self.violations),
            "blocked": self.blocked,
            "block_count": block_count,
            "warn_count": warn_count,
            "violations": [v.to_dict() for v in self.violations],
        }

    def reset(self):
        """Reset violations for a new check cycle."""
        self.violations = []
        self.blocked = False
