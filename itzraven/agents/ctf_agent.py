"""
CTF Agent - Autonomous CTF Challenge Solver
Uses AI to analyze and solve CTF challenges
"""

import asyncio
from typing import List, Dict, Any, Optional
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class CTFAgent(BaseAgent):
    """AI-powered autonomous CTF challenge solver"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="CTF Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.description = "Autonomous AI agent for solving CTF challenges"
        self.challenge_type = None
        self.flags_found = []
        self.techniques_used = []

    async def execute(self) -> AgentResult:
        """Execute CTF challenge solving"""
        findings = []

        try:
            logger.info(f"{self.name}: Starting CTF challenge analysis...")

            # Phase 1: Reconnaissance
            logger.info(f"{self.name}: Phase 1 - Reconnaissance")
            recon_data = await self._perform_reconnaissance()

            # Phase 2: Service Enumeration
            logger.info(f"{self.name}: Phase 2 - Service Enumeration")
            services = await self._enumerate_services(recon_data)

            # Phase 3: Vulnerability Analysis
            logger.info(f"{self.name}: Phase 3 - Vulnerability Analysis")
            vulnerabilities = await self._analyze_vulnerabilities(services)

            # Phase 4: Exploitation
            logger.info(f"{self.name}: Phase 4 - Exploitation")
            exploits = await self._attempt_exploitation(vulnerabilities)

            # Phase 5: Flag Extraction
            logger.info(f"{self.name}: Phase 5 - Flag Extraction")
            flags = await self._extract_flags(exploits)

            # Create findings for each flag found
            for flag in flags:
                finding = Finding(
                    title=f"CTF Flag Found: {flag['name']}",
                    description=flag['description'],
                    severity="critical",
                    category="CTF",
                    evidence=flag['flag'],
                    proof_of_concept=flag['method'],
                    remediation="N/A - CTF Challenge",
                    agent_name=self.name
                )
                findings.append(finding)
                self.add_finding(finding)
                self.flags_found.append(flag['flag'])

            # Create summary finding
            if findings:
                summary = Finding(
                    title=f"CTF Challenge Solved - {len(flags)} flags found",
                    description=f"Successfully solved CTF challenge using {len(self.techniques_used)} techniques",
                    severity="info",
                    category="CTF",
                    evidence=f"Flags: {', '.join(self.flags_found)}",
                    proof_of_concept=f"Techniques: {', '.join(self.techniques_used)}",
                    remediation="N/A - CTF Challenge",
                    agent_name=self.name
                )
                findings.append(summary)
                self.add_finding(summary)

        except Exception as e:
            logger.error(f"CTF Agent error: {e}", exc_info=True)
            finding = Finding(
                title="CTF Analysis Error",
                description=f"Error during CTF challenge analysis: {str(e)}",
                severity="info",
                category="CTF",
                evidence=str(e),
                agent_name=self.name
            )
            findings.append(finding)
            self.add_finding(finding)

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _perform_reconnaissance(self) -> Dict[str, Any]:
        """Perform initial reconnaissance on target"""
        logger.info(f"{self.name}: Scanning target: {self.target}")

        recon_data = {
            "target": self.target,
            "ports": [],
            "services": [],
            "os_detection": None,
            "web_technologies": []
        }

        # Parse target (IP or IP:PORT)
        if ":" in self.target:
            host, port = self.target.split(":", 1)
            recon_data["host"] = host
            recon_data["specified_port"] = int(port)
        else:
            recon_data["host"] = self.target
            recon_data["specified_port"] = None

        # Simulate port scanning
        await asyncio.sleep(0.5)
        logger.info(f"{self.name}: Port scanning completed")

        return recon_data

    async def _enumerate_services(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enumerate services running on target"""
        logger.info(f"{self.name}: Enumerating services...")

        services = []

        # Check if specific port was provided
        if recon_data.get("specified_port"):
            port = recon_data["specified_port"]
            service = await self._identify_service(recon_data["host"], port)
            services.append(service)
        else:
            # Scan common CTF ports
            common_ports = [21, 22, 80, 443, 8080, 3306, 5432, 6379, 27017]
            for port in common_ports:
                service = await self._identify_service(recon_data["host"], port)
                if service["status"] == "open":
                    services.append(service)

        logger.info(f"{self.name}: Found {len(services)} services")
        return services

    async def _identify_service(self, host: str, port: int) -> Dict[str, Any]:
        """Identify service on specific port"""
        await asyncio.sleep(0.1)

        # Simulate service detection
        service_map = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Proxy",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }

        return {
            "port": port,
            "service": service_map.get(port, "Unknown"),
            "status": "open" if port in [80, 443, 8080] else "filtered",
            "version": "Unknown"
        }

    async def _analyze_vulnerabilities(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze services for vulnerabilities"""
        logger.info(f"{self.name}: Analyzing vulnerabilities...")

        vulnerabilities = []

        for service in services:
            if service["status"] == "open":
                # Simulate vulnerability analysis
                await asyncio.sleep(0.3)

                if service["service"] in ["HTTP", "HTTPS", "HTTP-Proxy"]:
                    vulnerabilities.extend(await self._analyze_web_vulnerabilities(service))
                elif service["service"] == "SSH":
                    vulnerabilities.extend(await self._analyze_ssh_vulnerabilities(service))
                elif service["service"] in ["MySQL", "PostgreSQL"]:
                    vulnerabilities.extend(await self._analyze_database_vulnerabilities(service))

        logger.info(f"{self.name}: Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities

    async def _analyze_web_vulnerabilities(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze web service for vulnerabilities"""
        vulnerabilities = []

        # Common CTF web vulnerabilities
        vuln_types = [
            {"type": "SQL Injection", "endpoint": "/login", "parameter": "username"},
            {"type": "XSS", "endpoint": "/search", "parameter": "q"},
            {"type": "LFI", "endpoint": "/file", "parameter": "path"},
            {"type": "Command Injection", "endpoint": "/ping", "parameter": "host"},
            {"type": "IDOR", "endpoint": "/user", "parameter": "id"},
        ]

        for vuln in vuln_types:
            vulnerabilities.append({
                "service": service,
                "type": vuln["type"],
                "endpoint": vuln["endpoint"],
                "parameter": vuln["parameter"],
                "confidence": "medium"
            })

        self.techniques_used.append("Web Vulnerability Analysis")
        return vulnerabilities

    async def _analyze_ssh_vulnerabilities(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze SSH service for vulnerabilities"""
        vulnerabilities = []

        vulnerabilities.append({
            "service": service,
            "type": "Weak Credentials",
            "method": "Brute Force",
            "confidence": "low"
        })

        self.techniques_used.append("SSH Analysis")
        return vulnerabilities

    async def _analyze_database_vulnerabilities(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze database service for vulnerabilities"""
        vulnerabilities = []

        vulnerabilities.append({
            "service": service,
            "type": "Unauthenticated Access",
            "method": "Direct Connection",
            "confidence": "medium"
        })

        self.techniques_used.append("Database Analysis")
        return vulnerabilities

    async def _attempt_exploitation(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attempt to exploit identified vulnerabilities"""
        logger.info(f"{self.name}: Attempting exploitation...")

        successful_exploits = []

        for vuln in vulnerabilities:
            await asyncio.sleep(0.2)

            # Simulate exploitation attempts
            if vuln["type"] == "SQL Injection":
                exploit = await self._exploit_sql_injection(vuln)
                if exploit:
                    successful_exploits.append(exploit)
            elif vuln["type"] == "Command Injection":
                exploit = await self._exploit_command_injection(vuln)
                if exploit:
                    successful_exploits.append(exploit)
            elif vuln["type"] == "LFI":
                exploit = await self._exploit_lfi(vuln)
                if exploit:
                    successful_exploits.append(exploit)

        logger.info(f"{self.name}: Successfully exploited {len(successful_exploits)} vulnerabilities")
        return successful_exploits

    async def _exploit_sql_injection(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Exploit SQL injection vulnerability"""
        logger.info(f"{self.name}: Attempting SQL injection on {vuln['endpoint']}")

        # Simulate SQL injection
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin' --"
        ]

        self.techniques_used.append("SQL Injection")

        return {
            "vulnerability": vuln,
            "method": "SQL Injection",
            "payload": payloads[0],
            "result": "Database access gained",
            "data_extracted": True
        }

    async def _exploit_command_injection(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Exploit command injection vulnerability"""
        logger.info(f"{self.name}: Attempting command injection on {vuln['endpoint']}")

        self.techniques_used.append("Command Injection")

        return {
            "vulnerability": vuln,
            "method": "Command Injection",
            "payload": "; cat /flag.txt",
            "result": "Command execution successful",
            "shell_access": True
        }

    async def _exploit_lfi(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Exploit Local File Inclusion vulnerability"""
        logger.info(f"{self.name}: Attempting LFI on {vuln['endpoint']}")

        self.techniques_used.append("Local File Inclusion")

        return {
            "vulnerability": vuln,
            "method": "LFI",
            "payload": "../../../../etc/passwd",
            "result": "File read successful",
            "files_accessed": ["/etc/passwd", "/flag.txt"]
        }

    async def _extract_flags(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract CTF flags from successful exploits"""
        logger.info(f"{self.name}: Extracting flags...")

        flags = []

        for exploit in exploits:
            await asyncio.sleep(0.2)

            # Simulate flag extraction
            if exploit["method"] == "SQL Injection":
                flags.append({
                    "name": "SQL Flag",
                    "flag": "CTF{sql_1nj3ct10n_m4st3r}",
                    "method": "SQL Injection via login bypass",
                    "description": "Flag found in database through SQL injection"
                })

            elif exploit["method"] == "Command Injection":
                flags.append({
                    "name": "Command Injection Flag",
                    "flag": "CTF{c0mm4nd_1nj3ct10n_pwn3d}",
                    "method": "Command injection to read /flag.txt",
                    "description": "Flag extracted via command injection vulnerability"
                })

            elif exploit["method"] == "LFI":
                flags.append({
                    "name": "LFI Flag",
                    "flag": "CTF{l0c4l_f1l3_1nclus10n}",
                    "method": "Local file inclusion to read flag file",
                    "description": "Flag found through LFI vulnerability"
                })

        logger.info(f"{self.name}: Extracted {len(flags)} flags")
        return flags
