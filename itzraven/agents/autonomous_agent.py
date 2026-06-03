"""
Autonomous Security Agent with ReAct (Reasoning + Action) loop.
CAI-inspired: Think → Act → Observe → Repeat with dynamic tool selection.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import httpx

from itzraven.agents.base_agent import AgentResult, BaseAgent, Finding
from itzraven.agents.llm_client import LLMClient, get_route_for_task
from itzraven.skills import get_skills_engine
from itzraven.skills.registry import get_skill_registry
from itzraven.core.logger import get_logger
from itzraven.core.thinking_chain import get_thinking_chain
from itzraven.core.knowledge_graph import get_knowledge_graph
from itzraven.core.memory_system import get_memory_system
from itzraven.core.rag.context import get_rag_context

logger = get_logger()


@dataclass
class ReActStep:
    iteration: int
    thought: str
    action_type: str
    action_params: Dict[str, Any]
    observation: str
    status: str = "pending"
    timestamp: float = field(default_factory=time.time)
    findings_added: int = 0


TOOL_DESCRIPTIONS = {
    "http_request": "Send HTTP request (GET/POST) to target. Params: method, path, headers, body",
    "scan_endpoints": "Discover endpoints on target. Params: wordlist_size (int)",
    "test_sqli": "Test for SQL Injection on a parameter. Params: url, param, method",
    "test_xss": "Test for XSS on a parameter. Params: url, param, method",
    "test_ssrf": "Test for SSRF via parameter. Params: url, param",
    "analyze_response": "Analyze HTTP response for security issues. Params: response_snippet (str)",
    "nuclei_scan": "Run nuclei template against target. Params: template_tags (list)",
    "search_skills": "Search security testing skills. Params: query (str)",
    "emit_finding": "Record a confirmed finding. Params: title, severity, description, evidence",
    "done": "Mark this phase as complete. Provide summary.",
}


class PatternCache:
    def __init__(self, max_size: int = 50):
        self._cache: Dict[str, Any] = {}
        self._max_size = max_size

    def _make_key(self, tech_fingerprint: str, action_type: str, param_name: str) -> str:
        return f"{tech_fingerprint}:{action_type}:{param_name}"

    def get(self, tech_fingerprint: str, action_type: str, param_name: str) -> Optional[Any]:
        return self._cache.get(self._make_key(tech_fingerprint, action_type, param_name))

    def set(self, tech_fingerprint: str, action_type: str, param_name: str, result: Any):
        key = self._make_key(tech_fingerprint, action_type, param_name)
        if len(self._cache) >= self._max_size:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[key] = result

    def clear(self):
        self._cache.clear()


SPECIALIST_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "php": {
        "sqli": ["'", "' OR '1'='1", "1' AND 1=1--", "' UNION SELECT 1,2,3--", "1' ORDER BY 5--"],
        "xss":  ["<script>alert(1)</script>", "\" onfocus=alert(1) autofocus>", "{{7*7}}"],
        "ssrf": ["http://169.254.169.254/", "http://127.0.0.1/phpinfo.php"],
    },
    "mysql": {
        "sqli": ["' OR 1=1--", "1' AND SLEEP(5)--", "' UNION SELECT @@version--", "1' INTO OUTFILE '/tmp/test'--"],
    },
    "asp": {
        "sqli": ["' OR '1'='1", "1' AND 1=1--", "' UNION SELECT 1,2,3--"],
        "xss":  ["<script>alert(1)</script>", "\" onfocus=alert(1) autofocus>"],
    },
    "nodejs": {
        "sqli": ["'", "' OR '1'='1", "1' AND 1=1--"],
        "xss":  ["<script>alert(1)</script>", "{{7*7}}", "${7*7}"],
        "ssrf": ["http://localhost:3000/admin", "http://169.254.169.254/"],
    },
    "django": {
        "sqli": ["' OR 1=1--", "1' AND 1=1--"],
        "xss":  ["<script>alert(1)</script>", "{{7*7}}"],
    },
    "generic": {
        "sqli": ["'", "' OR '1'='1", "' OR 1=1--", '"', "1 AND 1=1", "1 AND 1=2"],
        "xss":  ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", '"><script>alert(1)</script>'],
        "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://localhost:8080", "file:///etc/passwd"],
    },
}

TECH_FINGERPRINTS: Dict[str, str] = {
    ".php": "php", "phpmyadmin": "php", "laravel": "php", "wordpress": "php",
    ".aspx": "asp", ".asp": "asp", "iis": "asp",
    "node": "nodejs", "express": "nodejs", "next.js": "nodejs",
    "django": "django", "python": "django",
    "mysql": "mysql", "mariadb": "mysql",
}


def _detect_tech_fingerprint(techs: Dict[str, Any], endpoints: List[str]) -> str:
    combined = []
    for t in techs:
        combined.append(t.lower())
    for ep in endpoints:
        combined.append(ep.lower())
    for keyword, fp in TECH_FINGERPRINTS.items():
        if any(keyword in c for c in combined):
            return fp
    return "generic"


class AutonomousSecurityAgent(BaseAgent):
    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        max_iterations: int = 10,
        scope: Optional[List[str]] = None,
        instruction: Optional[str] = None,
        scan_depth: str = "deep",
    ):
        super().__init__(
            "Autonomous Security Agent",
            target,
            event_bus=event_bus,
            memory_manager=memory_manager,
            scope=scope,
        )
        self.max_iterations = max(3, max_iterations)
        self.instruction = instruction.strip() if instruction else None
        self.scan_depth = scan_depth
        self.llm_client = LLMClient()
        self.skills_engine = get_skills_engine()
        self.skill_registry = get_skill_registry()
        self.history: List[ReActStep] = []
        self.discovered_urls: List[str] = []
        self.target_tech: Dict[str, Any] = {}
        self.session_context: Dict[str, Any] = {"findings": [], "open_questions": [], "blockers": []}
        self.knowledge_graph = get_knowledge_graph()
        self.memory = get_memory_system()
        self.rag = get_rag_context()
        self._pattern_cache = PatternCache()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: ReAct scan on {self.target}")

        if not self.llm_client.config.has_ai_enabled:
            return self._no_ai_fallback()

        self.memory.start_session(f"{self.name}_{int(time.time())}")
        self.memory.working.target_info = {"url": self.target, "scope": self.scope}
        self.memory.working.set_goal(f"Complete security assessment of {self.target}", "high")
        target_id = self.knowledge_graph.add_target(self.target)

        await self._emit_thought(f"Starting ReAct analysis of {self.target}", "intent", "init")

        await self._quick_connectivity_check()

        await self._emit_thought("Discovering target endpoints...", "searching", "recon")
        self.discovered_urls = await self._discover_urls() or [self.target.rstrip("/")]

        await self._emit_thought(
            f"Discovered {len(self.discovered_urls)} endpoints. Beginning ReAct loop.",
            "planning", "recon",
        )

        for iteration in range(1, self.max_iterations + 1):
            if self.should_stop:
                await self._emit_thought("Agent cancelled by user", "summary", "cancelled")
                break

            await self._emit_thought(f"ReAct iteration {iteration}/{self.max_iterations}", "reasoning", "react")

            try:
                rag_ctx = self.rag.build_context(
                    target=self.target,
                    technologies=list(self.target_tech.keys()),
                    vulnerability_focus="",
                )
                self.session_context["rag"] = rag_ctx
                thought, action_type, action_params = await self._think(iteration)
            except Exception as e:
                logger.debug(f"{self.name}: Think failed at iter {iteration}: {e}")
                await self._emit_thought(f"Reasoning error: {e}", "error", "react")
                continue

            self.memory.think(thought, self.name)
            self.memory.working.set_focus(f"Iter {iteration}: {action_type}")

            if action_type == "done":
                await self._emit_thought(f"ReAct complete: {action_params.get('summary', 'done')}", "summary", "complete")
                break

            try:
                observation = await self._act(action_type, action_params)
            except Exception as e:
                observation = f"Action failed: {e}"
                logger.debug(f"{self.name}: Act failed at iter {iteration}: {e}")

            # Cache successful vulnerability detection patterns
            if action_type in ("test_sqli", "test_xss", "test_ssrf"):
                tech_fp = _detect_tech_fingerprint(self.target_tech, self.discovered_urls)
                param_used = action_params.get("param", "id")
                has_hit = False
                if isinstance(observation, dict):
                    for key in ("suspicious", "reflected", "results"):
                        items = observation.get(key, [])
                        if isinstance(items, list) and len(items) > 0:
                            has_hit = True
                            break
                self._pattern_cache.set(tech_fp, action_type, param_used, {"success": has_hit})

            step = ReActStep(
                iteration=iteration,
                thought=thought,
                action_type=action_type,
                action_params=action_params,
                observation=str(observation)[:500],
            )

            await self._emit_thought(f"Action: {action_type} | Result: {str(observation)[:100]}", "action", "react")

            if action_type == "emit_finding":
                step.findings_added = 1

            self.history.append(step)
            self.memory.act(f"{action_type}: {str(observation)[:200]}", self.name)

            # Update knowledge graph for findings
            if action_type == "emit_finding":
                title = action_params.get("title", "Unknown")
                severity = action_params.get("severity", "medium")
                self.memory.add_finding(title, severity, self.name)
                self.memory.working.record_finding(title)
                self.knowledge_graph.add_finding(target_id, title, severity, "autonomous")

            # Update thinking chain for inter-agent context
            get_thinking_chain().add_block(
                agent_name=self.name,
                thought=f"[{action_type}] {str(observation)[:200]}",
                thought_type="observation",
                phase="react",
            )

        self.memory.end_session()
        self.memory.long_term.record_target(self.target, {
            "findings_count": len(self.findings),
            "iterations": len(self.history),
            "urls": self.discovered_urls[:10],
        })
        self.knowledge_graph.save(str(Path.home() / ".itzraven" / "knowledge_graph.json"))

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "iterations": len(self.history),
                "findings": len(self.findings),
                "urls_discovered": len(self.discovered_urls),
                "react_steps": [(s.action_type, s.status) for s in self.history],
            },
        )

    async def _think(self, iteration: int) -> Tuple[str, str, Dict[str, Any]]:
        tech_fp = _detect_tech_fingerprint(self.target_tech, self.discovered_urls)

        # Pattern cache: if we already handled this exact (tech, vuln, param), skip LLM
        for action_type in ["test_sqli", "test_xss", "test_ssrf"]:
            for param_hint in self._get_param_hints(action_type):
                cached = self._pattern_cache.get(tech_fp, action_type, param_hint)
                if cached and cached.get("success"):
                    self.memory.working.set_focus(f"Cached: {action_type} on {param_hint}")
                    return f"Using cached result for {action_type} on {param_hint}", action_type, {"param": param_hint, "url": self.target}

        system = self._build_system_prompt()
        prompt = self._build_react_prompt(iteration)

        response = await self.llm_client.generate(
            prompt=prompt, system=system, max_tokens=1000, task="react_think",
        )

        parsed = self._parse_react_response(response.content)
        if not parsed or "action" not in parsed:
            return "Fallback: no valid action from LLM", "done", {"summary": "No valid action generated"}

        thought = parsed.get("thought", "No reasoning provided")
        action_type = parsed["action"]
        action_params = parsed.get("params", {})

        # Validate action type
        if action_type not in TOOL_DESCRIPTIONS:
            return thought, "done", {"summary": f"Unknown action type: {action_type}"}

        # Specialist routing: override generic payloads with tech-specific ones
        if action_type in SPECIALIST_PAYLOADS.get("generic", {}):
            tech_specific = SPECIALIST_PAYLOADS.get(tech_fp, {})
            if action_type in tech_specific:
                action_params["_tech_payloads"] = tech_specific[action_type]
                action_params["_tech_fingerprint"] = tech_fp

        return thought, action_type, action_params

    def _build_system_prompt(self) -> str:
        tools_desc = "\n".join(f"- {k}: {v}" for k, v in TOOL_DESCRIPTIONS.items())
        return (
            "You are an autonomous security testing AI. You operate in a ReAct loop:\n"
            "1. THINK: Analyze current state, findings, and observations\n"
            "2. ACT: Choose one tool from the available list\n"
            "3. OBSERVE: Result will be provided in next iteration\n\n"
            "Available tools:\n" + tools_desc + "\n\n"
            "Output ONLY valid JSON with keys: thought (str), action (str), params (dict).\n"
            "Example: {\"thought\": \"Checking for SQLi on login page\", \"action\": \"http_request\", "
            "\"params\": {\"method\": \"GET\", \"path\": \"/login\"}}\n"
            "Use 'done' action with {\"summary\": \"...\"} when testing is complete."
        )

    def _build_react_prompt(self, iteration: int) -> str:
        recent = self.history[-5:] if self.history else []
        history_lines = []
        for s in recent:
            history_lines.append(
                f"  Iter {s.iteration}: thought='{s.thought[:100]}' "
                f"→ action={s.action_type} → '{s.observation[:150]}'"
            )

        finding_summary = f"{len(self.findings)} findings so far"
        if self.findings:
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in self.findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            finding_summary += " | " + " ".join(f"{k}={v}" for k, v in sev_counts.items() if v > 0)

        memory_ctx = self.memory.get_episodic_context(8)
        working_ctx = self.memory.get_working_context()
        rag_ctx = self.session_context.get("rag", "")
        handoff_ctx = self.context.get("handoff_context", "")

        return (
            f"Target: {self.target}\n"
            f"Iteration: {iteration}/{self.max_iterations}\n"
            f"Discovered URLs: {self.discovered_urls[:5]}\n"
            f"{finding_summary}\n"
            f"Recent history:\n" + ("\n".join(history_lines) or "  (none)\n") +
            f"\nInstruction: {self.instruction or 'None'}\n"
            f"Scope: {self.scope or 'None'}\n\n"
            f"{memory_ctx}\n\n"
            f"{working_ctx}\n\n"
            f"{rag_ctx}\n\n"
            f"{handoff_ctx}\n\n"
            "THINK about what you know, what you've found, and what to try next.\n"
            "Then pick ONE action from the available tools."
        )

    async def _act(self, action_type: str, params: Dict[str, Any]) -> Any:
        handler_map = {
            "http_request": self._act_http_request,
            "scan_endpoints": self._act_scan_endpoints,
            "test_sqli": self._act_test_sqli,
            "test_xss": self._act_test_xss,
            "test_ssrf": self._act_test_ssrf,
            "analyze_response": self._act_analyze_response,
            "nuclei_scan": self._act_nuclei_scan,
            "search_skills": self._act_search_skills,
            "emit_finding": self._act_emit_finding,
        }
        handler = handler_map.get(action_type)
        if not handler:
            return f"Unknown action: {action_type}"
        return await handler(params)

    async def _act_http_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        method = params.get("method", "GET").upper()
        path = params.get("path", "/")
        headers = params.get("headers", {})
        body = params.get("body", None)
        url = self._build_url(path)

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            if method == "POST":
                resp = await client.post(url, headers=headers, content=body)
            else:
                resp = await client.get(url, headers=headers)

        return {
            "url": str(resp.url),
            "status": resp.status_code,
            "length": len(resp.text),
            "headers": dict(resp.headers),
            "preview": resp.text[:500],
        }

    async def _act_scan_endpoints(self, params: Dict[str, Any]) -> List[str]:
        size = params.get("wordlist_size", 20)
        base = self.target.rstrip("/")
        paths = self._load_wordlist()[:size]
        found = []

        async def try_path(path: str) -> Optional[str]:
            url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
                    r = await c.get(url)
                    if r.status_code < 500:
                        return url
            except Exception:
                pass
            return None

        results = await asyncio_gather(*[try_path(p) for p in paths], return_exceptions=True)
        found = [r for r in results if isinstance(r, str)]
        self.discovered_urls.extend(found)
        return found

    def _get_param_hints(self, action_type: str) -> List[str]:
        common_params = {
            "test_sqli": ["id", "q", "page", "cat", "product", "user", "name", "email", "order", "search", "pid", "view", "file"],
            "test_xss":  ["q", "search", "name", "comment", "message", "text", "input", "user", "bio", "title", "ref", "redirect"],
            "test_ssrf": ["url", "page", "file", "path", "dest", "redirect", "proxy", "fetch", "include", "import", "load", "href"],
        }
        return common_params.get(action_type, ["id", "q"])

    async def _act_test_sqli(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", self.target)
        param = params.get("param", "id")
        method = params.get("method", "GET")
        payloads = params.get("_tech_payloads") or SPECIALIST_PAYLOADS["generic"]["sqli"]
        results = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for payload in payloads:
                try:
                    if method == "POST":
                        r = await client.post(url, data={param: payload})
                    else:
                        r = await client.get(url, params={param: payload})
                    results.append({"payload": payload, "status": r.status_code, "length": len(r.text)})
                except Exception as e:
                    results.append({"payload": payload, "error": str(e)})

        # Look for SQL error indicators
        sql_errors = ["sql", "mysql", "syntax", "odbc", "driver", "ora-", "postgresql"]
        findings = []
        for r in results:
            if r.get("error"):
                continue
            for err in sql_errors:
                if err in str(r).lower():
                    findings.append(r)
                    break

        await self._emit_thought(f"SQLi scan: tested {len(payloads)} payloads, {len(findings)} suspicious", "analyzing", "sqli")

        return {"payloads_tested": len(payloads), "suspicious": findings, "results": results[:3]}

    async def _act_test_xss(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", self.target)
        param = params.get("param", "q")
        method = params.get("method", "GET")
        payloads = params.get("_tech_payloads") or SPECIALIST_PAYLOADS["generic"]["xss"]
        results = []

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for payload in payloads:
                try:
                    if method == "POST":
                        r = await client.post(url, data={param: payload})
                    else:
                        r = await client.get(url, params={param: payload})
                    reflected = payload in r.text
                    results.append({"payload": payload, "status": r.status_code, "reflected": reflected})
                except Exception as e:
                    results.append({"payload": payload, "error": str(e)})

        reflected = [r for r in results if r.get("reflected")]
        return {"payloads_tested": len(payloads), "reflected": reflected, "results": results}

    async def _act_test_ssrf(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", self.target)
        param = params.get("param", "url")
        payloads = params.get("_tech_payloads") or SPECIALIST_PAYLOADS["generic"]["ssrf"]
        results = []
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            for payload in payloads:
                try:
                    r = await client.get(url, params={param: payload})
                    results.append({"payload": payload, "status": r.status_code, "length": len(r.text)})
                except Exception as e:
                    results.append({"payload": payload, "error": str(e)})
        return {"payloads_tested": len(payloads), "results": results}

    async def _act_analyze_response(self, params: Dict[str, Any]) -> Dict[str, Any]:
        snippet = params.get("response_snippet", "")
        system = "Analyze this HTTP response for security issues. List any vulnerabilities, exposed data, or misconfigurations."
        response = await self.llm_client.generate(
            prompt=f"Analyze this response:\n\n{snippet[:2000]}",
            system=system, max_tokens=500,
        )
        return {"analysis": response.content}

    async def _act_nuclei_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tags = params.get("template_tags", [])
        url = params.get("url", self.target)
        if not tags:
            return {"error": "No nuclei tags specified", "info": "Try: tech-detect, exposure, cve"}
        try:
            findings = await self._run_nuclei_tags(tags, [url])
            return {"findings": len(findings), "details": [str(f)[:200] for f in findings[:5]]}
        except Exception as e:
            return {"error": str(e)}

    async def _act_search_skills(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        query = params.get("query", "")
        self.skill_registry.build_index()
        results = self.skill_registry.search(query, top_k=5)
        return [{"name": r.get("name", ""), "description": r.get("description", "")[:200]} for r in results]

    async def _act_emit_finding(self, params: Dict[str, Any]) -> str:
        finding = Finding(
            title=str(params.get("title", "AI-discovered issue")),
            description=str(params.get("description", "")),
            severity=str(params.get("severity", "medium")).lower(),
            category=str(params.get("category", "autonomous")),
            evidence=str(params.get("evidence", ""))[:500],
            remediation=str(params.get("remediation", "")),
            confidence=float(params.get("confidence", 0.7)),
        )
        self.add_finding(finding)
        await self._emit_thought(f"Finding: {finding.title} ({finding.severity})", "finding", "discovery")
        return f"Finding recorded: {finding.title}"

    async def _quick_connectivity_check(self):
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(self.target.rstrip("/") + "/")
                logger.info(f"{self.name}: Target reachable (HTTP {r.status_code})")
                await self._emit_thought(f"Target reachable: HTTP {r.status_code}", "observation", "recon")
        except Exception as e:
            logger.warning(f"{self.name}: Target unreachable: {e}")
            await self._emit_thought(f"Target unreachable: {e}", "error", "recon")

    async def _discover_urls(self) -> List[str]:
        base = self.target.rstrip("/")
        paths = self._load_wordlist()[:40]
        found = []

        async def try_path(path: str) -> Optional[str]:
            url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
                    r = await c.get(url)
                    if r.status_code < 500:
                        return url
            except Exception:
                pass
            return None

        results = await asyncio_gather(*[try_path(p) for p in paths], return_exceptions=True)
        found = [r for r in results if isinstance(r, str)]
        return found

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        base = self.target.rstrip("/")
        if not (base.startswith("http://") or base.startswith("https://")):
            base = f"http://{base}"
        norm_path = path if path.startswith("/") else f"/{path}"
        return f"{base}{norm_path}"

    def _parse_react_response(self, content: str) -> Optional[Dict[str, Any]]:
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
        try:
            return json.loads(text)
        except Exception:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except Exception:
                    pass
        return None

    def _no_ai_fallback(self) -> AgentResult:
        self.add_finding(Finding(
            title="Autonomous mode unavailable",
            description="AI API keys not configured",
            severity="info", category="configuration",
            evidence="No API key detected",
            remediation="Configure API key for autonomous mode",
            confidence=1.0, validation_status="unvalidated_poc_missing",
        ))
        return AgentResult(
            agent_name=self.name, status=self.status,
            findings=self.findings, execution_time=0,
            metadata={"autonomous_enabled": False},
        )

    def _load_wordlist(self) -> List[str]:
        from pathlib import Path
        paths = ["/"]
        wordlist_path = Path(__file__).parent.parent / "data" / "wordlists" / "default_pentest_wordlist.txt"
        try:
            if wordlist_path.exists():
                text = wordlist_path.read_text()
                paths.extend(p.strip() for p in text.splitlines() if p.strip() and not p.startswith(("#", "!")))
        except Exception:
            pass
        return paths


def asyncio_gather(*args, **kwargs):
    import asyncio
    return asyncio.gather(*args, **kwargs)
