"""
WafDetectionAgent — Detects WAF/firewall using wafw00f + AI analysis,
then auto-deploys WAF bypass engine for intelligent payload selection.
Integration pipeline:
  1. Detect WAF (wafw00f + headers + behavior)
  2. Fingerprint WAF vendor via response headers
  3. Select bypass techniques from WAFBypassEngine
  4. Report findings with bypass payloads
  5. AI selects optimal Nmap/Naabu flags considering WAF type
"""
import asyncio
import json
from typing import Optional, List, Dict, Any
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.llm_client import LLMClient
from itzraven.core.logger import get_logger

logger = get_logger()

NMAP_FLAG_STRATEGIES = {
    "no_waf": {
        "label": "No WAF detected — Aggressive scan",
        "nmap_flags": "-sS -sV -sC -p- -T4 --max-retries 2",
        "naabu_flags": "-p - -rate 3000",
        "reason": "No firewall detected, use full aggressive scan",
    },
    "waf_generic": {
        "label": "WAF detected — Stealth scan with evasion",
        "nmap_flags": "-sS -sV -p- -T2 -f --data-length 200 --max-retries 1 --min-rate 100",
        "naabu_flags": "-p - -rate 500 -s",
        "reason": "WAF detected, use fragmented packets + slower rate to evade",
    },
    "waf_cloudflare": {
        "label": "Cloudflare detected — Origin scan via IP",
        "nmap_flags": "-sS -sV -p- -T4 --exclude-ports 80,443",
        "naabu_flags": "-p 22,8080,8443,3306,6379,27017 -rate 2000",
        "reason": "Cloudflare detected, scan non-proxied ports for origin IP",
    },
    "waf_aws": {
        "label": "AWS WAF detected — Origin-focused scan",
        "nmap_flags": "-sS -sV -p- -T3 --exclude-ports 80,443",
        "naabu_flags": "-p 22,8080,8443 -rate 1500",
        "reason": "AWS WAF detected, focus on non-standard ports",
    },
    "waf_modsec": {
        "label": "ModSecurity detected — Stealth scan",
        "nmap_flags": "-sT -sV -p- -T2 -f --data-length 150 --max-retries 1 --min-rate 50",
        "naabu_flags": "-p - -rate 200 -s",
        "reason": "ModSecurity detected, use connect scan + fragmentation",
    },
    "firewall_detected": {
        "label": "Firewall detected — Full stealth mode",
        "nmap_flags": "-sT -Pn -sV -p- -T1 -f --mtu 24 -D RND:5 --max-retries 1",
        "naabu_flags": "-p - -rate 100 -s -retries 1",
        "reason": "Firewall detected, use decoy scan + slow rate + fragmentation",
    },
}


class WafDetectionAgent(BaseAgent):
    """Detects WAF/firewall and uses AI to select optimal port scan flags."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("WAF Detection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.llm = LLMClient()
        self.detected_wafs: List[str] = []
        self.selected_strategy: str = "no_waf"
        self.nmap_flags: str = NMAP_FLAG_STRATEGIES["no_waf"]["nmap_flags"]
        self.naabu_flags: str = NMAP_FLAG_STRATEGIES["no_waf"]["naabu_flags"]
        self.firewall_detected: bool = False
        self.bypass_payloads: List[str] = []

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing WAF/firewall for {self.target}")

        await self._detect_waf_wafw00f()
        if not self.detected_wafs:
            await self._detect_waf_headers()
        if not self.detected_wafs:
            await self._detect_firewall_behavior()

        await self._attempt_waf_bypass()
        await self._ai_select_scan_strategy()

        if self.detected_wafs:
            bypass_desc = ""
            if self.bypass_payloads:
                bypass_desc = f"\nBypass payloads ready: {len(self.bypass_payloads)} techniques"
            self.add_finding(Finding(
                title=f"WAF/Firewall Detected: {', '.join(self.detected_wafs)}",
                description=f"Using scan strategy: {NMAP_FLAG_STRATEGIES.get(self.selected_strategy, {}).get('label', 'standard')}{bypass_desc}",
                severity="medium",
                category="waf_detection",
                evidence=f"WAF: {self.detected_wafs}, Strategy: {self.selected_strategy}, Nmap: {self.nmap_flags}",
                confidence=0.85,
            ))

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={
                "waf_detected": self.detected_wafs,
                "firewall_detected": self.firewall_detected,
                "selected_strategy": self.selected_strategy,
                "nmap_flags": self.nmap_flags,
                "naabu_flags": self.naabu_flags,
                "nmap_command": f"nmap {self.nmap_flags} {self.target}",
                "naabu_command": f"naabu {self.naabu_flags} {self.target}",
                "bypass_payloads": self.bypass_payloads[:10],
                "bypass_count": len(self.bypass_payloads),
            },
        )

    async def _detect_waf_wafw00f(self) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "wafw00f", self.target, "-o", "json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                if stdout:
                    data = json.loads(stdout.decode())
                    if isinstance(data, list):
                        for entry in data:
                            waf_name = entry.get("name", "") if isinstance(entry, dict) else ""
                            if waf_name and waf_name.lower() != "generic":
                                self.detected_wafs.append(waf_name)
                    elif isinstance(data, dict):
                        waf_name = data.get("name", "") or data.get("firewall", "")
                        if waf_name and waf_name.lower() != "generic":
                            self.detected_wafs.append(waf_name)
                if not self.detected_wafs:
                    pass
            except asyncio.TimeoutError:
                proc.kill()
                logger.debug("wafw00f timed out")
        except Exception as e:
            logger.debug(f"wafw00f failed: {e}")

    async def _detect_waf_headers(self) -> None:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(f"https://{self.target}" if not self.target.startswith("http") else self.target)
                headers = dict(resp.headers)
                body = resp.text[:5000].lower()
                combined = str(headers).lower() + body

                waf_signatures = {
                    "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
                    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "aws-waf"],
                    "Cloudfront": ["x-amz-cf-id", "cloudfront"],
                    "ModSecurity": ["mod_security", "modsecurity", "no-store"],
                    "F5 BIG-IP": ["bigip", "f5", "x-application-context"],
                    "Akamai": ["akamai", "x-akamai"],
                    "Sucuri": ["sucuri", "x-sucuri"],
                    "Barracuda": ["barracuda"],
                    "Fortinet": ["fortigate", "fortiweb"],
                    "Imperva": ["incapsula", "x-iinfo"],
                    "SafeDog": ["safedog", "waf"],
                    "Comodo": ["comodo", "cwatch"],
                    "Radware": ["radware", "appwall"],
                    "Wordfence": ["wordfence"],
                    "Varnish": ["x-varnish"],
                }
                for waf_name, sigs in waf_signatures.items():
                    if any(s in combined for s in sigs):
                        self.detected_wafs.append(waf_name)
        except Exception as e:
            logger.debug(f"Header WAF detection failed: {e}")

    async def _detect_firewall_behavior(self) -> None:
        import httpx
        malicious_paths = ["/admin", "/../../etc/passwd", "/?id=1 UNION SELECT 1", "/<script>alert(1)</script>",
                           "/.env", "/wp-admin", "/../../../etc/shadow", "/?page=../../../etc/passwd"]
        blocked_count = 0
        total = 0
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
                normal = await client.get(f"https://{self.target}" if not self.target.startswith("http") else self.target, timeout=8)
                normal_status = normal.status_code
                for path in malicious_paths[:5]:
                    total += 1
                    try:
                        url = f"https://{self.target}{path}" if not self.target.startswith("http") else f"{self.target.rstrip('/')}{path}"
                        resp = await client.get(url, timeout=8)
                        if resp.status_code in [403, 406, 429, 503] or resp.status_code != normal_status:
                            blocked_count += 1
                        if any(h in dict(resp.headers).get("content-type", "").lower() for h in ["html", "text"]):
                            ct = resp.text[:1000].lower()
                            if any(kw in ct for kw in ["blocked", "denied", "forbidden", "waf", "firewall", "attack detected", "malicious"]):
                                blocked_count += 1
                    except Exception:
                        blocked_count += 1
                        total += 1
            if total > 0 and (blocked_count / total) > 0.6:
                self.firewall_detected = True
                if not self.detected_wafs:
                    self.detected_wafs.append("Generic WAF/Firewall")
        except Exception as e:
            logger.debug(f"Behavioral firewall detection failed: {e}")

    async def _attempt_waf_bypass(self) -> None:
        """Use WAFBypassEngine to select bypass payloads for detected WAF.

        Integrates with the WAF Bypass Engine to get context-aware
        bypass techniques that downstream agents can use.
        """
        if not self.detected_wafs:
            return

        try:
            from itzraven.agents.waf_bypass_engine import get_waf_bypass
            engine = get_waf_bypass()

            waf_type = self._map_waf_to_vendor(self.detected_wafs[0])

            self.bypass_payloads = engine.get_payloads(waf_type, count=10)
            if not self.bypass_payloads:
                self.bypass_payloads = engine.get_payloads("unknown", count=10)

            if self.bypass_payloads:
                bypass_context = engine.get_bypass_context(waf_type, stealth=True)
                self.add_finding(Finding(
                    title=f"WAF Bypass Techniques Ready — {len(self.bypass_payloads)} payloads",
                    description=f"Detected WAF: {self.detected_wafs[0]} → {waf_type}\n"
                                f"Using {len(self.bypass_payloads)} bypass payloads for testing",
                    severity="info",
                    category="waf_bypass",
                    evidence=f"Bypass payloads: {self.bypass_payloads[:5]}",
                    confidence=0.9,
                ))
                logger.info(f"{self.name}: {len(self.bypass_payloads)} bypass payloads loaded for {waf_type}")
        except Exception as e:
            logger.debug(f"WAF bypass engine failed: {e}")

    @staticmethod
    def _map_waf_to_vendor(detected_name: str) -> str:
        """Map detected WAF name to WAFBypassEngine vendor name."""
        name = detected_name.lower()
        mapping = {
            "cloudflare": "cloudflare",
            "aws": "aws_waf",
            "amazon": "aws_waf",
            "modsecurity": "modsecurity",
            "mod_security": "modsecurity",
            "f5": "f5_asm",
            "big-ip": "f5_asm",
            "bigip": "f5_asm",
            "akamai": "akamai",
            "imperva": "imperva",
            "incapsula": "imperva",
            "sucuri": "sucuri",
            "wordfence": "wordfence",
            "barracuda": "barracuda",
        }
        for key, vendor in mapping.items():
            if key in name:
                return vendor
        return "unknown"

    async def _ai_select_scan_strategy(self) -> None:
        if not self.detected_wafs and not self.firewall_detected:
            self.selected_strategy = "no_waf"
            self.nmap_flags = NMAP_FLAG_STRATEGIES["no_waf"]["nmap_flags"]
            self.naabu_flags = NMAP_FLAG_STRATEGIES["no_waf"]["naabu_flags"]
            return

        waf_lower = " ".join(w.lower() for w in self.detected_wafs)

        if "cloudflare" in waf_lower:
            self.selected_strategy = "waf_cloudflare"
        elif any(k in waf_lower for k in ["aws", "amazon"]):
            self.selected_strategy = "waf_aws"
        elif any(k in waf_lower for k in ["modsecurity", "mod_security"]):
            self.selected_strategy = "waf_modsec"
        elif self.firewall_detected:
            self.selected_strategy = "firewall_detected"
        elif self.detected_wafs:
            self.selected_strategy = "waf_generic"
        else:
            self.selected_strategy = "no_waf"

        strategy = NMAP_FLAG_STRATEGIES.get(self.selected_strategy, NMAP_FLAG_STRATEGIES["no_waf"])
        self.nmap_flags = strategy["nmap_flags"]
        self.naabu_flags = strategy["naabu_flags"]

        try:
            prompt = f"""Target: {self.target}
Detected WAF/Firewall: {self.detected_wafs or 'None'}
Firewall behavior detected: {self.firewall_detected}

Choose the BEST nmap scan strategy from these options:
{json.dumps(NMAP_FLAG_STRATEGIES, indent=2)}

Return ONLY a JSON: {{"strategy": "key_name", "reason": "why this strategy"}}"""
            resp = await self.llm.generate(prompt=prompt, max_tokens=200, temperature=0.3)
            from itzraven.core.json_utils import extract_json_safe
            parsed = extract_json_safe(resp.content.strip(), {})
            ai_strategy = parsed.get("strategy", self.selected_strategy)
            if ai_strategy in NMAP_FLAG_STRATEGIES:
                self.selected_strategy = ai_strategy
                strategy = NMAP_FLAG_STRATEGIES[ai_strategy]
                self.nmap_flags = strategy["nmap_flags"]
                self.naabu_flags = strategy["naabu_flags"]
                logger.info(f"{self.name}: AI selected strategy '{ai_strategy}': {strategy['label']}")
        except Exception as e:
            logger.debug(f"AI strategy selection failed, using heuristic: {e}")
