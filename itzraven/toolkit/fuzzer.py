"""
Fuzzing Engine — parameter, header, path, and JSON body fuzzer for web security testing.
"""

import asyncio
import itertools
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

from itzraven.core.logger import get_logger
from itzraven.core.rate_limiter import get_rate_limiter

logger = get_logger()


@dataclass
class FuzzResult:
    parameter: str
    payload: str
    url: str
    status_code: int
    response_size: int
    response_time: float
    match_type: str  # reflected, timing, status_diff, error
    evidence: str = ""
    severity: str = "info"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "parameter": self.parameter,
            "payload": self.payload,
            "url": self.url,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time": round(self.response_time, 3),
            "match_type": self.match_type,
            "evidence": self.evidence[:300],
            "severity": self.severity,
        }


# Common payload lists
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' UNION SELECT NULL--",
    "' OR 1=1--",
    "admin'--",
    "1; DROP TABLE users--",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "${{7*7}}",
    "{{config}}",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "....//....//....//etc/passwd",
]

COMMON_PARAMETERS = [
    "id", "page", "file", "path", "dir", "action", "cmd", "exec",
    "command", "url", "host", "hostname", "redirect", "return",
    "next", "view", "template", "debug", "test", "token", "key",
    "api_key", "apikey", "secret", "pass", "password", "q", "s",
    "search", "query", "name", "user", "username", "email",
]


class FuzzerEngine:
    """Multi-mode fuzzer for web application testing."""

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._rate_limiter = get_rate_limiter()
        self._sem = asyncio.Semaphore(max_concurrent)
        self._baselines: Dict[str, dict] = {}

    async def fuzz_parameters(
        self,
        url: str,
        payloads: Optional[List[str]] = None,
        params: Optional[Dict[str, str]] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        callback: Optional[Callable[[FuzzResult], None]] = None,
    ) -> List[FuzzResult]:
        """Fuzz URL parameters with payloads."""
        payloads = payloads or (XSS_PAYLOADS + SQLI_PAYLOADS)
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        results: List[FuzzResult] = []

        if params:
            param_names = list(params.keys())
        else:
            param_names = list(existing_params.keys()) or COMMON_PARAMETERS[:5]

        tasks = []
        for param_name in param_names:
            for payload in payloads:
                tasks.append(self._fuzz_single(url, param_name, payload, method, headers, callback))

        batch_size = self.max_concurrent
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, FuzzResult):
                    results.append(r)

        return results

    async def fuzz_headers(
        self,
        url: str,
        payloads: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        callback: Optional[Callable[[FuzzResult], None]] = None,
    ) -> List[FuzzResult]:
        """Fuzz HTTP headers (User-Agent, X-Forwarded-For, etc.)."""
        payloads = payloads or SQLI_PAYLOADS + PATH_TRAVERSAL
        fuzz_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host",
            "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
            "User-Agent", "Referer", "X-Requested-With",
        ]
        results = []
        for hdr in fuzz_headers:
            for payload in payloads[:5]:
                test_headers = dict(headers or {})
                test_headers[hdr] = payload
                result = await self._send_and_check(url, method="GET", headers=test_headers)
                if result:
                    result.parameter = hdr
                    result.payload = payload
                    results.append(result)
                    if callback:
                        callback(result)
        return results

    async def fuzz_paths(
        self,
        base_url: str,
        paths: Optional[List[str]] = None,
        callback: Optional[Callable[[FuzzResult], None]] = None,
    ) -> List[FuzzResult]:
        """Fuzz URL paths for common files and directories."""
        paths = paths or [
            "/admin", "/wp-admin", "/.env", "/.git/config",
            "/backup", "/config", "/robots.txt", "/sitemap.xml",
            "/api/", "/swagger.json", "/api-docs", "/graphql",
            "/.well-known/", "/vendor/", "/node_modules/",
        ]
        results = []
        for path in paths:
            full_url = base_url.rstrip("/") + path
            result = await self._send_and_check(full_url, method="GET")
            if result:
                result.parameter = "path"
                result.payload = path
                result.match_type = "status_diff"
                results.append(result)
                if callback:
                    callback(result)
        return results

    async def fuzz_json_body(
        self,
        url: str,
        payloads: Optional[List[str]] = None,
        template: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        callback: Optional[Callable[[FuzzResult], None]] = None,
    ) -> List[FuzzResult]:
        """Fuzz JSON API endpoints with malicious payloads."""
        payloads = payloads or SSTI_PAYLOADS + SQLI_PAYLOADS
        template = template or {"id": 1, "name": "test", "email": "test@test.com"}
        results = []
        for key in template:
            for payload in payloads[:3]:
                body = dict(template)
                body[key] = payload
                result = await self._send_and_check(
                    url, method="POST",
                    headers={**(headers or {}), "Content-Type": "application/json"},
                    content=json.dumps(body),
                )
                if result:
                    result.parameter = key
                    result.payload = payload
                    results.append(result)
                    if callback:
                        callback(result)
        return results

    async def _fuzz_single(
        self, url: str, param: str, payload: str,
        method: str, headers: Optional[Dict], callback: Optional[Callable],
    ) -> Optional[FuzzResult]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        fuzz_url = urlunparse(parsed._replace(query=new_query))
        return await self._send_and_check(fuzz_url, method, headers, callback=callback,
                                          tag_param=param, tag_payload=payload)

    async def _send_and_check(
        self, url: str, method: str = "GET",
        headers: Optional[Dict] = None, content: Optional[str] = None,
        callback: Optional[Callable] = None,
        tag_param: str = "", tag_payload: str = "",
    ) -> Optional[FuzzResult]:
        async with self._sem:
            await self._rate_limiter.acquire(url)
            start = time.time()
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    resp = await client.request(method, url, headers=headers, content=content)
                elapsed = time.time() - start
                body = resp.text
                size = len(body)

                # Baseline comparison
                baseline = self._baselines.get(url)
                match_type = None
                evidence = ""

                # Check for reflection
                if tag_payload and tag_payload in body:
                    match_type = "reflected"
                    evidence = f"Payload reflected in response body"

                # Check for status code anomalies
                if resp.status_code in (500, 502, 503):
                    match_type = match_type or "error"
                    evidence = f"Server error: {resp.status_code}"

                # Check timing-based
                if elapsed > 5.0 and baseline and elapsed > baseline.get("time", 0) * 3:
                    match_type = match_type or "timing"
                    evidence = f"Response time: {elapsed:.2f}s (baseline: {baseline.get('time', 0):.2f}s)"

                if match_type:
                    return FuzzResult(
                        parameter=tag_param or "body",
                        payload=tag_payload or "",
                        url=url,
                        status_code=resp.status_code,
                        response_size=size,
                        response_time=elapsed,
                        match_type=match_type,
                        evidence=evidence,
                    )
            except Exception:
                pass
        return None
