import re
import base64
import binascii
from typing import Optional, List
from collections import Counter

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


class CryptoSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Crypto Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for encoded/hidden data")

        findings = []
        data = self.target

        try:
            if self.shell:
                result = await self.shell.execute(f"cat {self.target}")
                if result and result.output:
                    data = result.output

            findings.extend(self._check_base64(data))
            findings.extend(self._check_hex(data))
            findings.extend(self._check_rot(data))
            findings.extend(self._check_xor(data))
            findings.extend(self._check_frequency(data))
            findings.extend(self._check_hash_patterns(data))

            flags = self.flag_extractor.extract(data)
            for flag in flags:
                f = Finding(
                    title="Flag Found in Crypto Data",
                    description="Extracted flag from cryptographic/encoded data",
                    severity="critical",
                    category="CTF",
                    evidence=flag,
                    confidence=1.0,
                )
                self.add_finding(f)
                findings.append(f)

        except Exception as e:
            logger.error(f"{self.name} error: {e}")
            f = Finding(
                title="Crypto Analysis Error",
                description=str(e),
                severity="info",
                category="CTF",
                evidence=str(e),
            )
            self.add_finding(f)
            findings.append(f)

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    def _check_base64(self, data: str) -> List[Finding]:
        results = []
        for match in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", data):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
                if decoded and any(c.isalpha() for c in decoded):
                    f = Finding(
                        title="Base64 Encoded Data Detected",
                        description=f"Decoded base64 string reveals: {decoded[:200]}",
                        severity="medium",
                        category="CTF",
                        evidence=candidate,
                        confidence=0.7,
                    )
                    self.add_finding(f)
                    results.append(f)
            except (binascii.Error, ValueError):
                pass
        return results

    def _check_hex(self, data: str) -> List[Finding]:
        results = []
        for match in re.finditer(r"(?:[0-9a-fA-F]{2}\s?){16,}", data):
            candidate = match.group(0).replace(" ", "")
            try:
                decoded = bytes.fromhex(candidate).decode("utf-8", errors="replace")
                if decoded and any(c.isalpha() for c in decoded):
                    f = Finding(
                        title="Hex-Encoded Data Detected",
                        description=f"Decoded hex string reveals: {decoded[:200]}",
                        severity="medium",
                        category="CTF",
                        evidence=candidate,
                        confidence=0.6,
                    )
                    self.add_finding(f)
                    results.append(f)
            except (ValueError, binascii.Error):
                pass
        return results

    def _check_rot(self, data: str) -> List[Finding]:
        results = []
        for shift in range(1, 26):
            decoded = []
            for ch in data[:500]:
                if "a" <= ch <= "z":
                    decoded.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
                elif "A" <= ch <= "Z":
                    decoded.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
                else:
                    decoded.append(ch)
            result = "".join(decoded)
            common = ["the", "flag", "this", "that", "with", "have", "ctf"]
            score = sum(1 for w in common if w in result.lower())
            if score >= 2:
                f = Finding(
                    title=f"ROT{shift} Cipher Detected",
                    description=f"ROT{shift} decodes (first 200 chars): {result[:200]}",
                    severity="medium",
                    category="CTF",
                    evidence=data[:200],
                    confidence=0.5 + score * 0.1,
                )
                self.add_finding(f)
                results.append(f)
        return results

    def _check_xor(self, data: str) -> List[Finding]:
        results = []
        raw_bytes = data.encode("utf-8", errors="replace")
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in raw_bytes[:200])
            try:
                text = decoded.decode("utf-8", errors="replace")
                if "flag" in text.lower() or "ctf" in text.lower():
                    f = Finding(
                        title="XOR-Encoded Data Detected",
                        description=f"XOR with key 0x{key:02x} reveals: {text[:200]}",
                        severity="medium",
                        category="CTF",
                        evidence=f"XOR key: 0x{key:02x}",
                        confidence=0.8,
                    )
                    self.add_finding(f)
                    results.append(f)
            except (UnicodeDecodeError, ValueError):
                pass
        return results

    def _check_frequency(self, data: str) -> List[Finding]:
        results = []
        letters = [ch.lower() for ch in data if ch.isalpha()]
        if len(letters) < 50:
            return results
        counter = Counter(letters)
        most_common = counter.most_common(1)
        if most_common and most_common[0][0] in ("e", "t", "a"):
            return results
        if most_common and most_common[0][1] / len(letters) > 0.12:
            f = Finding(
                title="Non-Standard Letter Frequency",
                description="Letter frequency distribution suggests substitution cipher",
                severity="low",
                category="CTF",
                evidence=f"Most common: {most_common[0]} ({most_common[0][1]/len(letters):.1%})",
                confidence=0.5,
            )
            self.add_finding(f)
            results.append(f)
        return results

    def _check_hash_patterns(self, data: str) -> List[Finding]:
        results = []
        patterns = {
            "MD5": re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE),
            "SHA1": re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE),
            "SHA256": re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE),
        }
        for name, pattern in patterns.items():
            for match in pattern.finditer(data):
                f = Finding(
                    title=f"{name} Hash Detected",
                    description=f"Found {name} hash: {match.group(0)}",
                    severity="low",
                    category="CTF",
                    evidence=match.group(0),
                    confidence=0.9,
                )
                self.add_finding(f)
                results.append(f)
        return results
