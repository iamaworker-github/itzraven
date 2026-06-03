import os
import re
import base64
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


QR_MODULE_PATTERN = re.compile(
    rb"(?:QR|qrcode|qrstuff)",
    re.IGNORECASE,
)
BRAINFUCK_CHARS = set("<>+-.,[]")


class MiscSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Misc Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for miscellaneous CTF artifacts")

        findings = []
        target_text = self.target

        try:
            if os.path.isfile(target_text):
                with open(target_text, "rb") as f:
                    raw = f.read()
                target_text = raw.decode("latin-1", errors="replace")
            else:
                raw = target_text.encode("latin-1", errors="replace")

            findings.extend(self._check_qr_code(target_text, raw))
            findings.extend(self._check_brainfuck(target_text))
            findings.extend(self._check_unusual_formats(target_text))
            findings.extend(await self._check_sandbox_escape(target_text))

            flags = self.flag_extractor.extract(target_text)
            for flag in flags:
                f = Finding(
                    title="Flag Found in Misc Data",
                    description="Extracted flag from miscellaneous analysis",
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
                title="Misc Analysis Error",
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

    def _check_qr_code(self, text: str, raw: bytes) -> List[Finding]:
        results = []

        qr_keywords = ["qrcode", "qr code", "qrstuff", "zxing", "qrean"]
        for kw in qr_keywords:
            if kw in text.lower():
                f = Finding(
                    title="QR Code Reference Detected",
                    description=f"Reference to QR code technology found: '{kw}'",
                    severity="medium",
                    category="CTF",
                    evidence=f"Keyword: {kw}",
                    confidence=0.5,
                )
                self.add_finding(f)
                results.append(f)
                break

        qr_marker = b"\x7d\x0b"  # common Dense QR marker bytes
        if qr_marker in raw:
            f = Finding(
                title="QR Code Raw Data Detected",
                description="Binary data contains QR code-like markers — consider decoding with a QR library",
                severity="medium",
                category="CTF",
                evidence="QR marker bytes found in binary data",
                confidence=0.4,
            )
            self.add_finding(f)
            results.append(f)

        return results

    def _check_brainfuck(self, text: str) -> List[Finding]:
        results = []
        bf_chars = [c for c in text if c in BRAINFUCK_CHARS]
        if len(bf_chars) > 20:
            ratio = len(bf_chars) / max(len(text.strip()), 1)
            if ratio > 0.6:
                f = Finding(
                    title="Brainfuck Code Detected",
                    description=f"Text contains {len(bf_chars)} brainfuck instructions ({ratio:.0%} of content) — consider running with a brainfuck interpreter",
                    severity="medium",
                    category="CTF",
                    evidence=f"Brainfuck chars: {''.join(bf_chars[:50])}",
                    confidence=0.7,
                )
                self.add_finding(f)
                results.append(f)
        return results

    def _check_unusual_formats(self, text: str) -> List[Finding]:
        results = []

        whitespace_chars = [c for c in text if c in "\t\n " and ord(c) in (0x09, 0x0A, 0x20)]
        if whitespace_chars and len(text.strip()) == 0 and len(text) > 20:
            f = Finding(
                title="Whitespace Encoding Detected",
                description="Text consists entirely of whitespace — could be Whitespace language or steganography",
                severity="medium",
                category="CTF",
                evidence=f"Whitespace-only content ({len(text)} chars)",
                confidence=0.7,
            )
            self.add_finding(f)
            results.append(f)

        hex_like = re.findall(r"(?:[0-9a-fA-F]{2}\s?){20,}", text)
        for match in hex_like:
            f = Finding(
                title="Unusual Format: Hex Stream",
                description="Long hex-encoded stream detected — consider decoding",
                severity="low",
                category="CTF",
                evidence=match[:100],
                confidence=0.5,
            )
            self.add_finding(f)
            results.append(f)

        morse_pattern = re.findall(r"[.\- ]{10,}", text)
        for match in morse_pattern:
            dot_count = match.count(".")
            dash_count = match.count("-")
            if dot_count + dash_count > 10 and dot_count + dash_count > len(match) * 0.5:
                f = Finding(
                    title="Unusual Format: Morse Code",
                    description=f"Potential Morse code detected ({dot_count} dots, {dash_count} dashes)",
                    severity="medium",
                    category="CTF",
                    evidence=match[:100],
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)

        reversed_text = text[::-1]
        flags_rev = self.flag_extractor.extract(reversed_text)
        for flag in flags_rev:
            f = Finding(
                title="Flag Found in Reversed Text",
                description=f"Reversed text contains: {flag}",
                severity="high",
                category="CTF",
                evidence=flag,
                confidence=0.8,
            )
            self.add_finding(f)
            results.append(f)

        return results

    async def _check_sandbox_escape(self, text: str) -> List[Finding]:
        results = []

        pyjail_patterns = [
            r"__import__",
            r"__builtins__",
            r"__globals__",
            r"__subclasses__",
            r"__mro__",
            r"os\.system",
            r"os\.popen",
            r"subprocess",
            r"eval\s*\(",
            r"exec\s*\(",
            r"open\s*\(",
        ]
        for pattern in pyjail_patterns:
            if re.search(pattern, text):
                f = Finding(
                    title="Sandbox Escape Technique Detected",
                    description=f"Potential pyjail/sandbox escape vector: {pattern}",
                    severity="high",
                    category="CTF",
                    evidence=f"Pattern: {pattern}",
                    confidence=0.7,
                )
                self.add_finding(f)
                results.append(f)
                break

        container_indicators = [
            (r"/var/run/docker\.sock", "Docker socket mount"),
            (r"kubectl", "Kubernetes CLI detected"),
            (r"cgroup", "cgroup mount — potential container escape"),
            (r"--privileged", "Privileged container flag"),
            (r"CAP_SYS_ADMIN", "CAP_SYS_ADMIN capability"),
        ]
        for pattern, label in container_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                f = Finding(
                    title=f"Container Escape Indicator: {label}",
                    description=f"Potential container/k8s escape detected: {label}",
                    severity="high",
                    category="CTF",
                    evidence=f"Indicator: {label}",
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)

        return results
