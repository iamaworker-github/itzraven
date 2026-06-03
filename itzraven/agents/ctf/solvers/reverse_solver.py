import os
import re
import struct
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGIC_32 = b"\xfe\xed\xfa\xce"
MACHO_MAGIC_64 = b"\xfe\xed\xfa\xcf"
CLASS_MAGIC = b"\xca\xfe\xba\xbe"
PYC_MAGIC_PREFIX = b"\x6f\x0d\x0d\x0a"


class ReverseSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Reverse Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for reverse engineering artifacts")

        findings = []
        target_path = self.target

        try:
            if os.path.isfile(target_path):
                findings.extend(self._check_magic_bytes(target_path))
                findings.extend(self._search_hardcoded_strings(target_path))
                findings.extend(await self._try_decompile_pyc(target_path))
                findings.extend(self._check_elf_sections(target_path))

                flags = self.flag_extractor.extract_from_file(target_path)
                for flag in flags:
                    f = Finding(
                        title="Flag Found in Reverse Engineering Data",
                        description="Extracted flag from reverse engineering analysis",
                        severity="critical",
                        category="CTF",
                        evidence=flag,
                        confidence=1.0,
                    )
                    self.add_finding(f)
                    findings.append(f)
            else:
                flags = self.flag_extractor.extract(target_path)
                for flag in flags:
                    f = Finding(
                        title="Flag Found in Target",
                        description="Extracted flag from target string",
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
                title="Reverse Engineering Error",
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

    def _check_magic_bytes(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(16)

            formats = []
            if header.startswith(ELF_MAGIC):
                ei_class = header[4] if len(header) > 4 else 0
                ei_data = header[5] if len(header) > 5 else 0
                arch = "64-bit" if ei_class == 2 else "32-bit"
                endian = "little" if ei_data == 1 else "big"
                formats.append(f"ELF {arch} {endian} endian")
            if header.startswith(PE_MAGIC):
                formats.append("PE (Windows executable)")
            if header.startswith(MACHO_MAGIC_32) or header.startswith(MACHO_MAGIC_64):
                formats.append("Mach-O (macOS executable)")
            if header.startswith(CLASS_MAGIC):
                formats.append("Java class file")
            if header[:4] == PYC_MAGIC_PREFIX:
                formats.append("Python bytecode (.pyc)")

            if formats:
                for fmt in formats:
                    f = Finding(
                        title=f"Binary Format Detected: {fmt}",
                        description=f"File identified as {fmt}",
                        severity="info",
                        category="CTF",
                        evidence=f"Magic bytes: {header[:8].hex()}",
                        confidence=0.95,
                    )
                    self.add_finding(f)
                    results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Magic bytes check error: {e}")
        return results

    def _search_hardcoded_strings(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            strings = re.findall(rb"[\x20-\x7e]{6,}", data)
            decoded_strings = [s.decode("ascii", errors="replace") for s in strings]

            interesting = [s for s in decoded_strings if any(
                kw in s.lower() for kw in ["flag", "ctf", "password", "secret",
                                            "key", "token", "admin", "debug",
                                            "license", "register", "crack"]
            )]
            for s in interesting[:20]:
                f = Finding(
                    title="Hardcoded String Found",
                    description=f"Interesting hardcoded string: {s[:300]}",
                    severity="medium",
                    category="CTF",
                    evidence=s[:200],
                    confidence=0.7,
                )
                self.add_finding(f)
                results.append(f)

            base64_strings = re.findall(rb"[A-Za-z0-9+/]{40,}={0,2}", data)
            for b64 in base64_strings[:5]:
                f = Finding(
                    title="Potential Base64 Encoded Payload Found",
                    description=f"Base64-like blob found: {b64[:100].decode('ascii', errors='replace')}",
                    severity="medium",
                    category="CTF",
                    evidence=b64[:100].decode("ascii", errors="replace"),
                    confidence=0.5,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Hardcoded strings search error: {e}")
        return results

    async def _try_decompile_pyc(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(4)
            if header != PYC_MAGIC_PREFIX:
                return results

            f = Finding(
                title="Python Bytecode Detected",
                description="File is a .pyc (compiled Python) — consider decompiling with uncompyle6 or pycdc",
                severity="info",
                category="CTF",
                evidence=f"PYC magic bytes found in: {path}",
                confidence=0.95,
            )
            self.add_finding(f)
            results.append(f)

            if self.shell:
                try:
                    result = await self.shell.execute(f"strings '{path}' | grep -E '.{50,}' | head -10")
                    if result and result.output:
                        f2 = Finding(
                            title="Long Strings from PYC",
                            description=f"Extracted long strings from bytecode: {result.output[:500]}",
                            severity="low",
                            category="CTF",
                            evidence=result.output[:300],
                            confidence=0.5,
                        )
                        self.add_finding(f2)
                        results.append(f2)
                except Exception:
                    pass
        except (IOError, OSError) as e:
            logger.debug(f"PYC decompile check error: {e}")
        return results

    async def _check_elf_sections(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            if not header.startswith(ELF_MAGIC):
                return results

            f = Finding(
                title="ELF Binary — Section Analysis Recommended",
                description="ELF binary detected — use readelf -S to list sections, objdump -d to disassemble",
                severity="info",
                category="CTF",
                evidence=f"ELF binary: {path}",
                confidence=0.9,
            )
            self.add_finding(f)
            results.append(f)

            if self.shell:
                try:
                    result = await self.shell.execute(f"readelf -S '{path}' 2>/dev/null | head -30")
                    if result and result.output:
                        sections = result.output
                        unusual = [line for line in sections.split("\n") if "NOTE" in line or "." in line.lower()]
                        if unusual:
                            f2 = Finding(
                                title="ELF Sections Found",
                                description=f"ELF sections:\n{sections[:500]}",
                                severity="low",
                                category="CTF",
                                evidence=sections[:300],
                                confidence=0.5,
                            )
                            self.add_finding(f2)
                            results.append(f2)
                except Exception:
                    pass
        except (IOError, OSError) as e:
            logger.debug(f"ELF section check error: {e}")
        return results
