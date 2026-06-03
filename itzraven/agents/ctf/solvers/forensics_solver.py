import os
import re
from typing import List, Dict, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


FILE_HEADERS: Dict[str, bytes] = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff\xe0",
    "GIF": b"GIF8",
    "PDF": b"%PDF",
    "ZIP": b"PK\x03\x04",
    "GZIP": b"\x1f\x8b",
    "BMP": b"BM",
    "TIFF": b"II\x2a\x00",
    "ELF": b"\x7fELF",
    "PCAP": b"\xd4\xc3\xb2\xa1",
    "PCAPNG": b"\x0a\x0d\x0d\x0a",
    "RIFF_AVI": b"RIFF",
    "WAV": b"RIFF",
}


class ForensicsSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Forensics Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for forensic artifacts")

        findings = []
        target_path = self.target

        try:
            if not os.path.isfile(target_path) and self.shell:
                result = await self.shell.execute(f"file {target_path}")
                if result and result.output:
                    target_path = result.output.strip()

            if os.path.isfile(target_path):
                findings.extend(self._check_file_headers(target_path))
                findings.extend(self._search_strings(target_path))
                findings.extend(await self._examine_pcap(target_path))
                findings.extend(self._check_metadata(target_path))

                flags = self.flag_extractor.extract_from_file(target_path)
                for flag in flags:
                    f = Finding(
                        title="Flag Found in Forensics Data",
                        description="Extracted flag from forensic analysis of file",
                        severity="critical",
                        category="CTF",
                        evidence=flag,
                        confidence=1.0,
                    )
                    self.add_finding(f)
                    findings.append(f)
            else:
                logger.warning(f"{self.name}: Target not a file, searching target string")
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
                title="Forensics Analysis Error",
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

    def _check_file_headers(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            detected = []
            for name, magic in FILE_HEADERS.items():
                if header.startswith(magic):
                    detected.append(name)
            if detected:
                f = Finding(
                    title=f"File Format Detected: {', '.join(detected)}",
                    description=f"File header matches known format(s): {', '.join(detected)}",
                    severity="info",
                    category="CTF",
                    evidence=f"Header bytes: {header.hex()}",
                    confidence=0.95,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Header check error: {e}")
        return results

    def _search_strings(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            strings = re.findall(rb"[\x20-\x7e]{6,}", data)
            decoded = [s.decode("ascii", errors="replace") for s in strings]

            keywords = ["flag", "ctf", "password", "secret", "key{", "http", "ftp"]
            for s in decoded:
                for kw in keywords:
                    if kw in s.lower():
                        f = Finding(
                            title=f"Interesting String Found (keyword: {kw})",
                            description=f"Found string containing '{kw}': {s[:300]}",
                            severity="medium",
                            category="CTF",
                            evidence=s[:200],
                            confidence=0.6,
                        )
                        self.add_finding(f)
                        results.append(f)
                        break
        except (IOError, OSError) as e:
            logger.debug(f"String search error: {e}")
        return results

    async def _examine_pcap(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(4)
            if header not in (b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
                return results

            f = Finding(
                title="PCAP Network Capture Detected",
                description="File appears to be a PCAP or PCAPNG network capture",
                severity="medium",
                category="CTF",
                evidence="PCAP magic bytes detected in file header",
                confidence=0.9,
            )
            self.add_finding(f)
            results.append(f)

            if self.shell:
                try:
                    result = await self.shell.execute(f"strings '{path}' | grep -i 'flag\\|ctf\\|password' | head -20")
                    if result and result.output:
                        f2 = Finding(
                            title="Potential Flags from PCAP Strings",
                            description=f"Strings found in PCAP: {result.output[:500]}",
                            severity="high",
                            category="CTF",
                            evidence=result.output[:300],
                            confidence=0.7,
                        )
                        self.add_finding(f2)
                        results.append(f2)
                except Exception:
                    pass
        except (IOError, OSError) as e:
            logger.debug(f"PCAP examine error: {e}")
        return results

    def _check_metadata(self, path: str) -> List[Finding]:
        results = []
        try:
            stat = os.stat(path)
            f = Finding(
                title="File Metadata Available",
                description=f"Size: {stat.st_size} bytes, Modified: {stat.st_mtime}",
                severity="info",
                category="CTF",
                evidence=f"stat: size={stat.st_size}, mtime={stat.st_mtime}",
                confidence=1.0,
            )
            self.add_finding(f)
            results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Metadata check error: {e}")
        return results
