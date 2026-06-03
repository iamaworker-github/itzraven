import os
import re
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


IMAGE_MAGIC_BYTES = {
    b"\x89PNG": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"BM": "BMP",
}


class StegoSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Stego Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for steganographic data")

        findings = []
        target_path = self.target

        try:
            if os.path.isfile(target_path):
                findings.extend(self._check_lsb(target_path))
                findings.extend(self._check_metadata(target_path))
                findings.extend(await self._check_embedded_data(target_path))
                findings.extend(self._check_file_format(target_path))

                flags = self.flag_extractor.extract_from_file(target_path)
                for flag in flags:
                    f = Finding(
                        title="Flag Found in Stego Data",
                        description="Extracted flag from steganographic analysis",
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
                title="Stego Analysis Error",
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

    def _check_lsb(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            lsb_bits = []
            for i in range(min(len(data), 8000)):
                lsb_bits.append(data[i] & 1)

            if len(lsb_bits) < 8:
                return results

            lsb_bytes = []
            for i in range(0, len(lsb_bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | lsb_bits[i + j]
                lsb_bytes.append(byte_val)

            text = bytes(lsb_bytes[:100]).decode("latin-1", errors="replace")
            printable = sum(1 for c in text if 32 <= ord(c) <= 126)
            ratio = printable / max(len(text), 1)

            if ratio > 0.8 and len(text) > 10:
                f = Finding(
                    title="Potential LSB Steganography Detected",
                    description=f"LSB extraction reveals readable text: {text[:200]}",
                    severity="medium",
                    category="CTF",
                    evidence=f"LSB decoded preview: {text[:100]}",
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"LSB check error: {e}")
        return results

    def _check_metadata(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            text_data = data.decode("latin-1", errors="replace")

            txt_patterns = re.findall(r"(?:Author|Copyright|Description|Comment|Software|Creator):\s*(.{1,200})", text_data, re.IGNORECASE)
            for match in txt_patterns:
                stripped = match.strip()
                if stripped and len(stripped) > 3:
                    f = Finding(
                        title="Metadata Field Found",
                        description=f"Extracted metadata: {stripped[:300]}",
                        severity="low",
                        category="CTF",
                        evidence=stripped[:200],
                        confidence=0.5,
                    )
                    self.add_finding(f)
                    results.append(f)

            exif_like = re.findall(r"exif|iptc|xmp", text_data, re.IGNORECASE)
            if exif_like:
                f2 = Finding(
                    title="EXIF/IPTC/XMP Metadata Section Detected",
                    description="File contains image metadata sections that may hold hidden data",
                    severity="low",
                    category="CTF",
                    evidence="Metadata sections found in file",
                    confidence=0.4,
                )
                self.add_finding(f2)
                results.append(f2)
        except (IOError, OSError) as e:
            logger.debug(f"Metadata check error: {e}")
        return results

    async def _check_embedded_data(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            for magic, fmt_name in IMAGE_MAGIC_BYTES.items():
                offsets = [m.start() for m in re.finditer(re.escape(magic), data)]
                if len(offsets) > 1:
                    f = Finding(
                        title=f"Multiple {fmt_name} Headers Found",
                        description=f"Found {len(offsets)} {fmt_name} headers, suggesting embedded data",
                        severity="medium",
                        category="CTF",
                        evidence=f"Offsets: {offsets[:10]}",
                        confidence=0.7,
                    )
                    self.add_finding(f)
                    results.append(f)

            trailer_markers = [b"IEND", b"\xff\xd9"]
            marker_counts = {}
            for marker in trailer_markers:
                count = data.count(marker)
                if count > 1:
                    marker_counts[marker.hex()] = count

            if marker_counts:
                f2 = Finding(
                    title="Multiple Image Trailers Detected",
                    description=f"Found multiple image trailer markers suggesting concatenated images: {marker_counts}",
                    severity="high",
                    category="CTF",
                    evidence=str(marker_counts),
                    confidence=0.75,
                )
                self.add_finding(f2)
                results.append(f2)

            zip_magic = b"PK\x03\x04"
            if zip_magic in data:
                f3 = Finding(
                    title="ZIP Archive Embedded in File",
                    description="ZIP archive headers found within the file, suggesting appended archive",
                    severity="high",
                    category="CTF",
                    evidence="PK zip header found at non-zero offset",
                    confidence=0.8,
                )
                self.add_finding(f3)
                results.append(f3)
        except (IOError, OSError) as e:
            logger.debug(f"Embedded data check error: {e}")
        return results

    def _check_file_format(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(4)

            for magic, fmt_name in IMAGE_MAGIC_BYTES.items():
                if header.startswith(magic):
                    f = Finding(
                        title=f"Image Format Detected: {fmt_name}",
                        description=f"File identified as {fmt_name} image format",
                        severity="info",
                        category="CTF",
                        evidence=f"Magic bytes: {header.hex()}",
                        confidence=0.95,
                    )
                    self.add_finding(f)
                    results.append(f)
                    break
        except (IOError, OSError) as e:
            logger.debug(f"Format check error: {e}")
        return results
