import os
import re
import struct
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


ELF_MAGIC = b"\x7fELF"


class PWNSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="PWN Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing {self.target} for binary exploitation vectors")

        findings = []
        target_path = self.target

        try:
            if os.path.isfile(target_path):
                findings.extend(await self._check_binary_protections(target_path))
                findings.extend(await self._check_format_string(target_path))
                findings.extend(await self._check_buffer_overflow(target_path))
                findings.extend(self._check_rop_gadgets(target_path))

                flags = self.flag_extractor.extract_from_file(target_path)
                for flag in flags:
                    f = Finding(
                        title="Flag Found in PWN Data",
                        description="Extracted flag from binary exploitation analysis",
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
                title="PWN Analysis Error",
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

    async def _check_binary_protections(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            if not header.startswith(ELF_MAGIC):
                return results

            protections = {}
            data = b""
            with open(path, "rb") as f:
                data = f.read()

            ei_class = header[4] if len(header) > 4 else 0
            is_64 = ei_class == 2

            if is_64:
                phoff = struct.unpack("<Q", header[8:16])[0]
                shentsize_offset = 0x3A
            else:
                phoff = struct.unpack("<I", header[0x1C:0x20])[0]
                shentsize_offset = 0x2E

            shoff_pos = 0x28 if is_64 else 0x20
            shoff = struct.unpack("<Q" if is_64 else "<I", data[shoff_pos:shoff_pos + (8 if is_64 else 4)])[0]

            section_name_strtab = struct.unpack("<H", data[0x32:0x34] if is_64 else data[0x30:0x32])[0]

            sections = []
            shent_size = 64 if is_64 else 40
            num_sections = struct.unpack("<H", data[0x3C:0x3E] if is_64 else data[0x30:0x32])[0]

            for i in range(min(num_sections, 50)):
                offset = shoff + i * shent_size
                if offset + shent_size > len(data):
                    break
                if is_64:
                    sh_name, sh_type, sh_flags = struct.unpack("<IIQ", data[offset:offset + 16])
                else:
                    sh_name, sh_type, sh_flags = struct.unpack("<II", data[offset:offset + 8])

                sections.append({
                    "name_idx": sh_name,
                    "type": sh_type,
                    "flags": sh_flags,
                })

            has_exec_stack = False
            gnu_stack = None
            for i, sec in enumerate(sections):
                if sec["type"] == 0x6E475553:
                    gnu_stack = sec
                    break

            if gnu_stack and (gnu_stack["flags"] & 1):
                has_exec_stack = True

            nx_enabled = not has_exec_stack
            protections["NX"] = nx_enabled
            protections["Canary"] = "__stack_chk_fail" in data.decode("latin-1", errors="replace")

            pie_enabled = any(
                sec["type"] == 0x70000001 or (sec["flags"] & 0x2)
                for sec in sections
            ) if sections else False
            protections["PIE"] = pie_enabled

            relro_type = "none"
            for sec in sections:
                if sec.get("name") and "relro" in str(sec):
                    relro_type = "partial"
                    break
            for sec in sections:
                if sec.get("name") and "bind_now" in str(sec):
                    relro_type = "full"
                    break
            protections["RELRO"] = relro_type

            for pname, pvalue in protections.items():
                status_str = "Enabled" if pvalue and pvalue != "none" else "Disabled" if pvalue == "none" else str(pvalue)
                f = Finding(
                    title=f"Binary Protection: {pname} = {status_str}",
                    description=f"{pname} security mitigation is {status_str.lower()}",
                    severity="info" if pvalue else "medium",
                    category="CTF",
                    evidence=f"{pname}: {status_str}",
                    confidence=0.85,
                )
                self.add_finding(f)
                results.append(f)

            if not nx_enabled:
                f = Finding(
                    title="NX Disabled — Shellcode Injection Possible",
                    description="NX (no-execute) is disabled, shellcode on stack/heap may be executable",
                    severity="high",
                    category="CTF",
                    evidence="NX disabled in ELF program headers",
                    confidence=0.9,
                )
                self.add_finding(f)
                results.append(f)

        except (IOError, OSError, struct.error) as e:
            logger.debug(f"Binary protections check error: {e}")
        return results

    async def _check_format_string(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            text = data.decode("latin-1", errors="replace")

            printf_calls = re.findall(r"(printf|sprintf|fprintf|snprintf)\s*\([^)]*%s", text)
            format_strings = re.findall(r'"[^"]*%[nspdx][^"]*"', text)

            if printf_calls or format_strings:
                evidence_parts = []
                if printf_calls:
                    evidence_parts.append(f"printf-like calls: {', '.join(printf_calls[:5])}")
                if format_strings:
                    evidence_parts.append(f"format strings: {', '.join(format_strings[:5])}")

                f = Finding(
                    title="Potential Format String Vulnerability",
                    description=f"Found format string usage patterns that may be exploitable",
                    severity="high",
                    category="CTF",
                    evidence="; ".join(evidence_parts)[:300],
                    confidence=0.65,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Format string check error: {e}")
        return results

    async def _check_buffer_overflow(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read()

            text = data.decode("latin-1", errors="replace")

            dangerous = re.findall(r"(gets|strcpy|strcat|sprintf|vsprintf|scanf|read|recv)\s*\(", text)
            if dangerous:
                f = Finding(
                    title="Dangerous Functions Detected (Buffer Overflow Risk)",
                    description=f"Unsafe functions found: {', '.join(set(dangerous))}",
                    severity="high",
                    category="CTF",
                    evidence=f"Functions: {', '.join(set(dangerous))}",
                    confidence=0.75,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"Buffer overflow check error: {e}")
        return results

    def _check_rop_gadgets(self, path: str) -> List[Finding]:
        results = []
        try:
            with open(path, "rb") as f:
                header = f.read(4)
            if header != ELF_MAGIC:
                return results

            pop_ret_patterns = [
                (b"\x5b\xc3", "pop ebx; ret"),
                (b"\x58\xc3", "pop eax; ret"),
                (b"\x59\xc3", "pop ecx; ret"),
                (b"\x5a\xc3", "pop edx; ret"),
                (b"\x5f\xc3", "pop edi; ret"),
                (b"\x5e\xc3", "pop esi; ret"),
                (b"\x41\x5c\xc3", "inc ecx; pop esp; ret"),
                (b"\xff\xe4", "jmp esp"),
            ]

            with open(path, "rb") as f:
                data = f.read()

            found_gadgets = []
            for pattern, name in pop_ret_patterns:
                if pattern in data:
                    found_gadgets.append(name)

            if found_gadgets:
                f = Finding(
                    title="ROP Gadgets Found",
                    description=f"Useful ROP gadgets detected: {', '.join(found_gadgets)}",
                    severity="medium",
                    category="CTF",
                    evidence=f"Gadgets: {', '.join(found_gadgets)}",
                    confidence=0.7,
                )
                self.add_finding(f)
                results.append(f)
        except (IOError, OSError) as e:
            logger.debug(f"ROP gadgets check error: {e}")
        return results
