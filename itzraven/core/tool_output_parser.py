"""
Tool Output Parser — parses raw output from security tools into structured graph entities.

Supported tools:
- nmap (XML + normal output)
- nuclei (JSONL output)
- httpx (JSONL output)
- ffuf (JSONL output)
- sqlmap (JSONL output)
- naabu (JSONL output)
- subfinder (JSONL output)
- netexec (text output)
- curl/wget (response analysis)
"""

import ipaddress
import json
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.graph_memory import (
    GraphMemory, Entity, Relationship,
    EntityType, RelationType, get_graph_memory,
)

logger = get_logger()


@dataclass
class ParsedFinding:
    entity_type: EntityType
    entity_name: str
    relation_type: Optional[RelationType] = None
    relation_target: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)
    severity: str = "info"
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type.value,
            "entity_name": self.entity_name,
            "relation_type": self.relation_type.value if self.relation_type else None,
            "relation_target": self.relation_target,
            "properties": self.properties,
            "confidence": self.confidence,
            "tags": self.tags,
            "severity": self.severity,
            "summary": self.summary,
        }


class ToolOutputParser:
    """Parse tool outputs and ingest into graph memory."""

    def __init__(self, graph: Optional[GraphMemory] = None):
        self._graph = graph or get_graph_memory()
        self._findings: List[ParsedFinding] = []

    def parse_nmap_xml(self, xml_content: str, source_ip: str = "") -> List[ParsedFinding]:
        findings = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            for host in root.findall(".//host"):
                ip_el = host.find("address")
                ip = ip_el.get("addr", "") if ip_el is not None else ""
                if not ip:
                    continue
                findings.append(ParsedFinding(
                    entity_type=EntityType.IP_ADDRESS,
                    entity_name=ip,
                    tags=["nmap", "discovered"],
                    confidence=1.0,
                    summary=f"Nmap discovered host: {ip}",
                ))
                status_el = host.find("status")
                if status_el is not None:
                    findings[-1].properties["state"] = status_el.get("state", "")
                hostnames_el = host.find("hostnames")
                if hostnames_el is not None:
                    for hn in hostnames_el.findall("hostname"):
                        hname = hn.get("name", "")
                        if hname:
                            findings.append(ParsedFinding(
                                entity_type=EntityType.DOMAIN,
                                entity_name=hname,
                                relation_type=RelationType.RESOLVES_TO,
                                relation_target=ip,
                                tags=["nmap", "dns"],
                                summary=f"Nmap resolved {hname} → {ip}",
                            ))
                for port_el in host.findall(".//port"):
                    port_id = port_el.get("portid", "")
                    protocol = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    service_el = port_el.find("service")
                    service_name = service_el.get("name", "") if service_el is not None else ""
                    service_product = service_el.get("product", "") if service_el is not None else ""
                    service_version = service_el.get("version", "") if service_el is not None else ""

                    port_key = f"{ip}:{port_id}/{protocol}"
                    findings.append(ParsedFinding(
                        entity_type=EntityType.PORT,
                        entity_name=port_key,
                        properties={
                            "port": int(port_id), "protocol": protocol,
                            "state": state, "service": service_name,
                            "product": service_product, "version": service_version,
                        },
                        relation_type=RelationType.SCANNED_PORT,
                        relation_target=ip,
                        tags=["nmap", f"port_{port_id}", service_name],
                        confidence=0.95 if state == "open" else 0.5,
                        summary=f"Port {port_id}/{protocol} {state} - {service_name} {service_product} {service_version}",
                    ))
                    if service_name:
                        findings.append(ParsedFinding(
                            entity_type=EntityType.SERVICE,
                            entity_name=f"{service_name}/{ip}",
                            properties={"name": service_name, "product": service_product, "version": service_version},
                            relation_type=RelationType.DETECTED_SERVICE,
                            relation_target=port_key,
                            tags=["nmap", service_name],
                            summary=f"Service: {service_name} on {port_key}",
                        ))
        except Exception as e:
            logger.debug(f"Failed to parse nmap XML: {e}")
        self._findings.extend(findings)
        return findings

    def parse_nuclei_jsonl(self, jsonl_content: str) -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                template_id = entry.get("template-id", "")
                name = entry.get("name", "") or entry.get("info", {}).get("name", "")
                severity = entry.get("info", {}).get("severity", "info")
                host = entry.get("host", "")
                matched_at = entry.get("matched-at", "")
                type_tag = entry.get("type", "")

                findings.append(ParsedFinding(
                    entity_type=EntityType.VULNERABILITY,
                    entity_name=f"nuclei:{template_id}:{matched_at or host}",
                    properties={
                        "template": template_id, "name": name,
                        "severity": severity, "type": type_tag,
                        "matched_at": matched_at,
                    },
                    relation_type=RelationType.HAS_VULNERABILITY,
                    relation_target=host,
                    tags=["nuclei", severity, template_id],
                    confidence={"critical": 0.9, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}.get(severity, 0.5),
                    severity=severity,
                    summary=f"Nuclei: {name} on {matched_at or host}",
                ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_httpx_jsonl(self, jsonl_content: str) -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                status_code = entry.get("status_code", 0)
                title = entry.get("title", "")
                content_type = entry.get("content_type", "")
                content_length = entry.get("content_length", 0)
                tech = entry.get("tech", []) or []
                server = entry.get("webserver", "")
                cname = entry.get("cname", "")
                response_time = entry.get("response_time", "")
                cdn_name = entry.get("cdn_name", "")

                findings.append(ParsedFinding(
                    entity_type=EntityType.URL,
                    entity_name=url,
                    properties={
                        "status": status_code, "title": title,
                        "content_type": content_type, "content_length": content_length,
                        "server": server, "response_time": response_time,
                        "cdn": cdn_name,
                    },
                    tags=["httpx", f"status_{status_code}"],
                    confidence=1.0,
                    summary=f"HTTPX: {url} [{status_code}] {title}",
                ))
                for t in tech:
                    findings.append(ParsedFinding(
                        entity_type=EntityType.TECHNOLOGY,
                        entity_name=t,
                        relation_type=RelationType.RUNS_ON,
                        relation_target=url,
                        tags=["httpx", "tech", t.lower()],
                        summary=f"Technology: {t} on {url}",
                    ))
                if server:
                    findings.append(ParsedFinding(
                        entity_type=EntityType.TECHNOLOGY,
                        entity_name=f"Server:{server}",
                        properties={"type": "server", "name": server},
                        relation_type=RelationType.RUNS_ON,
                        relation_target=url,
                        tags=["httpx", "server"],
                        summary=f"Server: {server}",
                    ))
                if cname:
                    findings.append(ParsedFinding(
                        entity_type=EntityType.DOMAIN,
                        entity_name=cname,
                        relation_type=RelationType.REDIRECTS_TO,
                        relation_target=url,
                        tags=["httpx", "cname"],
                    ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_ffuf_jsonl(self, jsonl_content: str, base_url: str = "") -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                status = entry.get("status", 0)
                length = entry.get("length", 0)
                words = entry.get("words", 0)
                lines = entry.get("lines", 0)
                content_type = entry.get("content_type", "")
                redirect_location = entry.get("redirectlocation", "")

                findings.append(ParsedFinding(
                    entity_type=EntityType.URL,
                    entity_name=url,
                    properties={
                        "status": status, "length": length,
                        "words": words, "lines": lines,
                        "content_type": content_type,
                        "redirect_location": redirect_location,
                        "source": "ffuf",
                    },
                    tags=["ffuf", f"status_{status}", "discovered"],
                    confidence=0.7 if status in (200, 301, 302, 401, 403) else 0.4,
                    severity="medium" if status in (200, 401, 403) else "info",
                    summary=f"FFUF: {url} [{status}] ({length} bytes)",
                ))
                if redirect_location:
                    findings.append(ParsedFinding(
                        entity_type=EntityType.URL,
                        entity_name=redirect_location,
                        relation_type=RelationType.REDIRECTS_TO,
                        relation_target=url,
                        tags=["ffuf", "redirect"],
                    ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_sqlmap_jsonl(self, jsonl_content: str) -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                target_url = entry.get("target", {}).get("url", "")
                vuln_type = entry.get("vulnerability", {}).get("type", "")
                parameter = entry.get("vulnerability", {}).get("parameter", "")
                payload = entry.get("vulnerability", {}).get("payload", "")
                dbms = entry.get("vulnerability", {}).get("dbms", "")
                title = f"SQLi:{parameter}:{dbms}"

                findings.append(ParsedFinding(
                    entity_type=EntityType.VULNERABILITY,
                    entity_name=title,
                    properties={
                        "type": vuln_type, "parameter": parameter,
                        "dbms": dbms, "payload": payload[:200],
                        "target": target_url,
                        "source": "sqlmap",
                    },
                    relation_type=RelationType.HAS_VULNERABILITY,
                    relation_target=target_url,
                    tags=["sqli", "sqlmap", dbms],
                    confidence=0.95,
                    severity="critical",
                    summary=f"SQLi: {parameter} on {target_url} ({dbms})",
                ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_naabu_jsonl(self, jsonl_content: str) -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                port = entry.get("port", 0)
                protocol = entry.get("protocol", "tcp")
                ip = entry.get("ip", host)

                port_key = f"{ip}:{port}/{protocol}"
                findings.append(ParsedFinding(
                    entity_type=EntityType.PORT,
                    entity_name=port_key,
                    properties={"port": port, "protocol": protocol, "ip": ip},
                    relation_type=RelationType.SCANNED_PORT,
                    relation_target=ip,
                    tags=["naabu", f"port_{port}"],
                    confidence=0.95,
                    summary=f"Naabu: Port {port}/{protocol} open on {ip}",
                ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_subfinder_jsonl(self, jsonl_content: str, parent_domain: str = "") -> List[ParsedFinding]:
        findings = []
        for line in jsonl_content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", line)
                ip = entry.get("ip", "")
                source = entry.get("source", "subfinder")

                findings.append(ParsedFinding(
                    entity_type=EntityType.DOMAIN,
                    entity_name=host,
                    properties={"source": source, "parent": parent_domain},
                    relation_type=RelationType.SUBDOMAIN_OF,
                    relation_target=parent_domain or host.split(".", 1)[-1],
                    tags=["subfinder", "subdomain", source],
                    confidence=0.8,
                    summary=f"Subdomain: {host}",
                ))
                if ip:
                    findings.append(ParsedFinding(
                        entity_type=EntityType.IP_ADDRESS,
                        entity_name=ip,
                        relation_type=RelationType.RESOLVES_TO,
                        relation_target=host,
                        tags=["subfinder"],
                    ))
            except Exception:
                continue
        self._findings.extend(findings)
        return findings

    def parse_generic_text(self, text: str, source: str = "") -> List[ParsedFinding]:
        findings = []
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        url_pattern = re.compile(r'https?://[^\s<>"\'\[\]]+')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

        seen_ips = set()
        for match in ip_pattern.finditer(text):
            ip = match.group()
            if ip not in seen_ips:
                seen_ips.add(ip)
                findings.append(ParsedFinding(
                    entity_type=EntityType.IP_ADDRESS,
                    entity_name=ip,
                    tags=[source, "extracted"],
                    confidence=0.5,
                ))

        seen_urls = set()
        for match in url_pattern.finditer(text):
            url = match.group()
            if url not in seen_urls:
                seen_urls.add(url)
                findings.append(ParsedFinding(
                    entity_type=EntityType.URL,
                    entity_name=url,
                    tags=[source, "extracted"],
                    confidence=0.5,
                ))

        seen_emails = set()
        for match in email_pattern.finditer(text):
            email = match.group()
            if email not in seen_emails:
                seen_emails.add(email)
                findings.append(ParsedFinding(
                    entity_type=EntityType.EMAIL,
                    entity_name=email,
                    tags=[source, "extracted"],
                    confidence=0.6,
                ))

        # Domains that aren't already caught as URLs
        seen_domains = set()
        for match in domain_pattern.finditer(text):
            domain = match.group().lower()
            if domain not in seen_domains and "." in domain and not any(domain in u for u in seen_urls):
                seen_domains.add(domain)
                findings.append(ParsedFinding(
                    entity_type=EntityType.DOMAIN,
                    entity_name=domain,
                    tags=[source, "extracted"],
                    confidence=0.4,
                ))

        self._findings.extend(findings)
        return findings

    def ingest_all(self, graph: Optional[GraphMemory] = None) -> int:
        g = graph or self._graph
        count = 0
        for f in self._findings:
            try:
                entity = g.add_entity(
                    etype=f.entity_type, name=f.entity_name,
                    properties=f.properties, confidence=f.confidence,
                    source="tool_parser", tags=f.tags,
                )
                count += 1
                if f.relation_type and f.relation_target:
                    target_key = f"{f.entity_type.value}:{f.entity_name.lower().strip()}"
                    # Try to find appropriate target entity type
                    g.add_relation(
                        source_id=entity.id,
                        target_id=f._resolve_target_id(),
                        rtype=f.relation_type,
                        properties={"summary": f.summary},
                        confidence=f.confidence,
                        source="tool_parser",
                    )
            except Exception:
                pass
        return count

    def get_findings(self) -> List[ParsedFinding]:
        return self._findings

    def clear(self):
        self._findings.clear()
