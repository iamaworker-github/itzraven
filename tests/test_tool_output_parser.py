"""Tests for Tool Output Parser."""

import json
import pytest
from itzraven.core.tool_output_parser import ToolOutputParser, ParsedFinding
from itzraven.core.graph_memory import EntityType, RelationType, get_graph_memory


@pytest.fixture
def parser():
    graph = get_graph_memory(namespace="test_parser")
    p = ToolOutputParser(graph=graph)
    yield p
    graph.clear()


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml(parser):
    findings = parser.parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(findings) >= 5  # IP + domain + 2 ports + 2 services


def test_parse_nmap_ip(parser):
    findings = parser.parse_nmap_xml(SAMPLE_NMAP_XML)
    ips = [f for f in findings if f.entity_type == EntityType.IP_ADDRESS]
    assert len(ips) >= 1
    assert ips[0].entity_name == "93.184.216.34"


def test_parse_nmap_port(parser):
    findings = parser.parse_nmap_xml(SAMPLE_NMAP_XML)
    ports = [f for f in findings if f.entity_type == EntityType.PORT]
    assert len(ports) >= 2
    assert any(p.properties.get("port") == 80 for p in ports)


def test_parse_nuclei_jsonl(parser):
    sample = json.dumps({"template-id": "CVE-2024-0001", "name": "Test Vuln",
                         "host": "https://example.com", "matched-at": "https://example.com/admin",
                         "info": {"severity": "high"}, "type": "http"})
    findings = parser.parse_nuclei_jsonl(sample)
    assert len(findings) >= 1
    assert findings[0].entity_type == EntityType.VULNERABILITY
    assert findings[0].severity == "high"


def test_parse_httpx_jsonl(parser):
    sample = json.dumps({"url": "https://example.com", "status_code": 200,
                         "title": "Example", "tech": ["nginx", "PHP"],
                         "webserver": "nginx", "content_type": "text/html",
                         "content_length": 1256})
    findings = parser.parse_httpx_jsonl(sample)
    assert len(findings) >= 2  # URL + tech
    assert any(f.entity_type == EntityType.TECHNOLOGY for f in findings)


def test_parse_ffuf_jsonl(parser):
    sample = json.dumps({"url": "https://example.com/admin", "status": 200,
                         "length": 1024, "words": 150, "lines": 30})
    findings = parser.parse_ffuf_jsonl(sample)
    assert len(findings) >= 1
    assert findings[0].entity_type == EntityType.URL


def test_parse_generic_text(parser):
    text = "Server at 192.168.1.1 found. Contact admin@example.com. Visit https://example.com."
    findings = parser.parse_generic_text(text, source="test")
    ips = [f for f in findings if f.entity_type == EntityType.IP_ADDRESS]
    emails = [f for f in findings if f.entity_type == EntityType.EMAIL]
    urls = [f for f in findings if f.entity_type == EntityType.URL]
    assert len(ips) >= 1
    assert len(emails) >= 1
    assert len(urls) >= 1


def test_parse_sqlmap_jsonl(parser):
    sample = json.dumps({"target": {"url": "https://example.com/page?id=1"},
                         "vulnerability": {"type": "boolean-based blind",
                                           "parameter": "id", "dbms": "MySQL",
                                           "payload": "1' AND 1=1-- "}})
    findings = parser.parse_sqlmap_jsonl(sample)
    assert len(findings) >= 1
    assert findings[0].entity_type == EntityType.VULNERABILITY


def test_clear(parser):
    parser.parse_nmap_xml(SAMPLE_NMAP_XML)
    assert len(parser.get_findings()) > 0
    parser.clear()
    assert len(parser.get_findings()) == 0
