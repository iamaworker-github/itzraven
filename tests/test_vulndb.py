"""Tests for the Vulnerability Database Lookup."""

from itzraven.core.vulndb import VulnDB, CVE


def test_cve_creation():
    cve = CVE(
        id="CVE-2024-0001",
        description="Test vulnerability",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    )
    assert cve.id == "CVE-2024-0001"
    assert cve.severity == "HIGH"
    assert cve.cvss_score == 7.5
    d = cve.to_dict()
    assert d["id"] == "CVE-2024-0001"


def test_vulndb_init():
    db = VulnDB()
    assert db is not None


def test_vulndb_enrich_finding_empty():
    db = VulnDB()
    cves = db.enrich_finding("SQL Injection in login", "SQL injection vulnerability in login parameter")
    assert isinstance(cves, list)


def test_vulndb_search_empty():
    db = VulnDB()
    results = db.search("sql injection")
    assert isinstance(results, list)


def test_vulndb_singleton():
    from itzraven.core.vulndb import get_vulndb
    v1 = get_vulndb()
    v2 = get_vulndb()
    assert v1 is v2


def test_vulndb_close():
    db = VulnDB()
    db.close()
