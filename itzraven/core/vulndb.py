"""
Vulnerability Database Lookup — CVE/NVD/Exploit-DB context enrichment for findings.

Supports:
- Local SQLite cache of CVEs
- NVD API 2.0 lookup
- Basic keyword-to-CVE matching
"""

import json
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import quote

import httpx

from itzraven.core.logger import get_logger

logger = get_logger()

DB_PATH = Path.home() / ".itzraven" / "vulndb" / "cache.sqlite"


@dataclass
class CVE:
    id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_software: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    source: str = "nvd"

    def to_dict(self) -> dict:
        return asdict(self)


class VulnDB:
    """Local vulnerability database with NVD API 2.0 integration."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EXPLOIT_DB_API = "https://www.exploit-db.com/search"

    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(DB_PATH))
        self._init_db()
        self._http = httpx.Client(timeout=15.0)
        self._cache_ttl = 86400  # 24 hours

    def _init_db(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                fetched_at REAL NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS keywords (
                keyword TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                score REAL DEFAULT 1.0
            )
        """)
        self._conn.commit()

    def lookup(self, cve_id: str) -> Optional[CVE]:
        """Look up a specific CVE by ID."""
        row = self._conn.execute(
            "SELECT data FROM cves WHERE id = ?", (cve_id.upper(),)
        ).fetchone()
        if row:
            return CVE(**json.loads(row[0]))
        return self._fetch_from_nvd(cve_id.upper())

    def search(self, query: str, limit: int = 10) -> List[CVE]:
        """Search CVEs by keyword."""
        results = []
        rows = self._conn.execute(
            """SELECT DISTINCT c.data FROM cves c
               JOIN keywords k ON c.id = k.cve_id
               WHERE k.keyword LIKE ? ORDER BY k.score DESC LIMIT ?""",
            (f"%{query.lower()}%", limit),
        ).fetchall()
        for row in rows:
            results.append(CVE(**json.loads(row[0])))
        if not results:
            results = self._fetch_search_nvd(query, limit)
        return results

    def enrich_finding(self, title: str, description: str) -> List[CVE]:
        """Find CVEs relevant to a finding based on title and description."""
        text = f"{title} {description}".lower()
        keywords = [w for w in text.split() if len(w) > 3]
        seen = set()
        cves = []
        for kw in keywords[:20]:
            rows = self._conn.execute(
                """SELECT c.data FROM cves c
                   JOIN keywords k ON c.id = k.cve_id
                   WHERE k.keyword = ? ORDER BY k.score DESC LIMIT 3""",
                (kw,),
            ).fetchall()
            for row in rows:
                cve_data = json.loads(row[0])
                cve_id = cve_data["id"]
                if cve_id not in seen:
                    seen.add(cve_id)
                    cves.append(CVE(**cve_data))
        return cves[:10]

    def _fetch_from_nvd(self, cve_id: str) -> Optional[CVE]:
        try:
            resp = self._http.get(
                f"{self.NVD_API_BASE}?cveId={cve_id}",
                headers={"User-Agent": "ItzravenSecurity/2.0"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            if not vuln:
                return None

            metrics = vuln.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            cvss_data = cvss_v31 or cvss_v30

            descriptions = vuln.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            cve = CVE(
                id=cve_id.upper(),
                description=desc_text,
                severity=(cvss_data.get("baseSeverity") or "UNKNOWN").upper(),
                cvss_score=cvss_data.get("baseScore"),
                cvss_vector=cvss_data.get("vectorString"),
                published_date=vuln.get("published"),
                last_modified=vuln.get("lastModified"),
                references=[r.get("url", "") for r in vuln.get("references", [])],
                source="nvd",
            )

            self._cache_cve(cve)
            return cve
        except Exception as e:
            logger.debug(f"NVD lookup failed for {cve_id}: {e}")
            return None

    def _fetch_search_nvd(self, query: str, limit: int) -> List[CVE]:
        try:
            resp = self._http.get(
                f"{self.NVD_API_BASE}?keywordSearch={quote(query)}&resultsPerPage={limit}",
                headers={"User-Agent": "ItzravenSecurity/2.0"},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            cves = []
            for vuln_item in data.get("vulnerabilities", [])[:limit]:
                vuln = vuln_item.get("cve", {})
                cve_id = vuln.get("id", "")
                descriptions = vuln.get("descriptions", [])
                desc_text = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value", "")
                        break
                metrics = vuln.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                )
                cve = CVE(
                    id=cve_id,
                    description=desc_text,
                    severity=(cvss_data.get("baseSeverity") or "UNKNOWN").upper(),
                    cvss_score=cvss_data.get("baseScore"),
                    source="nvd",
                )
                self._cache_cve(cve)
                cves.append(cve)
            return cves
        except Exception as e:
            logger.debug(f"NVD search failed: {e}")
            return []

    def _cache_cve(self, cve: CVE):
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO cves (id, data, fetched_at) VALUES (?, ?, ?)",
                (cve.id, json.dumps(cve.to_dict()), time.time()),
            )
            desc = (cve.description + " " + cve.id).lower()
            for word in set(desc.split()):
                if len(word) > 3:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO keywords (keyword, cve_id, score) VALUES (?, ?, ?)",
                        (word, cve.id, 1.0),
                    )
            self._conn.commit()
        except Exception as e:
            logger.debug(f"Failed to cache CVE {cve.id}: {e}")

    def close(self):
        self._conn.close()
        self._http.close()


_vulndb: Optional[VulnDB] = None


def get_vulndb() -> VulnDB:
    global _vulndb
    if _vulndb is None:
        _vulndb = VulnDB()
    return _vulndb


CVELookup = VulnDB
