"""
Corpus Populator — Load HackerOne reports from multiple sources into RAG index.

Sources (tried in order):
  1. HuggingFace datasets (earthywh/hackerone_disclosed_reports — 10,094 reports)
  2. JSON files from GitHub repos (Krishnathakur063, zzzteph/bugbounty-monitor)
  3. Writeup files from ~/.itzraven/writeups/*.json

Output: FAISS index + SQLite metadata store + TF-IDF embedding models.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

import numpy as np

from itzraven.core.config import ITZRAVEN_CACHE_DIR
from itzraven.core.logger import get_logger
from itzraven.core.embeddings import EmbeddingEngine, get_embedding_engine, EMBEDDING_DIM

logger = get_logger()

_FAISS_AVAILABLE = False
try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    faiss = None


@dataclass
class ReportRecord:
    source: str
    report_id: str
    title: str
    description: str
    technique: str = ""
    severity: str = "medium"
    program_name: str = ""
    weakness_type: str = ""
    weakness_id: int = 0
    reporter: str = ""
    bounty: int = 0
    url: str = ""
    tags: List[str] = field(default_factory=list)
    disclosed_at: str = ""
    vote_count: int = 0


# ---------------------------------------------------------------------------
# Weakness → Severity mapping (H1 weakness categories → standard severity)
# ---------------------------------------------------------------------------
CRITICAL_WEAKNESSES = {
    "remote code execution", "command injection", "sql injection",
    "insecure deserialization", "memory corruption", "buffer overflow",
    "code injection", "authentication bypass", "privilege escalation",
    "path traversal", "local file inclusion", "server-side request forgery",
}

HIGH_WEAKNESSES = {
    "cross-site scripting", "cross site scripting", "xss",
    "open redirect", "subdomain takeover", "account takeover",
    "cross-site request forgery", "csrf", "idor",
    "insecure direct object reference", "oauth misconfiguration",
    "jwt", "jwt signature bypass", "cors misconfiguration",
}

MEDIUM_WEAKNESSES = {
    "information disclosure", "improper access control",
    "improper authentication", "business logic errors",
    "unvalidated redirect", "content spoofing",
    "clickjacking", "missing security headers",
}


def _infer_severity(weakness_name: str) -> str:
    if not weakness_name:
        return "medium"
    w = weakness_name.lower()
    for kw in CRITICAL_WEAKNESSES:
        if kw in w:
            return "critical"
    for kw in HIGH_WEAKNESSES:
        if kw in w:
            return "high"
    for kw in MEDIUM_WEAKNESSES:
        if kw in w:
            return "medium"
    return "medium"


def _infer_technique(weakness_name: str, title: str, description: str) -> str:
    text = f"{weakness_name} {title} {description}".lower()
    tech_map = {
        "sqli": ["sql injection", "blind sqli", "sql"],
        "xss": ["cross-site scripting", "xss", "script injection"],
        "ssrf": ["server-side request forgery", "ssrf", "server side request"],
        "idor": ["insecure direct object", "idor", "object reference"],
        "rce": ["remote code execution", "command injection", "rce", "code injection"],
        "ssti": ["template injection", "ssti", "server-side template"],
        "lfi": ["local file inclusion", "lfi", "path traversal", "directory traversal"],
        "csrf": ["cross-site request forgery", "csrf", "xsrf"],
        "open redirect": ["open redirect", "url redirect", "redirect"],
        "deserialization": ["deserialization", "serialize", "ysoserial"],
        "oauth": ["oauth", "authorization code", "token theft"],
        "jwt": ["jwt", "json web token", "alg none"],
        "file upload": ["file upload", "webshell", "unrestricted upload"],
        "race": ["race condition", "toctou", "time of check"],
        "graphql": ["graphql", "introspection", "graphql injection"],
        "xxe": ["xxe", "xml external entity", "xml injection"],
        "nosql": ["nosql", "mongodb injection", "$where"],
        "smtp": ["email injection", "smtp injection", "mail header"],
        "cors": ["cors", "cross-origin resource sharing"],
        "clickjacking": ["clickjack", "clickjack", "ui redress"],
    }
    for technique, keywords in tech_map.items():
        for kw in keywords:
            if kw in text:
                return technique
    if weakness_name:
        return weakness_name.split(" - ")[0].strip() if " - " in weakness_name else weakness_name
    return "unknown"


def _make_tags(weakness_name: str, severity: str, program_name: str) -> List[str]:
    tags = []
    if weakness_name:
        w = weakness_name.lower()
        if " - " in w:
            tags.append(w.split(" - ")[0].strip().replace(" ", "-"))
        else:
            tags.append(w.replace(" ", "-").replace("/", "-"))
    if severity:
        tags.append(severity)
    if program_name:
        tags.append(program_name.lower().replace(" ", "-"))
    return tags


class CorpusPopulator:
    """Populate RAG index from multiple data sources."""

    def __init__(self):
        self.embedder = get_embedding_engine()
        self.index_dir = ITZRAVEN_CACHE_DIR / "rag"
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.records: List[ReportRecord] = []
        self.existing_ids: set = set()

    def from_huggingface(self, max_reports: int = 0) -> int:
        """Load from HuggingFace dataset — earthywh/hackerone_disclosed_reports."""
        try:
            from datasets import load_dataset
        except ImportError:
            logger.warning("datasets not installed. Run: pip install datasets")
            return 0

        logger.info("Loading from HuggingFace: earthywh/hackerone_disclosed_reports...")
        ds = load_dataset("earthywh/hackerone_disclosed_reports", split="train", streaming=True)

        count = 0
        for row in ds:
            rid = str(row.get("id", ""))
            if rid in self.existing_ids:
                continue

            team_info = row.get("team", {}) or {}
            if isinstance(team_info, dict):
                program_name = (team_info.get("profile", {}) or {}).get("name", "") or team_info.get("handle", "")
            else:
                program_name = str(team_info)

            weakness = row.get("weakness", {}) or {}
            weakness_name = weakness.get("name", "") if isinstance(weakness, dict) else ""
            weakness_id = weakness.get("id", 0) if isinstance(weakness, dict) else 0

            description = row.get("vulnerability_information", "") or ""
            title = row.get("title", "") or ""
            severity = _infer_severity(weakness_name)
            technique = _infer_technique(weakness_name, title, description)
            tags = _make_tags(weakness_name, severity, program_name)

            reporter_info = row.get("reporter", {}) or {}
            reporter = reporter_info.get("username", "") if isinstance(reporter_info, dict) else ""

            record = ReportRecord(
                source="hackerone",
                report_id=rid,
                title=title,
                description=description[:5000],
                technique=technique,
                severity=severity,
                program_name=program_name,
                weakness_type=weakness_name,
                weakness_id=weakness_id,
                reporter=reporter,
                url=f"https://hackerone.com/reports/{rid}",
                tags=tags,
                disclosed_at=str(row.get("disclosed_at", "") or ""),
                vote_count=row.get("vote_count", 0) or 0,
            )
            self.records.append(record)
            self.existing_ids.add(rid)
            count += 1
            if max_reports and count >= max_reports:
                break

        logger.info(f"Loaded {count} reports from HuggingFace")
        return count

    def from_json_dir(self, path: str, max_reports: int = 0, recursive: bool = True) -> int:
        """Load from directory of JSON files.

        Handles both flat structures (Krishnathakur063) and
        hierarchical structures (zzzteph/bugbounty-monitor).

        Args:
            path: Directory path
            max_reports: Max to load (0 = all)
            recursive: Search subdirectories recursively

        Returns:
            Number of reports loaded
        """
        json_dir = Path(path)
        if not json_dir.is_dir():
            logger.warning(f"Directory not found: {path}")
            return 0

        pattern = "**/*.json" if recursive else "*.json"
        files = sorted(json_dir.glob(pattern))
        logger.info(f"Found {len(files)} JSON files in {path}")

        count = 0
        for fpath in files:
            try:
                data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            rid = str(data.get("id", data.get("report_id", fpath.stem)))
            if rid in self.existing_ids:
                continue

            title = data.get("title", "") or ""
            description = data.get("vulnerability_information", data.get("description", "")) or ""

            team_info = data.get("team", {}) or {}
            program_name = ""
            if isinstance(team_info, dict):
                program_name = (team_info.get("profile", {}) or {}).get("name", "") or team_info.get("handle", "")
            else:
                program_name = str(team_info)

            weakness = data.get("weakness", {}) or {}
            weakness_name = ""
            if isinstance(weakness, dict):
                weakness_name = weakness.get("name", "")
            elif isinstance(weakness, str):
                weakness_name = weakness

            # Prefer actual severity_rating over inferred (zzzteph/Krishnathakur063 have this)
            severity_rating = data.get("severity_rating", "") or ""
            if severity_rating and severity_rating.lower() in ("critical", "high", "medium", "low", "none"):
                severity = severity_rating.lower()
                if severity == "none":
                    severity = "info"
            else:
                severity = _infer_severity(weakness_name)

            technique = _infer_technique(weakness_name, title, description)
            tags = _make_tags(weakness_name, severity, program_name)

            # Extract real bounty if available
            bounty = 0
            bounty_amount = data.get("bounty_amount", "")
            if bounty_amount:
                try:
                    bounty = int(float(bounty_amount))
                except (ValueError, TypeError):
                    pass

            record = ReportRecord(
                source="hackerone",
                report_id=rid,
                title=title,
                description=str(description)[:5000],
                technique=technique,
                severity=severity,
                program_name=program_name,
                weakness_type=weakness_name,
                reporter=str(data.get("reporter", {}).get("username", "")) if isinstance(data.get("reporter"), dict) else "",
                bounty=bounty,
                url=f"https://hackerone.com/reports/{rid}",
                tags=tags,
                disclosed_at=str(data.get("disclosed_at", "") or ""),
                vote_count=int(data.get("vote_count", 0) or 0),
            )
            self.records.append(record)
            self.existing_ids.add(rid)
            count += 1
            if max_reports and count >= max_reports:
                break

        logger.info(f"Loaded {count} reports from {path}")
        return count

    def from_writeup_dir(self, path: Optional[str] = None) -> int:
        """Load custom writeups from ~/.itzraven/writeups/*.json."""
        writeup_dir = Path(path) if path else (ITZRAVEN_CACHE_DIR.parent / "writeups")
        if not writeup_dir.is_dir():
            return 0

        count = 0
        for fpath in sorted(writeup_dir.glob("*.json")):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

            rid = data.get("id", data.get("report_id", f"writeup-{fpath.stem}"))
            if rid in self.existing_ids:
                continue

            record = ReportRecord(
                source=data.get("source", "writeup"),
                report_id=rid,
                title=data.get("title", fpath.stem),
                description=str(data.get("description", data.get("body", "")))[:5000],
                technique=data.get("technique", "unknown"),
                severity=data.get("severity", "medium"),
                program_name=data.get("program", ""),
                weakness_type=data.get("weakness", ""),
                reporter=data.get("reporter", ""),
                bounty=int(data.get("bounty", 0)),
                url=data.get("url", ""),
                tags=data.get("tags", []),
            )
            self.records.append(record)
            self.existing_ids.add(rid)
            count += 1

        if count:
            logger.info(f"Loaded {count} writeups from {writeup_dir}")
        return count

    def build_index(self) -> Tuple[int, float]:
        """Build/rebuild FAISS index from loaded records.

        Returns:
            (num_records, build_time_seconds)
        """
        if not self.records:
            logger.warning("No records to index")
            return 0, 0.0

        if not _FAISS_AVAILABLE:
            logger.error("FAISS not installed. Cannot build index.")
            return 0, 0.0

        t0 = time.time()

        texts = [
            f"{r.title} {r.description} {r.technique} {r.weakness_type}"
            for r in self.records
        ]

        embeddings = self.embedder.train(texts)
        n_records = len(self.records)

        dim = embeddings.shape[1]
        index = faiss.IndexHNSWFlat(dim, 32)
        index.hnsw.efConstruction = 200
        index.add(embeddings)
        faiss.write_index(index, str(self.index_dir / "prior_art.index"))

        meta = []
        import sqlite3
        db_path = self.index_dir / "prior_art.db"
        db = sqlite3.connect(str(db_path))
        db.execute("""
            CREATE TABLE IF NOT EXISTS prior_art (
                id TEXT PRIMARY KEY,
                source TEXT, title TEXT, description TEXT,
                technique TEXT, severity TEXT, program_name TEXT,
                weakness_type TEXT, weakness_id INTEGER,
                reporter TEXT, bounty INTEGER,
                url TEXT, tags TEXT, disclosed_at TEXT, vote_count INTEGER
            )
        """)
        for r in self.records:
            db.execute(
                "INSERT OR REPLACE INTO prior_art VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r.report_id, r.source, r.title, r.description,
                 r.technique, r.severity, r.program_name,
                 r.weakness_type, r.weakness_id,
                 r.reporter, r.bounty,
                 r.url, json.dumps(r.tags), r.disclosed_at, r.vote_count),
            )
            meta.append({
                "source": r.source,
                "id": r.report_id,
                "title": r.title,
                "description": r.description,
                "technique": r.technique,
                "severity": r.severity,
                "program_name": r.program_name,
                "weakness_type": r.weakness_type,
                "reporter": r.reporter,
                "url": r.url,
                "tags": r.tags,
                "disclosed_at": r.disclosed_at,
                "vote_count": r.vote_count,
            })
        db.commit()
        db.close()

        with open(self.index_dir / "prior_art_meta.json", "w") as f:
            json.dump(meta, f)

        elapsed = time.time() - t0
        logger.success(f"Index built: {n_records} records, {dim}d, {elapsed:.1f}s")
        return n_records, elapsed

    def clone_github_source(self, repo_url: str, target_dir: Optional[str] = None) -> str:
        """Clone or update a GitHub repo with H1 report data.

        Uses shallow clone for speed. If already cloned, git pull.

        Args:
            repo_url: GitHub repo URL
            target_dir: Local target directory (default: ~/.itzraven/cache/repos/<repo-name>)

        Returns:
            Path to the cloned repo root
        """
        import subprocess

        if target_dir is None:
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            target_dir = str(ITZRAVEN_CACHE_DIR / "repos" / repo_name)

        target = Path(target_dir)
        if target.is_dir() and (target / ".git").is_dir():
            logger.info(f"Updating existing clone: {repo_url}")
            try:
                subprocess.run(
                    ["git", "-C", target_dir, "pull", "--depth=1"],
                    capture_output=True, text=True, timeout=120,
                )
                logger.info(f"Updated {target_dir}")
            except Exception as e:
                logger.warning(f"Git pull failed ({e}), using existing clone")
        else:
            logger.info(f"Cloning {repo_url} -> {target_dir}")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["git", "clone", "--depth=1", repo_url, target_dir],
                    capture_output=True, text=True, timeout=300,
                )
                logger.info(f"Cloned to {target_dir}")
            except Exception as e:
                logger.error(f"Git clone failed: {e}")
                raise

        return target_dir

    def from_zzzteph_repo(self, max_reports: int = 0) -> int:
        """Load reports from zzzteph/bugbounty-monitor repo.

        Auto-clones if not present. Repo has hierarchical structure:
            reports/<category>/<weakness>/<year>/<id>.json

        Key advantages over HF dataset:
            - Has real severity_rating field (not inferred)
            - Has bounty_amount field
            - Hourly updated with fresh disclosures
            - Pre-categorized by weakness/category
        """
        repo_dir = self.clone_github_source(
            "https://github.com/zzzteph/bugbounty-monitor.git"
        )
        reports_dir = Path(repo_dir) / "reports"
        if not reports_dir.is_dir():
            logger.warning(f"reports/ directory not found in {repo_dir}")
            return 0

        return self.from_json_dir(str(reports_dir), max_reports=max_reports, recursive=True)

    @staticmethod
    def refresh(repos: Optional[List[str]] = None) -> int:
        """Refresh corpus from all available sources (incremental).

        Clones/updates GitHub repos, merges new reports, rebuilds index.

        Args:
            repos: List of repo URLs to sync (default: [zzzteph])

        Returns:
            Total records after refresh
        """
        if repos is None:
            repos = ["https://github.com/zzzteph/bugbounty-monitor.git"]

        populator = CorpusPopulator()
        total = 0

        # Load existing index to avoid duplicates
        existing_meta = ITZRAVEN_CACHE_DIR / "rag" / "prior_art_meta.json"
        if existing_meta.exists():
            try:
                with open(existing_meta) as f:
                    existing = json.load(f)
                for m in existing:
                    populator.existing_ids.add(m.get("id", ""))
                logger.info(f"Existing index: {len(existing)} records")
            except Exception:
                pass

        # Clone/update each repo and load reports
        for repo_url in repos:
            try:
                repo_dir = populator.clone_github_source(repo_url)
                reports_path = Path(repo_dir) / "reports"
                if reports_path.is_dir():
                    n = populator.from_json_dir(str(reports_path), recursive=True)
                    total += n
                else:
                    n = populator.from_json_dir(str(repo_dir), recursive=True)
                    total += n
            except Exception as e:
                logger.warning(f"Failed to load from {repo_url}: {e}")

        if total == 0:
            logger.info("No new reports found")
            return len(populator.existing_ids)

        # Merge with existing index
        if existing_meta.exists():
            try:
                with open(existing_meta) as f:
                    existing = json.load(f)
                existing_ids = {m.get("id", "") for m in existing}
                merged = []
                for m in existing:
                    merged.append(ReportRecord(
                        source=m.get("source", "hackerone"),
                        report_id=m.get("id", ""),
                        title=m.get("title", ""),
                        description=m.get("description", ""),
                        technique=m.get("technique", ""),
                        severity=m.get("severity", "medium"),
                        program_name=m.get("program_name", ""),
                        weakness_type=m.get("weakness_type", ""),
                        reporter=m.get("reporter", ""),
                        bounty=int(m.get("bounty", 0) or 0),
                        url=m.get("url", ""),
                        tags=m.get("tags", []),
                        disclosed_at=m.get("disclosed_at", ""),
                        vote_count=int(m.get("vote_count", 0) or 0),
                    ))
                for r in populator.records:
                    if r.report_id not in existing_ids:
                        merged.append(r)
                populator.records = merged
                logger.info(f"Merged: {len(merged)} total records ({total} new)")
            except Exception as e:
                logger.warning(f"Merge failed ({e}), rebuilding from scratch")

        indexed, elapsed = populator.build_index()
        return indexed

    def statistics(self) -> Dict[str, Any]:
        """Get corpus statistics."""
        stats = {
            "total_records": len(self.records),
            "sources": {},
            "severity": {},
            "techniques": {},
            "programs": {},
        }
        for r in self.records:
            stats["sources"][r.source] = stats["sources"].get(r.source, 0) + 1
            stats["severity"][r.severity] = stats["severity"].get(r.severity, 0) + 1
            tech = r.technique or "unknown"
            stats["techniques"][tech] = stats["techniques"].get(tech, 0) + 1
            if r.program_name:
                stats["programs"][r.program_name] = stats["programs"].get(r.program_name, 0) + 1
        return stats


def populate_from_all_sources(max_reports: int = 0, force: bool = False) -> int:
    """Convenience: populate RAG index from all available sources.

    Args:
        max_reports: Max reports to load (0 = all)
        force: Rebuild even if index exists

    Returns:
        Number of records indexed
    """
    index_dir = ITZRAVEN_CACHE_DIR / "rag"
    if not force and (index_dir / "prior_art.index").exists():
        meta_path = index_dir / "prior_art_meta.json"
        if meta_path.exists():
            with open(meta_path) as f:
                meta = json.load(f)
            logger.info(f"Index already exists: {len(meta)} records")
            return len(meta)

    populator = CorpusPopulator()
    total = 0

    n = populator.from_huggingface(max_reports)
    total += n

    if total == 0:
        for repo_dir in [
            "/root/.itzraven/json_reports",
            "/tmp/h1_reports/jsonReports",
        ]:
            n = populator.from_json_dir(repo_dir, max_reports - total if max_reports else 0)
            total += n
            if max_reports and total >= max_reports:
                break

    if total == 0:
        try:
            n = populator.from_zzzteph_repo(max_reports)
            total += n
        except Exception as e:
            logger.warning(f"zzzteph repo unavailable: {e}")

    n = populator.from_writeup_dir()
    total += n

    if total == 0:
        logger.warning("No data sources available. Use built-in 18-entry corpus.")
        return 0

    if max_reports:
        populator.records = populator.records[:max_reports]

    indexed, elapsed = populator.build_index()

    stats = populator.statistics()
    logger.info(f"Corpus: {stats['total_records']} records, {len(stats['techniques'])} techniques, {len(stats['programs'])} programs")

    return indexed


def refresh_corpus() -> int:
    """Refresh RAG index from GitHub repos (incremental update).

    Clones/updates zzzteph/bugbounty-monitor, merges new reports
    with existing index, rebuilds FAISS. Designed for cron use.

    Returns:
        Total records after refresh
    """
    return CorpusPopulator.refresh()


def get_corpus_stats() -> Dict[str, Any]:
    """Get current corpus statistics without rebuilding."""
    index_dir = ITZRAVEN_CACHE_DIR / "rag"
    meta_path = index_dir / "prior_art_meta.json"
    if not meta_path.exists():
        return {"total": 0, "status": "not_built"}

    with open(meta_path) as f:
        meta = json.load(f)

    stats = {"total": len(meta), "status": "built", "sources": {}, "severity": {}, "techniques": {}}
    for m in meta:
        stats["sources"][m.get("source", "unknown")] = stats["sources"].get(m.get("source", "unknown"), 0) + 1
        stats["severity"][m.get("severity", "unknown")] = stats["severity"].get(m.get("severity", "unknown"), 0) + 1
        tech = m.get("technique", "unknown")
        stats["techniques"][tech] = stats["techniques"].get(tech, 0) + 1

    return stats
