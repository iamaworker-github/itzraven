"""
Memory Manager - Unified interface to Itzraven Memory System

Coordinates Neo4j (attack graph), Qdrant (semantic search), and Redis (state)
for persistent memory and intelligence capabilities.

Integrates with Event Bus (Phase 2) for real-time updates.
"""

import asyncio
import hashlib
import json
from typing import List, Optional, Dict, Any
from datetime import datetime

from neo4j import AsyncGraphDatabase, AsyncDriver
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, Range, MatchValue
import redis.asyncio as redis

from itzraven.core.memory_models import (
    Vulnerability,
    VulnerabilitySeverity,
    Target,
    Exploit,
    AttackPath,
    AttackComplexity,
    ScanState,
)
from itzraven.core.event_bus import EventBus, get_event_bus
from itzraven.core.events import (
    FindingDiscoveredEvent,
    FindingValidatedEvent,
    ScanStartedEvent,
    ScanCompletedEvent,
    AgentCompletedEvent,
)
from itzraven.core.logger import get_logger

logger = get_logger()


class MemoryManager:
    """
    Unified memory management system

    Coordinates storage and retrieval across:
    - Neo4j (attack graph and relationships)
    - Qdrant (semantic search via embeddings)
    - Redis (state management and caching)

    Integrates with Event Bus for automatic storage on events.

    Example:
        memory = MemoryManager()
        await memory.initialize()

        # Store vulnerability
        vuln = Vulnerability(...)
        await memory.store_vulnerability(vuln, "https://example.com")

        # Search similar
        similar = await memory.search_similar_vulnerabilities(vuln)

        # Find attack paths
        paths = await memory.find_attack_paths()
    """

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password",
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        redis_url: str = "redis://localhost:6379/0",
        event_bus: Optional[EventBus] = None,
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        """
        Initialize memory manager

        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            qdrant_host: Qdrant host
            qdrant_port: Qdrant port
            redis_url: Redis connection URL
            event_bus: Event bus instance (optional)
            embedding_model: Sentence transformer model name
        """
        # Connection parameters
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.qdrant_host = qdrant_host
        self.qdrant_port = qdrant_port
        self.redis_url = redis_url

        # Clients (initialized in initialize())
        self.neo4j_driver: Optional[AsyncDriver] = None
        self.qdrant_client: Optional[QdrantClient] = None
        self.redis_client: Optional[redis.Redis] = None

        # Embedding model
        self.embedding_model_name = embedding_model
        self.embedding_model = None  # type: ignore[assignment]

        # Event bus
        self.event_bus = event_bus or get_event_bus()

        # Statistics
        self.stats = {
            "findings_stored": 0,
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
        }

        # Async task tracking for graceful shutdown
        self._pending_tasks: set = set()
        self._task_lock = asyncio.Lock()

        # Initialization flag
        self._initialized = False

    async def initialize(self) -> None:
        """
        Initialize all memory systems

        - Connects to Neo4j, Qdrant, and Redis
        - Creates database schemas
        - Loads embedding model
        - Sets up event subscriptions
        """
        if self._initialized:
            logger.warning("Memory Manager already initialized")
            return

        try:
            # Initialize Neo4j
            self.neo4j_driver = AsyncGraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )
            await self._create_neo4j_schema()
            logger.info("✓ Neo4j connected and schema created")

            # Initialize Qdrant
            self.qdrant_client = QdrantClient(
                host=self.qdrant_host,
                port=self.qdrant_port
            )
            await self._create_qdrant_collections()
            logger.info("✓ Qdrant connected and collections created")

            # Initialize Redis
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("✓ Redis connected")

            # Load embedding model (lazy import)
            from sentence_transformers import SentenceTransformer
            self.embedding_model = SentenceTransformer(self.embedding_model_name)
            logger.info(f"✓ Embedding model loaded: {self.embedding_model_name}")

            # Setup event subscriptions
            await self._setup_event_subscriptions()
            logger.info("✓ Event subscriptions configured")

            self._initialized = True
            logger.info("Memory Manager initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Memory Manager: {e}")
            self.stats["errors"] += 1
            raise

    async def close(self) -> None:
        """Close all connections gracefully"""
        # Wait for all pending tasks to complete
        if self._pending_tasks:
            logger.info(f"Waiting for {len(self._pending_tasks)} pending tasks to complete...")
            await asyncio.gather(*self._pending_tasks, return_exceptions=True)
            logger.info("All pending tasks completed")

        # Close connections
        if self.neo4j_driver:
            await self.neo4j_driver.close()
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Memory Manager closed")

    # ========================================================================
    # NEO4J SCHEMA SETUP
    # ========================================================================

    async def _create_neo4j_schema(self) -> None:
        """Create Neo4j constraints and indexes"""
        async with self.neo4j_driver.session() as session:
            # Constraints (ensure uniqueness)
            constraints = [
                "CREATE CONSTRAINT target_id IF NOT EXISTS FOR (t:Target) REQUIRE t.id IS UNIQUE",
                "CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
                "CREATE CONSTRAINT exploit_id IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
                "CREATE CONSTRAINT agent_id IF NOT EXISTS FOR (a:Agent) REQUIRE a.id IS UNIQUE",
                "CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (s:Scan) REQUIRE s.id IS UNIQUE",
            ]

            for constraint in constraints:
                try:
                    await session.run(constraint)
                except Exception as e:
                    logger.debug(f"Constraint may already exist: {e}")

            # Indexes (improve query performance)
            indexes = [
                "CREATE INDEX target_url IF NOT EXISTS FOR (t:Target) ON (t.url)",
                "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                "CREATE INDEX vulnerability_category IF NOT EXISTS FOR (v:Vulnerability) ON (v.category)",
                "CREATE INDEX vulnerability_confidence IF NOT EXISTS FOR (v:Vulnerability) ON (v.confidence)",
            ]

            for index in indexes:
                try:
                    await session.run(index)
                except Exception as e:
                    logger.debug(f"Index may already exist: {e}")

    # ========================================================================
    # QDRANT COLLECTIONS SETUP
    # ========================================================================

    async def _create_qdrant_collections(self) -> None:
        """Create Qdrant collections for semantic search"""
        collections = [
            {
                "name": "findings",
                "vector_size": 384,  # all-MiniLM-L6-v2 dimension
                "distance": Distance.COSINE,
            },
            {
                "name": "payloads",
                "vector_size": 384,
                "distance": Distance.COSINE,
            },
            {
                "name": "attack_patterns",
                "vector_size": 384,
                "distance": Distance.COSINE,
            },
        ]

        for collection in collections:
            try:
                self.qdrant_client.create_collection(
                    collection_name=collection["name"],
                    vectors_config=VectorParams(
                        size=collection["vector_size"],
                        distance=collection["distance"]
                    ),
                )
                logger.debug(f"Created Qdrant collection: {collection['name']}")
            except Exception as e:
                logger.debug(f"Collection {collection['name']} may already exist: {e}")

    # ========================================================================
    # EVENT BUS INTEGRATION
    # ========================================================================

    def _track_task(self, coro):
        """Track an async task for graceful shutdown"""
        task = asyncio.create_task(coro)
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)
        return task

    async def _setup_event_subscriptions(self) -> None:
        """Setup event bus subscriptions for automatic storage"""

        @self.event_bus.subscribe("finding.discovered")
        async def on_finding_discovered(event: FindingDiscoveredEvent):
            """Automatically store finding when discovered"""
            async def store_finding():
                try:
                    vulnerability = Vulnerability(
                        id=event.finding_id,
                        title=event.title,
                        description=event.description,
                        severity=VulnerabilitySeverity(event.severity),
                        category=event.category,
                        confidence=event.confidence,
                        evidence=event.evidence,
                        proof_of_concept=event.proof_of_concept,
                        remediation=event.remediation,
                        cwe_id=event.cwe_id,
                        cvss_score=event.cvss_score,
                    )
                    await self.store_vulnerability(vulnerability, event.target)
                    logger.debug(f"Auto-stored finding: {event.finding_id}")
                except Exception as e:
                    logger.error(f"Failed to auto-store finding: {e}")
                    self.stats["errors"] += 1

            # Track the task for graceful shutdown
            self._track_task(store_finding())

        @self.event_bus.subscribe("finding.validated")
        async def on_finding_validated(event: FindingValidatedEvent):
            """Update vulnerability validation state when PoC validation completes"""
            async def update_validation_state_task():
                try:
                    await self.update_vulnerability_validation(
                        vulnerability_id=event.finding_id,
                        validation_result=event.validation_result,
                        validation_method=event.validation_method,
                        validation_time=event.validation_time,
                    )
                    logger.debug(f"Updated validation state for finding: {event.finding_id}")
                except Exception as e:
                    logger.error(f"Failed to update validation state: {e}")
                    self.stats["errors"] += 1

            self._track_task(update_validation_state_task())

        @self.event_bus.subscribe("scan.started")
        async def on_scan_started(event: ScanStartedEvent):
            """Initialize scan state when scan starts"""
            async def store_scan_state_task():
                try:
                    scan_state = ScanState(
                        scan_id=event.scan_id,
                        target=event.target,
                        mode=event.mode,
                        status="running",
                        start_time=event.timestamp,
                        agents_total=event.agent_count,
                    )
                    await self.store_scan_state(scan_state)
                    logger.debug(f"Initialized scan state: {event.scan_id}")
                except Exception as e:
                    logger.error(f"Failed to initialize scan state: {e}")
                    self.stats["errors"] += 1

            # Track the task for graceful shutdown
            self._track_task(store_scan_state_task())

        @self.event_bus.subscribe("scan.completed")
        async def on_scan_completed(event: ScanCompletedEvent):
            """Update scan state when scan completes"""
            async def update_scan_state_task():
                try:
                    scan_state = await self.get_scan_state(event.scan_id)
                    if scan_state:
                        scan_state.status = "completed" if event.success else "failed"
                        scan_state.end_time = event.timestamp
                        scan_state.findings_count = event.total_findings
                        await self.store_scan_state(scan_state)
                        logger.debug(f"Updated scan state: {event.scan_id}")
                except Exception as e:
                    logger.error(f"Failed to update scan state: {e}")
                    self.stats["errors"] += 1

            # Track the task for graceful shutdown
            self._track_task(update_scan_state_task())

    # ========================================================================
    # VULNERABILITY OPERATIONS
    # ========================================================================

    async def store_vulnerability(
        self,
        vulnerability: Vulnerability,
        target_url: str
    ) -> str:
        """
        Store vulnerability in all memory systems

        Args:
            vulnerability: Vulnerability to store
            target_url: Target URL

        Returns:
            Vulnerability ID
        """
        try:
            # Store in Neo4j (graph)
            await self._store_vulnerability_neo4j(vulnerability, target_url)

            # Store in Qdrant (vector search)
            await self._store_vulnerability_qdrant(vulnerability)

            # Cache in Redis
            await self._cache_vulnerability_redis(vulnerability)

            self.stats["findings_stored"] += 1

            # Publish event (only if event bus is available)
            if self.event_bus:
                try:
                    await self.event_bus.publish("memory.finding.stored", {
                        "finding_id": vulnerability.id,
                        "stored_in": ["neo4j", "qdrant", "redis"],
                        "timestamp": datetime.now().isoformat(),
                    })
                except Exception as e:
                    # Don't fail storage if event publishing fails
                    logger.debug(f"Failed to publish memory.finding.stored event: {e}")

            return vulnerability.id

        except Exception as e:
            logger.error(f"Failed to store vulnerability: {e}")
            self.stats["errors"] += 1
            raise

    async def update_vulnerability_validation(self, vulnerability_id: str, validation_result: bool, validation_method: str, validation_time: float) -> bool:
        vulnerability = await self.get_vulnerability(vulnerability_id)
        if not vulnerability:
            logger.debug(f"Validation update skipped, vulnerability not found: {vulnerability_id}")
            return False

        now = datetime.now()
        vulnerability.last_validated = now
        vulnerability.validation_count = int(vulnerability.validation_count or 0) + 1
        vulnerability.validation_status = "validated" if validation_result else "failed_validation"
        vulnerability.poc_validated = bool(validation_result)

        history = vulnerability.metadata.get("validation_history", [])
        if not isinstance(history, list):
            history = []
        history.append({
            "timestamp": now.isoformat(),
            "status": vulnerability.validation_status,
            "method": validation_method,
            "duration_seconds": float(validation_time),
        })
        vulnerability.metadata["validation_history"] = history[-20:]

        async with self.neo4j_driver.session() as session:
            result = await session.run(
                """
                MATCH (v:Vulnerability {id: $vuln_id})
                SET v += $props
                RETURN v.id AS id
                """,
                vuln_id=vulnerability_id,
                props=vulnerability.to_neo4j(),
            )
            record = await result.single()
            if not record:
                return False

        await self._store_vulnerability_qdrant(vulnerability)
        await self._cache_vulnerability_redis(vulnerability)
        return True

    async def _store_vulnerability_neo4j(
        self,
        vulnerability: Vulnerability,
        target_url: str
    ) -> None:
        """Store vulnerability in Neo4j"""
        async with self.neo4j_driver.session() as session:
            # Create or update target
            await session.run(
                """
                MERGE (t:Target {url: $url})
                ON CREATE SET t.id = $target_id,
                             t.hostname = $hostname,
                             t.first_seen = datetime($now),
                             t.scan_count = 1
                ON MATCH SET t.last_seen = datetime($now),
                            t.scan_count = t.scan_count + 1
                """,
                url=target_url,
                target_id=self._generate_id(target_url),
                hostname=self._extract_hostname(target_url),
                now=datetime.now().isoformat(),
            )

            # Create vulnerability node
            await session.run(
                """
                CREATE (v:Vulnerability $props)
                """,
                props=vulnerability.to_neo4j(),
            )

            # Create relationship
            await session.run(
                """
                MATCH (t:Target {url: $url})
                MATCH (v:Vulnerability {id: $vuln_id})
                MERGE (t)-[:HAS_VULNERABILITY]->(v)
                """,
                url=target_url,
                vuln_id=vulnerability.id,
            )

    async def _store_vulnerability_qdrant(self, vulnerability: Vulnerability) -> None:
        """Store vulnerability in Qdrant for semantic search"""
        # Generate embedding
        text = vulnerability.get_embedding_text()
        embedding = self.embedding_model.encode(text).tolist()

        # Store in Qdrant
        self.qdrant_client.upsert(
            collection_name="findings",
            points=[
                PointStruct(
                    id=self._hash_to_int(vulnerability.id),
                    vector=embedding,
                    payload=vulnerability.to_qdrant_payload(),
                )
            ],
        )

    async def _cache_vulnerability_redis(self, vulnerability: Vulnerability) -> None:
        """Cache vulnerability in Redis"""
        await self.redis_client.setex(
            f"finding:{vulnerability.id}",
            3600,  # 1 hour TTL
            json.dumps(vulnerability.to_neo4j()),
        )

    async def get_vulnerability(self, vulnerability_id: str) -> Optional[Vulnerability]:
        """
        Get vulnerability by ID

        Checks Redis cache first, then queries Neo4j.

        Args:
            vulnerability_id: Vulnerability ID

        Returns:
            Vulnerability if found, None otherwise
        """
        try:
            # Try cache first
            cached = await self.redis_client.get(f"finding:{vulnerability_id}")
            if cached:
                self.stats["cache_hits"] += 1
                data = json.loads(cached)
                return Vulnerability.from_neo4j(data)

            self.stats["cache_misses"] += 1

            # Query Neo4j
            async with self.neo4j_driver.session() as session:
                result = await session.run(
                    """
                    MATCH (v:Vulnerability {id: $vuln_id})
                    RETURN v
                    """,
                    vuln_id=vulnerability_id,
                )
                record = await result.single()
                if record:
                    vuln = Vulnerability.from_neo4j(dict(record["v"]))
                    # Cache for next time
                    await self._cache_vulnerability_redis(vuln)
                    return vuln

            return None

        except Exception as e:
            logger.error(f"Failed to get vulnerability: {e}")
            self.stats["errors"] += 1
            return None

    async def search_similar_vulnerabilities(
        self,
        vulnerability: Vulnerability,
        limit: int = 10,
        min_confidence: float = 0.7
    ) -> List[Vulnerability]:
        """
        Find similar vulnerabilities using semantic search

        Args:
            vulnerability: Query vulnerability
            limit: Maximum results
            min_confidence: Minimum confidence threshold

        Returns:
            List of similar vulnerabilities
        """
        try:
            # Generate embedding
            text = vulnerability.get_embedding_text()
            embedding = self.embedding_model.encode(text).tolist()

            # Search Qdrant
            results = self.qdrant_client.search(
                collection_name="findings",
                query_vector=embedding,
                limit=limit,
                query_filter=Filter(
                    must=[
                        FieldCondition(
                            key="confidence",
                            range=Range(gte=min_confidence)
                        ),
                        FieldCondition(
                            key="validated",
                            match=MatchValue(value=True)
                        ),
                    ]
                ),
            )

            self.stats["queries_executed"] += 1

            # Convert to Vulnerability objects
            vulnerabilities = []
            for result in results:
                vuln = await self.get_vulnerability(result.payload["finding_id"])
                if vuln:
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            logger.error(f"Failed to search similar vulnerabilities: {e}")
            self.stats["errors"] += 1
            return []

    # ========================================================================
    # ATTACK PATH OPERATIONS
    # ========================================================================

    async def find_attack_paths(
        self,
        from_severity: str = "high",
        to_impact: str = "privilege_escalation",
        max_depth: int = 5,
        min_confidence: float = 0.8
    ) -> List[AttackPath]:
        """
        Find attack paths in the graph

        Args:
            from_severity: Starting vulnerability severity
            to_impact: Target impact
            max_depth: Maximum path length
            min_confidence: Minimum confidence threshold

        Returns:
            List of attack paths
        """
        try:
            async with self.neo4j_driver.session() as session:
                result = await session.run(
                    f"""
                    MATCH path = (v1:Vulnerability {{severity: $severity}})-[:LEADS_TO*1..{max_depth}]->(v2:Vulnerability)
                    WHERE v1.confidence >= $min_confidence
                      AND v2.metadata CONTAINS $impact
                    RETURN path
                    ORDER BY length(path)
                    LIMIT 10
                    """,
                    severity=from_severity,
                    impact=to_impact,
                    min_confidence=min_confidence,
                )

                paths = []
                async for record in result:
                    path = record["path"]
                    attack_path = await self._convert_to_attack_path(path)
                    paths.append(attack_path)

                self.stats["queries_executed"] += 1
                return paths

        except Exception as e:
            logger.error(f"Failed to find attack paths: {e}")
            self.stats["errors"] += 1
            return []

    async def _convert_to_attack_path(self, neo4j_path) -> AttackPath:
        """Convert Neo4j path to AttackPath object"""
        vulnerabilities = []
        for node in neo4j_path.nodes:
            if "Vulnerability" in node.labels:
                vuln = Vulnerability.from_neo4j(dict(node))
                vulnerabilities.append(vuln)

        # Calculate success probability
        success_prob = 1.0
        for vuln in vulnerabilities:
            success_prob *= vuln.confidence

        # Determine complexity
        if len(vulnerabilities) <= 2:
            complexity = AttackComplexity.LOW
        elif len(vulnerabilities) <= 4:
            complexity = AttackComplexity.MEDIUM
        else:
            complexity = AttackComplexity.HIGH

        return AttackPath(
            path_id=self._generate_id(str([v.id for v in vulnerabilities])),
            vulnerabilities=vulnerabilities,
            exploits=[],  # TODO: Extract exploits from path
            success_probability=success_prob,
            complexity=complexity,
            estimated_time=len(vulnerabilities) * 10.0,  # Rough estimate
        )

    # ========================================================================
    # SCAN STATE OPERATIONS
    # ========================================================================

    async def store_scan_state(self, scan_state: ScanState) -> None:
        """Store scan state in Redis"""
        try:
            await self.redis_client.hset(
                f"scan:{scan_state.scan_id}",
                mapping=scan_state.to_redis(),
            )
        except Exception as e:
            logger.error(f"Failed to store scan state: {e}")
            self.stats["errors"] += 1
            raise

    async def get_scan_state(self, scan_id: str) -> Optional[ScanState]:
        """Get scan state from Redis"""
        try:
            data = await self.redis_client.hgetall(f"scan:{scan_id}")
            if data:
                # Convert bytes to strings
                data = {k.decode(): v.decode() for k, v in data.items()}
                return ScanState.from_redis(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get scan state: {e}")
            self.stats["errors"] += 1
            return None

    async def acquire_scan_lock(self, target: str, scan_id: str) -> bool:
        """
        Acquire distributed lock for scanning target

        Args:
            target: Target URL
            scan_id: Scan ID

        Returns:
            True if lock acquired, False otherwise
        """
        try:
            lock_key = f"lock:scan:{target}"
            acquired = await self.redis_client.set(
                lock_key,
                scan_id,
                nx=True,  # Only set if not exists
                ex=300,   # 5 minute TTL
            )
            return bool(acquired)
        except Exception as e:
            logger.error(f"Failed to acquire scan lock: {e}")
            self.stats["errors"] += 1
            return False

    async def release_scan_lock(self, target: str, scan_id: str) -> bool:
        """
        Release scan lock

        Args:
            target: Target URL
            scan_id: Scan ID (must match)

        Returns:
            True if released, False otherwise
        """
        try:
            lock_key = f"lock:scan:{target}"
            current_holder = await self.redis_client.get(lock_key)

            if current_holder and current_holder.decode() == scan_id:
                await self.redis_client.delete(lock_key)
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to release scan lock: {e}")
            self.stats["errors"] += 1
            return False

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def _generate_id(self, text: str) -> str:
        """Generate deterministic ID from text"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _hash_to_int(self, text: str) -> int:
        """Convert hash to integer for Qdrant"""
        return int(hashlib.sha256(text.encode()).hexdigest()[:16], 16)

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        return url.split("://")[-1].split("/")[0].split(":")[0]

    async def get_stats(self) -> Dict[str, Any]:
        """Get memory manager statistics"""
        return {
            **self.stats,
            "neo4j_connected": self.neo4j_driver is not None,
            "qdrant_connected": self.qdrant_client is not None,
            "redis_connected": await self.redis_client.ping() if self.redis_client else False,
            "initialized": self._initialized,
        }


# Global memory manager instance
_memory_manager: Optional[MemoryManager] = None


def get_memory_manager() -> MemoryManager:
    """Get global memory manager instance"""
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager()
    return _memory_manager


def set_memory_manager(memory_manager: MemoryManager) -> None:
    """Set global memory manager instance"""
    global _memory_manager
    _memory_manager = memory_manager
