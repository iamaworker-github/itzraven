#!/usr/bin/env python3
"""
Health check for Itzraven Memory System

Verifies all components are running and accessible.
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from itzraven.core.memory_manager import MemoryManager
from itzraven.core.config import get_config


async def check_health():
    """Check health of all memory components"""
    # Use default configuration values
    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_password = "itzraven_password_2026"
    qdrant_host = "localhost"
    qdrant_port = 6333
    redis_url = "redis://localhost:6379/0"

    print()
    print("=" * 60)
    print("Itzraven Memory System Health Check")
    print("=" * 60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    memory_manager = MemoryManager(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        qdrant_host=qdrant_host,
        qdrant_port=qdrant_port,
        redis_url=redis_url,
    )

    all_healthy = True

    # Check Neo4j
    print("Neo4j:")
    try:
        await memory_manager.initialize()
        async with memory_manager.neo4j_driver.session() as session:
            result = await session.run("RETURN 1 as num")
            record = await result.single()
            assert record["num"] == 1
        print("  \u2713 Connected")
        print(f"  \u2713 URI: {neo4j_uri}")
    except Exception as e:
        print(f"  \u2717 Failed: {e}")
        all_healthy = False

    print()

    # Check Qdrant
    print("Qdrant:")
    try:
        collections = memory_manager.qdrant_client.get_collections()
        print("  \u2713 Connected")
        print(f"  \u2713 Host: {qdrant_host}:{qdrant_port}")
        print(f"  \u2713 Collections: {len(collections.collections)}")
        for collection in collections.collections:
            print(f"    - {collection.name}")
    except Exception as e:
        print(f"  \u2717 Failed: {e}")
        all_healthy = False

    print()

    # Check Redis
    print("Redis:")
    try:
        pong = await memory_manager.redis_client.ping()
        print(f"  \u2713 Connected (ping={pong})")
        print(f"  \u2713 URL: {redis_url}")

        # Get info
        info = await memory_manager.redis_client.info("memory")
        used_memory = info.get("used_memory_human", "unknown")
        print(f"  \u2713 Memory used: {used_memory}")
    except Exception as e:
        print(f"  \u2717 Failed: {e}")
        all_healthy = False

    print()

    # Get statistics
    print("Statistics:")
    try:
        stats = await memory_manager.get_stats()
        print(f"  Findings stored: {stats['findings_stored']}")
        print(f"  Queries executed: {stats['queries_executed']}")
        print(f"  Cache hits: {stats['cache_hits']}")
        print(f"  Cache misses: {stats['cache_misses']}")
        print(f"  Errors: {stats['errors']}")
    except Exception as e:
        print(f"  \u2717 Failed to get stats: {e}")

    print()

    # Close
    await memory_manager.close()

    # Summary
    print("=" * 60)
    if all_healthy:
        print("\u2713 All systems healthy")
        print("=" * 60)
        print()
        return 0
    else:
        print("\u2717 Some systems unhealthy")
        print("=" * 60)
        print()
        print("Troubleshooting:")
        print("  1. Check Docker containers:")
        print("     docker-compose -f docker-compose.memory.yml ps")
        print("  2. Restart services:")
        print("     docker-compose -f docker-compose.memory.yml restart")
        print("  3. Check logs:")
        print("     docker-compose -f docker-compose.memory.yml logs")
        print()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(check_health())
    sys.exit(exit_code)
