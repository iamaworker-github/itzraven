#!/usr/bin/env python3
"""
Initialize Itzraven Memory System

Creates database schemas, collections, and indexes.
Run this after starting the Docker containers.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from itzraven.core.memory_manager import MemoryManager
from itzraven.core.config import get_config
from itzraven.core.logger import get_logger, setup_logging

logger = get_logger()


async def main():
    """Initialize memory system"""
    print("=" * 60)
    print("Itzraven Memory System Initialization")
    print("=" * 60)
    print()

    # Setup logging
    setup_logging(Path("./logs"), verbose=True)

    # Use default configuration values
    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_password = "itzraven_password_2026"
    qdrant_host = "localhost"
    qdrant_port = 6333
    redis_url = "redis://localhost:6379/0"

    print("Configuration:")
    print(f"  Neo4j URI: {neo4j_uri}")
    print(f"  Qdrant: {qdrant_host}:{qdrant_port}")
    print(f"  Redis: {redis_url}")
    print()

    try:
        # Create memory manager
        print("Creating Memory Manager...")
        memory_manager = MemoryManager(
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            qdrant_host=qdrant_host,
            qdrant_port=qdrant_port,
            redis_url=redis_url,
        )

        # Initialize
        print("Initializing...")
        await memory_manager.initialize()
        print()

        # Verify connections
        print("Verifying connections...")
        stats = await memory_manager.get_stats()

        print(f"  \u2713 Neo4j: {'Connected' if stats['neo4j_connected'] else 'Failed'}")
        print(f"  \u2713 Qdrant: {'Connected' if stats['qdrant_connected'] else 'Failed'}")
        print(f"  \u2713 Redis: {'Connected' if stats['redis_connected'] else 'Failed'}")
        print()

        # Close
        await memory_manager.close()

        print("=" * 60)
        print("\u2713 Memory System initialized successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("  1. Test with: python scripts/check_memory_health.py")
        print("  2. Try examples: python examples/memory_system_integration.py")
        print("  3. Integrate with Itzraven")
        print()

    except Exception as e:
        print()
        print("=" * 60)
        print("\u2717 Initialization failed!")
        print("=" * 60)
        print(f"Error: {e}")
        print()
        print("Troubleshooting:")
        print("  1. Check Docker containers are running:")
        print("     docker-compose -f docker-compose.memory.yml ps")
        print("  2. Check logs:")
        print("     docker-compose -f docker-compose.memory.yml logs")
        print("  3. Verify ports are not in use:")
        print("     netstat -an | grep -E '(7687|6333|6379)'")
        print()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
