"""
Lightpanda Headless Browser Integration — lightweight Rust-based browser.
Use as alternative to Playwright for CI/CD and resource-constrained environments.
"""

import asyncio
import json
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class BrowserPage:
    url: str
    html: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    screenshot: Optional[str] = None


class LightpandaBrowser:
    def __init__(self, binary: str = "lightpanda", port: int = 9230):
        self.binary = binary
        self.port = port
        self._process: Optional[asyncio.subprocess.Process] = None
        self._available = None

    async def check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            self._available = proc.returncode == 0
            return self._available
        except Exception:
            self._available = False
            return False

    async def start(self) -> bool:
        if not await self.check_available():
            logger.warning("Lightpanda not installed, falling back to Playwright")
            return False
        try:
            self._process = await asyncio.create_subprocess_exec(
                self.binary, "--port", str(self.port),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.sleep(1)
            logger.info(f"Lightpanda browser started on port {self.port}")
            return True
        except Exception as e:
            logger.debug(f"Lightpanda start failed: {e}")
            return False

    async def navigate(self, url: str, timeout: float = 15.0) -> Optional[BrowserPage]:
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"url": url, "timeout": int(timeout * 1000)}
                async with session.post(f"http://localhost:{self.port}/navigate", json=payload) as resp:
                    data = await resp.json()
                    return BrowserPage(
                        url=data.get("url", url),
                        html=data.get("html", ""),
                        status_code=data.get("status", 0),
                        headers=data.get("headers", {}),
                        cookies=data.get("cookies", []),
                    )
        except Exception as e:
            logger.debug(f"Lightpanda navigate error: {e}")
            return None

    async def stop(self):
        if self._process:
            self._process.kill()
            self._process = None
            logger.info("Lightpanda browser stopped")

    @property
    def is_lightweight(self) -> bool:
        return True  # Lightpanda uses ~10MB vs Playwright's ~300MB
