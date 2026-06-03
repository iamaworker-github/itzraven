import asyncio
from typing import Optional, List
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.osint.osint_base import OSINTBaseAgent

logger = get_logger()


class VisualIntelAgent(OSINTBaseAgent):
    """Visual reconnaissance agent — captures screenshots and page metadata.

    Uses Playwright (browser automation) for screenshot capture.
    Falls back to HTTP-only title extraction when the browser is unavailable.
    """

    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope: Optional[List[str]] = None,
    ):
        super().__init__("Visual Intel Agent", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.page_title: Optional[str] = None
        self.screenshot_path: Optional[str] = None
        self.page_text_snippet: Optional[str] = None

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Capturing visual intel on {self.target}")

        url = self.target
        if not url.startswith("http"):
            url = f"https://{url}"

        browser_available = False
        if self.browser:
            try:
                browser_available = await self._try_browser_capture(url)
            except Exception as e:
                logger.debug(f"{self.name}: Browser capture failed — {e}")

        if not browser_available:
            await self._http_fallback(url)

        self._create_findings()

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "page_title": self.page_title,
                "screenshot_path": self.screenshot_path,
                "url": url,
            },
        )

    async def _try_browser_capture(self, url: str) -> bool:
        try:
            config = get_config()
            headless = config.get("headless_browser") if config else True
            timeout = config.get("browser_timeout") if config else 30000

            page = await self.browser.browser.new_page()
            try:
                await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                self.page_title = await page.title()

                import tempfile
                from pathlib import Path
                output_dir = Path(config.get("output_dir")) if config else Path("./itzraven_results")
                output_dir.mkdir(parents=True, exist_ok=True)
                screenshot_file = output_dir / f"screenshot_{self.name.replace(' ', '_')}.png"
                await page.screenshot(path=str(screenshot_file), full_page=True)
                self.screenshot_path = str(screenshot_file.absolute())

                content = await page.content()
                self.page_text_snippet = content[:200] if content else None
            finally:
                await page.close()
            return True
        except Exception as e:
            logger.debug(f"{self.name}: Browser screenshot failed — {e}")
            return False

    async def _http_fallback(self, url: str) -> None:
        try:
            import httpx
            from bs4 import BeautifulSoup
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    title_tag = soup.find("title")
                    self.page_title = title_tag.get_text(strip=True) if title_tag else None
                    self.page_text_snippet = resp.text[:200]
        except ImportError:
            logger.warning(f"{self.name}: httpx/bs4 not installed — using simulated data")
            self.page_title = f"{self.target} (simulated title)"
            self.page_text_snippet = "(simulated page content)"
        except Exception as e:
            logger.debug(f"{self.name}: HTTP fallback failed — {e}")
            self.page_title = None

    def _create_findings(self) -> None:
        if self.page_title:
            self.add_finding(Finding(
                title="Page Title Detected",
                description=f"Target page title: {self.page_title}",
                severity="info",
                category="osint_visual",
                evidence=f"Title: {self.page_title}",
                confidence=0.9,
            ))

        if self.screenshot_path:
            self.add_finding(Finding(
                title="Screenshot Captured",
                description=f"Visual reconnaissance screenshot saved",
                severity="info",
                category="osint_visual",
                evidence=f"Screenshot: {self.screenshot_path}",
                confidence=1.0,
            ))

        if self.page_text_snippet:
            self.add_finding(Finding(
                title="Page Content Sample",
                description=f"Retrieved {len(self.page_text_snippet)} characters of page content",
                severity="info",
                category="osint_visual",
                evidence=f"Content preview: {self.page_text_snippet[:100]}...",
                confidence=0.8,
            ))
