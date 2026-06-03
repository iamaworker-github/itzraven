"""
Browser automation wrapper using Playwright
"""

import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
from itzraven.core.config import get_config
from itzraven.core.logger import get_logger
from itzraven.core.scope import ScopeValidator

logger = get_logger()
config = get_config()


@dataclass
class BrowserSession:
    """Browser session information"""
    browser: Browser
    context: BrowserContext
    pages: List[Page]


class BrowserAutomation:
    """Browser automation for client-side testing"""

    def __init__(self, headless: bool = True, scope_validator: Optional[ScopeValidator] = None):
        self.headless = headless if headless is not None else config.headless_browser
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.pages: List[Page] = []
        self.scope_validator = scope_validator

    async def start(self) -> None:
        """Start browser automation"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        logger.info(f"Browser started (headless={self.headless})")

    async def stop(self) -> None:
        """Stop browser automation"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("Browser stopped")

    async def new_page(self, url: Optional[str] = None) -> Page:
        """Create a new page/tab"""
        if not self.context:
            await self.start()

        if url and self.scope_validator and not self.scope_validator.is_in_scope(url):
            logger.warning(f"Scope violation blocked: {url}")
            raise PermissionError(f"Target {url} is out of scope")

        page = await self.context.new_page()
        self.pages.append(page)

        if url:
            await page.goto(url, wait_until="networkidle", timeout=config.browser_timeout)

        logger.debug(f"New page created: {url or 'blank'}")
        return page

    async def execute_script(self, page: Page, script: str) -> Any:
        """Execute JavaScript in page context"""
        try:
            result = await page.evaluate(script)
            return result
        except Exception as e:
            logger.error(f"Script execution failed: {e}")
            return None

    async def find_xss(self, page: Page, payload: str) -> bool:
        """Test for XSS vulnerability"""
        try:
            # Inject payload
            await page.evaluate(f"document.body.innerHTML += '{payload}'")

            # Check if alert was triggered
            dialog_triggered = False

            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)
            await asyncio.sleep(0.5)

            return dialog_triggered
        except Exception as e:
            logger.error(f"XSS test failed: {e}")
            return False

    async def get_dom(self, page: Page) -> str:
        """Get page DOM content"""
        try:
            return await page.content()
        except Exception as e:
            logger.error(f"Failed to get DOM: {e}")
            return ""

    async def get_cookies(self, page: Page) -> List[Dict[str, Any]]:
        """Get page cookies"""
        try:
            return await page.context.cookies()
        except Exception as e:
            logger.error(f"Failed to get cookies: {e}")
            return []

    async def set_cookie(self, page: Page, cookie: Dict[str, Any]) -> None:
        """Set a cookie"""
        try:
            await page.context.add_cookies([cookie])
        except Exception as e:
            logger.error(f"Failed to set cookie: {e}")

    async def screenshot(self, page: Page, path: str) -> bool:
        """Take a screenshot"""
        try:
            await page.screenshot(path=path, full_page=True)
            logger.success(f"Screenshot saved: {path}")
            return True
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return False

    async def intercept_requests(self, page: Page, handler: callable) -> None:
        """Intercept and modify network requests"""
        await page.route("**/*", handler)

    async def close_page(self, page: Page) -> None:
        """Close a specific page"""
        if page in self.pages:
            await page.close()
            self.pages.remove(page)
