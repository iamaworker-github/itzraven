import json
from typing import Optional, Dict, Any, List
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()


class BurpIntegrationError(Exception):
    """Raised when Burp Suite integration fails."""


class BurpIntegration:
    """Integration with Burp Suite for proxied scanning and findings retrieval.

    Requires BURP_API_KEY and BURP_URL environment variables.
    """

    def __init__(self, burp_url: Optional[str] = None, api_key: Optional[str] = None):
        config = get_config()
        self.burp_url = (burp_url or config.get("burp_url") or "").rstrip("/")
        self.api_key = api_key or config.get("burp_api_key") or ""
        self._session: Optional[Any] = None

    async def _ensure_session(self) -> Any:
        if self._session is None:
            import aiohttp
            headers = {
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._session = aiohttp.ClientSession(
                base_url=self.burp_url,
                headers=headers,
            )
        return self._session

    async def send_to_burp(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Proxy an HTTP request through Burp Suite.

        ``request`` should contain::

            {
                "url": "https://example.com/path",
                "method": "GET",
                "headers": {"Host": "example.com"},
                "body": "...",
            }
        """
        if not self.burp_url:
            raise BurpIntegrationError("BURP_URL is not configured. Set BURP_URL environment variable.")

        session = await self._ensure_session()

        payload = {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "headers": request.get("headers", {}),
            "body": request.get("body", ""),
        }

        try:
            async with session.post("/v0.1/proxy/send", json=payload) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    raise BurpIntegrationError(f"Burp API error ({resp.status}): {text[:200]}")
                return await resp.json()
        except BurpIntegrationError:
            raise
        except Exception as e:
            raise BurpIntegrationError(f"Failed to send request to Burp: {e}")

    async def get_findings_from_burp(self) -> List[Dict[str, Any]]:
        """Fetch scan findings from Burp Suite REST API."""
        if not self.burp_url:
            raise BurpIntegrationError("BURP_URL is not configured. Set BURP_URL environment variable.")

        session = await self._ensure_session()

        try:
            findings = []
            offset = 0
            limit = 100

            while True:
                async with session.get(f"/v0.1/scan/results", params={
                    "offset": offset,
                    "limit": limit,
                }) as resp:
                    if resp.status >= 400:
                        text = await resp.text()
                        raise BurpIntegrationError(f"Burp API error ({resp.status}): {text[:200]}")

                    data = await resp.json()

                items = data.get("results", [])
                findings.extend(items)

                if len(items) < limit:
                    break
                offset += limit

            return findings

        except BurpIntegrationError:
            raise
        except Exception as e:
            raise BurpIntegrationError(f"Failed to fetch findings from Burp: {e}")

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None
