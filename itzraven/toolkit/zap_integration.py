import asyncio
import time
from typing import Optional, Dict, Any, List
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()


class ZAPIntegrationError(Exception):
    """Raised when ZAP integration fails."""


class ZAPIntegration:
    """Integration with OWASP ZAP for automated scanning.

    Requires ZAP_API_KEY and ZAP_URL environment variables.
    """

    def __init__(self, zap_url: Optional[str] = None, api_key: Optional[str] = None):
        config = get_config()
        self.zap_url = (zap_url or config.get("zap_url") or "http://localhost:8080").rstrip("/")
        self.api_key = api_key or config.get("zap_api_key") or ""
        self._session: Optional[Any] = None

    async def _ensure_session(self) -> Any:
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession(
                base_url=self.zap_url,
            )
        return self._session

    async def start_scan(self, target: str, scan_type: str = "spider") -> str:
        """Start a ZAP spider or active scan against a target.

        Args:
            target: URL to scan (e.g. https://example.com)
            scan_type: 'spider' (passive) or 'ascan' (active)

        Returns:
            Scan ID string.
        """
        if not self.zap_url:
            raise ZAPIntegrationError("ZAP_URL is not configured. Set ZAP_URL environment variable.")

        session = await self._ensure_session()
        params = {"url": target, "apikey": self.api_key}

        try:
            if scan_type == "spider":
                async with session.get("/JSON/spider/action/scan/", params=params) as resp:
                    data = await resp.json()
                    scan_id = data.get("scan")
                    if not scan_id:
                        raise ZAPIntegrationError(f"ZAP spider failed: {data}")
            else:
                async with session.get("/JSON/ascan/action/scan/", params=params) as resp:
                    data = await resp.json()
                    scan_id = data.get("scan")
                    if not scan_id:
                        raise ZAPIntegrationError(f"ZAP active scan failed: {data}")

            logger.info(f"ZAP {scan_type} scan started — ID: {scan_id}")
            return str(scan_id)

        except ZAPIntegrationError:
            raise
        except Exception as e:
            raise ZAPIntegrationError(f"Failed to start ZAP scan: {e}")

    async def scan_status(self, scan_id: str, scan_type: str = "spider") -> int:
        """Check the progress of a ZAP scan.

        Returns:
            Percentage complete (0–100).
        """
        session = await self._ensure_session()
        endpoint = "/JSON/spider/view/status/" if scan_type == "spider" else "/JSON/ascan/view/status/"
        params = {"scanId": scan_id, "apikey": self.api_key}

        try:
            async with session.get(endpoint, params=params) as resp:
                data = await resp.json()
                return int(data.get("status", 0))
        except Exception as e:
            raise ZAPIntegrationError(f"Failed to get scan status: {e}")

    async def wait_for_scan(self, scan_id: str, scan_type: str = "spider",
                            poll_interval: float = 2.0, timeout: float = 600.0) -> None:
        """Poll ZAP until the scan completes."""
        start = time.time()
        while True:
            if time.time() - start > timeout:
                raise ZAPIntegrationError(f"ZAP scan {scan_id} timed out after {timeout}s")
            status = await self.scan_status(scan_id, scan_type)
            if status >= 100:
                logger.info(f"ZAP {scan_type} scan {scan_id} completed")
                return
            await asyncio.sleep(poll_interval)

    async def get_alerts(self, base_url: str = "", risk: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch ZAP alerts as dicts.

        Args:
            base_url: Filter alerts by URL (optional)
            risk: Filter by risk level (0=Info, 1=Low, 2=Medium, 3=High)

        Returns:
            List of alert dicts with keys: title, description, severity,
            category, evidence, remediation, confidence.
        """
        session = await self._ensure_session()
        params: Dict[str, Any] = {"apikey": self.api_key}
        if base_url:
            params["baseurl"] = base_url
        if risk is not None:
            params["riskId"] = risk

        try:
            async with session.get("/JSON/alert/view/alerts/", params=params) as resp:
                data = await resp.json()
        except Exception as e:
            raise ZAPIntegrationError(f"Failed to fetch ZAP alerts: {e}")

        findings: List[Dict[str, Any]] = []
        severity_map = {
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "info",
        }

        for alert in data.get("alerts", []):
            risk_id = str(alert.get("riskId", "0"))
            evidence = alert.get("evidence", "") or alert.get("param", "") or alert.get("attack", "")
            finding = {
                "title": alert.get("name", "ZAP Alert"),
                "description": alert.get("description", ""),
                "severity": severity_map.get(risk_id, "info"),
                "category": "zap_alert",
                "evidence": evidence[:500],
                "remediation": alert.get("solution", ""),
                "confidence": 0.7,
            }
            findings.append(finding)

        logger.info(f"Fetched {len(findings)} alerts from ZAP")
        return findings

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

import asyncio
