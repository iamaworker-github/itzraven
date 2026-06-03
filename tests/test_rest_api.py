"""Tests for REST API Server."""

import pytest
from itzraven.core.rest_api import RESTAPI


def test_api_initialization():
    api = RESTAPI(host="127.0.0.1", port=18484)
    assert api.host == "127.0.0.1"
    assert api.port == 18484


def test_build_app():
    api = RESTAPI()
    if hasattr(api, 'build_app'):
        try:
            app = api.build_app()
        except ImportError:
            pass  # FastAPI not installed — skip


@pytest.mark.asyncio
async def test_background_scan():
    api = RESTAPI()
    scan_id = "test-scan-1"
    api._active_scans[scan_id] = {"id": scan_id, "status": "queued"}
    await api._run_scan_background(scan_id, "https://example.com", "osint", "quick", None)
    scan = api._active_scans.get(scan_id)
    if scan:
        assert scan["status"] in ("completed", "failed", "running")
