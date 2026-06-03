"""Tests for the WebSocket Real-Time API."""

import pytest
from itzraven.core.ws_api import WebSocketAPI


@pytest.mark.asyncio
async def test_ws_api_init():
    api = WebSocketAPI(host="127.0.0.1", port=18765)
    assert api.host == "127.0.0.1"
    assert api.port == 18765


@pytest.mark.asyncio
async def test_ws_api_start_stop():
    api = WebSocketAPI(host="127.0.0.1", port=18766)
    await api.start()
    assert api._running is True
    await api.stop()
    assert api._running is False


def test_ws_api_singleton():
    from itzraven.core.ws_api import get_ws_api
    w1 = get_ws_api()
    w2 = get_ws_api()
    assert w1 is w2
