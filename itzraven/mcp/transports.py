import asyncio
import json
import sys
from typing import Any, Dict, Optional

from itzraven.core.logger import get_logger

logger = get_logger()


async def handle_stdio(mcp_app: Any) -> None:
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            response = await mcp_app.process_message(msg)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received: {line}")
        except Exception as e:
            logger.error(f"MCP error: {e}")


async def handle_sse(mcp_app: Any, host: str = "0.0.0.0", port: int = 8000) -> None:
    from aiohttp import web

    async def handle_post(request):
        try:
            body = await request.json()
            response = await mcp_app.process_message(body)
            return web.json_response(response)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_sse_endpoint(request):
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await response.prepare(request)
        async def send_event(data: dict):
            await response.write(f"data: {json.dumps(data)}\n\n".encode())
        mcp_app.set_send_callback(send_event)
        try:
            await request.app["mcp_event"].wait()
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        return response

    app = web.Application()
    app["mcp_event"] = asyncio.Event()
    app.router.add_post("/mcp", handle_post)
    app.router.add_get("/mcp/events", handle_sse_endpoint)

    logger.info(f"MCP SSE server listening on http://{host}:{port}")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    await asyncio.Event().wait()
