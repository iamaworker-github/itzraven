"""
Advanced HTTP Proxy for comprehensive security testing
"""

import asyncio
import json
from typing import Optional, Dict, Any, Callable, List, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import aiohttp
from aiohttp import web, ClientSession
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ProxyRequest:
    """Enhanced captured HTTP request with client information"""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    timestamp: datetime
    client_ip: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class ProxyResponse:
    """Enhanced captured HTTP response with timing information"""
    status: int
    headers: Dict[str, str]
    body: Optional[bytes]
    timestamp: datetime
    request_id: Optional[str] = None
    response_time: Optional[float] = None


class AdvancedHTTPProxy:
    """Advanced HTTP proxy for comprehensive security testing"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888, 
                 intercept_requests: bool = True, intercept_responses: bool = True):
        self.host = host
        self.port = port
        self.intercept_requests = intercept_requests
        self.intercept_responses = intercept_responses
        
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None

        # Storage for captured traffic
        self.requests: List[ProxyRequest] = []
        self.responses: List[ProxyResponse] = []
        self.request_count = 0

        # Hooks for request/response modification
        self.request_hooks: List[Callable] = []
        self.response_hooks: List[Callable] = []
        
        # Vulnerability detection hooks
        self.vulnerability_hooks: List[Callable] = []

        # Setup routes
        self.app.router.add_route("*", "/{path:.*}", self.handle_request)

    async def start(self) -> None:
        """Start the proxy server"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        logger.info(f"🛡️ Advanced HTTP Proxy started on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the proxy server"""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        logger.info("🛑 Advanced HTTP Proxy stopped")

    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming proxy request with enhanced capabilities"""
        start_time = asyncio.get_event_loop().time()
        request_id = f"req_{self.request_count}"
        self.request_count += 1
        
        # Capture request with enhanced details
        proxy_req = ProxyRequest(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
            body=await request.read() if request.can_read_body else None,
            timestamp=datetime.now(),
            client_ip=request.remote,
            request_id=request_id
        )
        
        # Store request
        self.requests.append(proxy_req)
        
        # Log request
        logger.info(f"📥 {request.method} {request.url}")
        
        # Apply request hooks
        modified_req = proxy_req
        for hook in self.request_hooks:
            modified_req = await hook(modified_req)

        # Forward request with advanced options
        try:
            async with ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(verify_ssl=False)
            ) as session:
                # Prepare request data
                request_kwargs = {
                    'method': modified_req.method,
                    'url': modified_req.url,
                    'headers': modified_req.headers,
                    'allow_redirects': False
                }
                
                # Add body if present
                if modified_req.body:
                    request_kwargs['data'] = modified_req.body
                
                # Forward request
                async with session.request(**request_kwargs) as response:
                    # Calculate response time
                    response_time = asyncio.get_event_loop().time() - start_time
                    
                    # Capture response with enhanced details
                    response_body = await response.read()
                    proxy_resp = ProxyResponse(
                        status=response.status,
                        headers=dict(response.headers),
                        body=response_body,
                        timestamp=datetime.now(),
                        request_id=request_id,
                        response_time=response_time
                    )
                    
                    # Store response
                    self.responses.append(proxy_resp)
                    
                    # Apply response hooks
                    modified_resp = proxy_resp
                    for hook in self.response_hooks:
                        modified_resp = await hook(modified_resp)
                        
                    # Run vulnerability detection hooks
                    for hook in self.vulnerability_hooks:
                        await hook(modified_req, modified_resp)

                    # Return modified response
                    return web.Response(
                        status=modified_resp.status,
                        headers=modified_resp.headers,
                        body=modified_resp.body
                    )
        except Exception as e:
            logger.error(f"❌ Proxy error: {e}")
            return web.Response(status=502, text=f"Proxy Error: {str(e)}")

    def add_request_hook(self, hook: Callable) -> None:
        """Add a request modification hook"""
        self.request_hooks.append(hook)

    def add_response_hook(self, hook: Callable) -> None:
        """Add a response modification hook"""
        self.response_hooks.append(hook)
        
    def add_vulnerability_hook(self, hook: Callable) -> None:
        """Add a vulnerability detection hook"""
        self.vulnerability_hooks.append(hook)

    def get_captured_requests(self) -> List[ProxyRequest]:
        """Get all captured requests"""
        return self.requests.copy()

    def get_captured_responses(self) -> List[ProxyResponse]:
        """Get all captured responses"""
        return self.responses.copy()
        
    def get_request_response_pairs(self) -> List[Dict[str, Union[ProxyRequest, ProxyResponse]]]:
        """Get matched request/response pairs"""
        pairs = []
        response_map = {resp.request_id: resp for resp in self.responses}
        
        for req in self.requests:
            pair = {
                'request': req,
                'response': response_map.get(req.request_id)
            }
            pairs.append(pair)
            
        return pairs

    def clear_history(self) -> None:
        """Clear captured traffic history"""
        self.requests.clear()
        self.responses.clear()
        self.request_count = 0
        logger.info("🧹 Proxy history cleared")
        
    def export_traffic(self, filepath: str) -> None:
        """Export captured traffic to JSON file"""
        traffic_data = {
            'requests': [asdict(req) for req in self.requests],
            'responses': [asdict(resp) for resp in self.responses]
        }
        
        with open(filepath, 'w') as f:
            json.dump(traffic_data, f, indent=2, default=str)
            
        logger.info(f"💾 Traffic exported to {filepath}")
        
    async def test_for_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Test captured traffic for common vulnerabilities"""
        vulnerabilities = []
        
        # Test for potential XSS in responses
        for resp in self.responses:
            if resp.body and b"<script>" in resp.body:
                vulnerabilities.append({
                    'type': 'potential_xss',
                    'severity': 'high',
                    'description': 'Potential XSS found in response body',
                    'request_id': resp.request_id
                })
                
        # Test for missing security headers
        for resp in self.responses:
            headers = resp.headers
            if 'x-frame-options' not in headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': 'X-Frame-Options header missing',
                    'request_id': resp.request_id
                })
                
        return vulnerabilities