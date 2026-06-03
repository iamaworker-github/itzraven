import asyncio
import socket
import dns.resolver
from typing import List, Dict, Any, Optional, Tuple
from itzraven.core.logger import get_logger

logger = get_logger()


class NetworkTools:
    """Utility class for network scanning and reconnaissance operations."""

    @staticmethod
    async def scan_ports(target: str, ports: List[int], timeout: float = 3.0,
                         max_concurrent: int = 200) -> List[Dict[str, Any]]:
        """TCP port scan using asyncio.

        Returns list of dicts with 'port', 'state' keys for open ports.
        """
        open_ports: List[Dict[str, Any]] = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _scan_port(port: int) -> Optional[Dict[str, Any]]:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return {"port": port, "state": "open"}
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
                except Exception as e:
                    logger.debug(f"scan_ports: error on port {port}: {e}")
                    return None

        tasks = [_scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r.get("state") == "open":
                open_ports.append(r)

        return open_ports

    @staticmethod
    async def get_banner(host: str, port: int, timeout: float = 5.0) -> str:
        """Grab service banner from an open port."""
        banner = ""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            # Send protocol probes to elicit banner
            probes = [b"\r\n", b"\n", b"HEAD / HTTP/1.0\r\n\r\n", b"GET / HTTP/1.0\r\n\r\n"]
            for probe in probes:
                try:
                    writer.write(probe)
                    await writer.drain()
                except Exception:
                    pass

            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if banner_bytes:
                banner = banner_bytes.decode("utf-8", errors="replace").strip()

            writer.close()
            await writer.wait_closed()

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            logger.debug(f"get_banner: {host}:{port} — {e}")

        return banner

    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> List[str]:
        """Resolve DNS records for a domain.

        Supports A, AAAA, MX, NS, TXT, CNAME, SOA record types.
        """
        results: List[str] = []
        try:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            for rdata in answers:
                results.append(rdata.to_text())
        except dns.resolver.NoAnswer:
            logger.debug(f"dns_lookup: No {record_type} records for {domain}")
        except dns.resolver.NXDOMAIN:
            logger.debug(f"dns_lookup: NXDOMAIN for {domain}")
        except dns.resolver.NoNameservers:
            logger.debug(f"dns_lookup: No nameservers for {domain}")
        except dns.exception.Timeout:
            logger.debug(f"dns_lookup: Timeout resolving {domain}")
        except Exception as e:
            logger.debug(f"dns_lookup: {domain} {record_type} — {e}")

        return results

    @staticmethod
    async def reverse_dns(ip_address: str) -> Optional[str]:
        """Reverse DNS lookup for an IP address."""
        try:
            hostname, _, _ = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyaddr, ip_address
            )
            return hostname
        except (socket.herror, socket.gaierror):
            return None
        except Exception as e:
            logger.debug(f"reverse_dns: {ip_address} — {e}")
            return None

    @staticmethod
    async def whois_lookup(domain: str) -> Optional[str]:
        """Perform WHOIS lookup (basic, requires python-whois)."""
        try:
            import whois
            result = await asyncio.get_event_loop().run_in_executor(
                None, whois.whois, domain
            )
            return str(result)
        except ImportError:
            logger.debug("whois_lookup: python-whois not installed")
            return None
        except Exception as e:
            logger.debug(f"whois_lookup: {domain} — {e}")
            return None
