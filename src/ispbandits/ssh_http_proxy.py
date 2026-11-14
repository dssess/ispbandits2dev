"""HTTP Custom compatibility relay for the existing OpenSSH daemon.

The legacy NginxBandit client sends an HTTP-looking payload, receives a legacy
101 response, then speaks raw SSH on the same TCP stream. This service consumes
that payload and relays the subsequent stream only to the configured local SSH
backend; it is not a general-purpose CONNECT proxy.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import logging
import socket
from typing import Any

LOG = logging.getLogger("neverbandits.ssh_http_proxy")
LEGACY_SWITCHING_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n\r\n"
)
BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
MAX_HEADER_BYTES = 16 * 1024
INITIAL_READ_TIMEOUT = 8.0
BACKEND_CONNECT_TIMEOUT = 5.0
MAX_CONNECTIONS = 4096
MAX_CONNECTIONS_PER_IP = 200
HTTP_METHODS = (b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ", b"PATCH ")


def _is_http_payload(data: bytes) -> bool:
    upper = data[:MAX_HEADER_BYTES].upper()
    return upper.startswith(HTTP_METHODS) or b"HTTP/" in upper or b"UPGRADE:" in upper


def _could_be_fragmented_http_method(data: bytes) -> bool:
    upper = data.upper()
    return any(method.startswith(upper) for method in HTTP_METHODS if len(upper) < len(method))


class SSHHTTPProxy:
    def __init__(self, target_host: str, target_port: int) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.connections_by_ip: Counter[str] = Counter()
        self.active_connections = 0

    async def handle(self, reader: asyncio.StreamReader, client: asyncio.StreamWriter) -> None:
        peer = client.get_extra_info("peername")
        peer_ip = str(peer[0]) if peer else "unknown"
        backend_reader: asyncio.StreamReader | None = None
        backend: asyncio.StreamWriter | None = None
        counted = False
        try:
            if (self.active_connections >= MAX_CONNECTIONS or
                    self.connections_by_ip[peer_ip] >= MAX_CONNECTIONS_PER_IP):
                LOG.warning("connection limit reached for %s", peer_ip)
                return
            self.active_connections += 1
            self.connections_by_ip[peer_ip] += 1
            counted = True

            try:
                initial = await asyncio.wait_for(reader.read(8192), INITIAL_READ_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not initial:
                return

            request = initial
            while _could_be_fragmented_http_method(request):
                if len(request) >= MAX_HEADER_BYTES:
                    LOG.info("oversized HTTP Custom header from %s", peer_ip)
                    return
                try:
                    more = await asyncio.wait_for(reader.read(8192), INITIAL_READ_TIMEOUT)
                except asyncio.TimeoutError:
                    return
                if not more:
                    return
                request += more

            is_http_payload = _is_http_payload(request)
            remainder = b""
            if is_http_payload:
                while b"\r\n\r\n" not in request:
                    if len(request) >= MAX_HEADER_BYTES:
                        LOG.info("oversized HTTP Custom header from %s", peer_ip)
                        return
                    try:
                        more = await asyncio.wait_for(reader.read(8192), INITIAL_READ_TIMEOUT)
                    except asyncio.TimeoutError:
                        return
                    if not more:
                        return
                    request += more
                header, remainder = request.split(b"\r\n\r\n", 1)
                if len(header) + 4 > MAX_HEADER_BYTES:
                    LOG.info("oversized HTTP Custom header from %s", peer_ip)
                    return

            try:
                backend_reader, backend = await asyncio.wait_for(
                    asyncio.open_connection(self.target_host, self.target_port),
                    BACKEND_CONNECT_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError):
                if is_http_payload:
                    client.write(BAD_GATEWAY)
                    await client.drain()
                LOG.warning("SSH backend unavailable for connection from %s", peer_ip)
                return

            if is_http_payload:
                client.write(LEGACY_SWITCHING_RESPONSE)
                await client.drain()
                if remainder:
                    backend.write(remainder)
                    await backend.drain()
            else:
                backend.write(request)
                await backend.drain()

            assert backend_reader is not None
            await self._relay(reader, client, backend_reader, backend)
        except (ConnectionError, asyncio.CancelledError):
            pass
        except Exception:
            LOG.exception("unexpected relay error for %s", peer_ip)
        finally:
            if counted:
                self.active_connections -= 1
                self.connections_by_ip[peer_ip] -= 1
                if self.connections_by_ip[peer_ip] <= 0:
                    del self.connections_by_ip[peer_ip]
            for writer in (backend, client):
                if writer is not None and not writer.is_closing():
                    writer.close()
            for writer in (backend, client):
                if writer is not None:
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass

    @staticmethod
    async def _copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        while True:
            chunk = await source.read(65536)
            if not chunk:
                return
            destination.write(chunk)
            await destination.drain()

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        client: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend: asyncio.StreamWriter,
    ) -> None:
        pumps = {
            asyncio.create_task(self._copy(reader, backend)),
            asyncio.create_task(self._copy(backend_reader, client)),
        }
        try:
            done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            for task in pumps:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)


def _socket_listener(host: str, port: int, family: int) -> socket.socket:
    address: tuple[Any, ...] = (host, port) if family == socket.AF_INET else (host, port, 0, 0)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
        sock.listen(socket.SOMAXCONN)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


async def serve(host: str, port: int, target_host: str, target_port: int) -> None:
    proxy = SSHHTTPProxy(target_host, target_port)
    sockets: list[socket.socket] = []
    servers: list[asyncio.AbstractServer] = []
    try:
        sockets.append(_socket_listener(host, port, socket.AF_INET))
        try:
            sockets.append(_socket_listener("::", port, socket.AF_INET6))
        except OSError as exc:
            LOG.info("IPv6 listener unavailable on port %d: %s", port, exc)
        for sock in sockets:
            servers.append(await asyncio.start_server(proxy.handle, sock=sock, limit=MAX_HEADER_BYTES + 1))
        LOG.info("HTTP Custom SSH relay listening on port %d; SSH backend %s:%d", port, target_host, target_port)
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers), return_exceptions=True)
        for sock in sockets:
            if sock.fileno() >= 0:
                sock.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Neverbandits HTTP Custom SSH relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 1 <= args.target_port <= 65535:
        parser.error("port values must be in the range 1..65535")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(serve(args.host, args.port, args.target_host, args.target_port))
    except KeyboardInterrupt:
        LOG.info("shutdown requested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
