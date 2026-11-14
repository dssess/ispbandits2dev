from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from ispbandits.ssh_http_proxy import LEGACY_SWITCHING_RESPONSE, SSHHTTPProxy


class SSHHTTPProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = await asyncio.start_server(self.backend_handler, "127.0.0.1", 0)
        self.backend_port = self.backend.sockets[0].getsockname()[1]
        self.proxy = SSHHTTPProxy("127.0.0.1", self.backend_port)
        self.server = await asyncio.start_server(self.proxy.handle, "127.0.0.1", 0)
        self.proxy_port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        self.backend.close()
        await self.server.wait_closed()
        await self.backend.wait_closed()

    async def backend_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        writer.write(b"SSH-2.0-TestOpenSSH\r\n")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), 2)
            if data:
                writer.write(b"ECHO:" + data)
                await writer.drain()
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()

    async def test_http_custom_legacy_payload_receives_101_then_ssh_banner(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(
            b"CONNECT netfin.co.ke:GET HTTP/1.1\r\n"
            b"Host: vpn.example.test:80\r\n\r\n"
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertEqual(LEGACY_SWITCHING_RESPONSE, response)
        banner = await asyncio.wait_for(reader.readline(), 2)
        self.assertEqual(b"SSH-2.0-TestOpenSSH\r\n", banner)
        writer.write(b"client-identification\r\n")
        await writer.drain()
        self.assertEqual(b"ECHO:client-identification\r\n", await asyncio.wait_for(reader.readline(), 2))
        writer.close()
        await writer.wait_closed()

    async def test_http_custom_get_upgrade_payload_receives_101_then_ssh_banner(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: vpn.example.test\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n\r\n"
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertEqual(LEGACY_SWITCHING_RESPONSE, response)
        banner = await asyncio.wait_for(reader.readline(), 2)
        self.assertEqual(b"SSH-2.0-TestOpenSSH\r\n", banner)
        writer.close()
        await writer.wait_closed()

    async def test_fragmented_http_method_is_classified_and_body_is_forwarded(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"G")
        await writer.drain()
        await asyncio.sleep(0.03)
        writer.write(b"ET / HTTP/1.1\r\nHost: vpn.example.test\r\nUpgrade: websocket\r\n"
                     b"Connection: Upgrade\r\n\r\nclient-identification\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertEqual(LEGACY_SWITCHING_RESPONSE, response)
        banner = await asyncio.wait_for(reader.readline(), 2)
        self.assertEqual(b"SSH-2.0-TestOpenSSH\r\n", banner)
        self.assertEqual(b"ECHO:client-identification\r\n", await asyncio.wait_for(reader.readline(), 2))
        writer.close()
        await writer.wait_closed()

    async def test_plain_ssh_client_bytes_are_forwarded_without_http_response(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"SSH-2.0-TestClient\r\n")
        await writer.drain()
        self.assertEqual(b"SSH-2.0-TestOpenSSH\r\n", await asyncio.wait_for(reader.readline(), 2))
        self.assertEqual(b"ECHO:SSH-2.0-TestClient\r\n", await asyncio.wait_for(reader.readline(), 2))
        writer.close()
        await writer.wait_closed()

    def test_systemd_unit_is_restricted_and_targets_loopback_sshd(self):
        unit = (Path(__file__).resolve().parents[1] / "systemd" /
                "neverbandits-ssh-http.service.in").read_text(encoding="utf-8")
        self.assertIn("User=ispbd-ws", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("--target-host 127.0.0.1", unit)
        self.assertIn("--port 80", unit)


if __name__ == "__main__":
    unittest.main()
