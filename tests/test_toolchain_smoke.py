#!/usr/bin/env python3
"""Opt-in real tools; run ONLY in a network namespace with loopback up.

SUBENUM_REAL_TOOL_SMOKE=1 python3 -m unittest discover -s tests -p test_toolchain_smoke.py -v
Targets HTTPX 1.12.0, Katana 1.8.0, Nuclei 3.11.1 and PureDNS 2.1.1.
No tool is launched unless explicitly enabled; missing tools then fail tests.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import unittest


MARKER = "subenum-private-smoke-marker"


class HTTPFixture(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def do_GET(self):
        if self.path == "/":
            body = (f"<html><head><title>{MARKER}</title></head>"
                    '<body><script src="/assets/health.js"></script></body></html>').encode()
            content_type = "text/html"
        elif self.path == "/assets/health.js":
            body, content_type = b"/* benign local fixture */", "application/javascript"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class DNSFixture:
    """Private UDP resolver: one positive A record, NXDOMAIN otherwise."""
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.endpoint = "127.0.0.1:" + str(self.socket.getsockname()[1])
        self.stop = threading.Event()
        self.errors = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                ident, flags, count, _, _, _ = struct.unpack("!6H", packet[:12])
                if count != 1:
                    raise ValueError("expected one question")
                offset, labels = 12, []
                while packet[offset]:
                    length = packet[offset]
                    if length >= 64:
                        raise ValueError("compressed question unsupported")
                    offset += 1
                    labels.append(packet[offset:offset + length].decode("ascii"))
                    offset += length
                offset += 1
                qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
                offset += 4
                exists = ".".join(labels).lower() == "good.example.test"
                answer = b""
                if exists and qtype == 1:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, qclass, 60, 4)
                    answer += socket.inet_aton("192.0.2.10")
                header = struct.pack("!6H", ident, 0x8480 | (flags & 0x100)
                                     | (0 if exists else 3), 1, bool(answer), 0, 0)
                self.socket.sendto(header + packet[12:offset] + answer, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.thread.is_alive():
            raise AssertionError("DNS fixture did not stop")
        if self.errors:
            raise AssertionError(self.errors)


@unittest.skipUnless(os.environ.get("SUBENUM_REAL_TOOL_SMOKE") == "1",
                     "set SUBENUM_REAL_TOOL_SMOKE=1 inside isolated network namespace")
class RealToolchainSmoke(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="subenum-real-smoke-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        # Deliberately do not inherit proxy settings, credentials or tool config overrides.
        self.env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8"}
        for key, directory in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                               ("TMPDIR", "tmp")):
            path = self.work / directory
            path.mkdir()
            self.env[key] = str(path)

    def binary(self, name):
        binary = shutil.which(name)
        self.assertIsNotNone(binary, f"opt-in smoke requires installed {name}")
        return binary

    def run_tool(self, name, *args):
        command = [self.binary(name), *map(str, args)]
        with subprocess.Popen(command, cwd=self.work, env=self.env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                self.fail(f"{name} exceeded 45-second smoke deadline")
            finally:
                # Kill descendants too (PureDNS starts massdns), including on assertion failure.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        self.assertEqual(process.returncode, 0, f"{command!r}\n{stdout}\n{stderr}")
        return stdout

    def http_fixture(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive(), "HTTP fixture did not stop")

        self.addCleanup(close)
        return f"http://127.0.0.1:{server.server_port}"

    def dns_fixture(self):
        server = DNSFixture()
        self.addCleanup(server.close)
        resolvers, domains = self.work / "resolvers.txt", self.work / "domains.txt"
        resolvers.write_text(server.endpoint + "\n")
        domains.write_text("good.example.test\nmissing.example.test\n")
        return resolvers, domains

    def test_httpx_title_and_status(self):
        url = self.http_fixture()
        output = self.run_tool("httpx", "-u", url, "-title", "-status-code", "-silent",
                               "-nc", "-duc", "-timeout", "3", "-retries", "0")
        self.assertIn(url, output)
        self.assertIn("[200]", output)
        self.assertIn(MARKER, output)

    def test_katana_discovers_script(self):
        url = self.http_fixture()
        output = self.run_tool("katana", "-u", url, "-d", "2", "-silent", "-nc", "-duc",
                               "-timeout", "3", "-ct", "10s", "-c", "1", "-p", "1")
        self.assertIn(url + "/assets/health.js", output)

    def test_nuclei_local_benign_template(self):
        template = self.work / "smoke.yaml"
        template.write_text(f"""id: subenum-local-smoke
info:
  name: Benign localhost marker
  author: subenum
  severity: info
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers:
      - type: word
        part: body
        words:
          - "{MARKER}"
""")
        output = self.run_tool("nuclei", "-u", self.http_fixture(), "-t", template,
                               "-duc", "-ni", "-silent", "-nc", "-timeout", "3",
                               "-retries", "0", "-c", "1", "-rl", "5")
        self.assertIn("[subenum-local-smoke]", output)

    def test_massdns_private_resolver(self):
        resolvers, domains = self.dns_fixture()
        output = self.work / "massdns.txt"
        self.run_tool("massdns", "--root", "-r", resolvers, "-t", "A", "-o", "S",
                      "-w", output, domains)
        self.assertIn("good.example.test. A 192.0.2.10", output.read_text())
        self.assertNotIn("missing.example.test", output.read_text())

    def test_puredns_private_resolvers(self):
        massdns = self.binary("massdns")
        resolvers, domains = self.dns_fixture()
        output = self.work / "puredns.txt"
        self.run_tool("puredns", "resolve", domains, "--bin", massdns,
                      "--resolvers", resolvers, "--resolvers-trusted", resolvers,
                      "--skip-wildcard-filter", "--rate-limit", "10",
                      "--rate-limit-trusted", "10", "--write", output, "--quiet")
        self.assertEqual(output.read_text().splitlines(), ["good.example.test"])


if __name__ == "__main__":
    unittest.main()
