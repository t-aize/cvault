"""Black-box TCP tests against the real event loop; no third-party packages.

Two programs are exercised over real sockets:

* the *network fixture* (``--fixture``), a server with a few test commands and
  short timeouts, used to probe framing, limits, back-pressure and shutdown;
* the production ``cvault-server`` (``--server``), used to check its CLI and the
  probe-only behaviour it has without a security policy.

Every test runs once per selected readiness backend (``poll`` or ``epoll``).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import os
import queue
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest


# Protocol limits, mirroring include/cvault/config.h.
MAX_LINE = 256 + 65536 + 32
MAX_RESPONSE = 65536 + 128

# Command-line arguments, filled in by the ``__main__`` block below.
ARGS = None


class Server:
    """A server process (fixture or production) started on an ephemeral port."""

    def __init__(self, fixture=True, extra=()):
        """Start the process and wait for its ``Listening on ...`` readiness line."""
        self.fixture = fixture

        executable = ARGS.fixture if fixture else ARGS.server
        arguments = [ARGS.backend] if fixture else ["--port", "0", "--backend", ARGS.backend]

        self.errors = tempfile.TemporaryFile(mode="w+b")
        self.process = subprocess.Popen(
            [executable, *arguments, *extra], stdout=subprocess.PIPE, stderr=self.errors
        )

        # Read the readiness line on a thread so that a hung server times out.
        lines = queue.Queue()

        threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()

        try:
            line = lines.get(timeout=10)
            match = re.search(rb"Listening on .*:(\d+) \(([^)]+)\)", line)

            if not match:
                raise AssertionError(f"Missing readiness line: {line!r}")

            self.port = int(match[1])
            self.backend = match[2].decode()
        except BaseException:
            self.close()
            raise

    def connect(self, address="127.0.0.1"):
        """Open a TCP connection to the server."""
        return socket.create_connection((address, self.port), timeout=3)

    def close(self):
        """Stop the process and fail if a sanitizer reported a problem."""
        # Exercise destruction after every fixture test so leak detection can run.
        if self.fixture and hasattr(self, "port") and self.process.poll() is None:
            try:
                with self.connect() as control:
                    control.sendall(b"STOP\n")
                    read_to_close(control)

                self.process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass

        if self.process.poll() is None:
            self.process.terminate()

            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

        if self.process.stdout:
            self.process.stdout.close()

        self.errors.seek(0)

        diagnostics = self.errors.read().decode(errors="replace")

        self.errors.close()

        if "AddressSanitizer" in diagnostics or "runtime error:" in diagnostics:
            raise AssertionError(diagnostics)


def read_exact(connection, size):
    """Read exactly ``size`` bytes, failing the test on early EOF."""
    result = bytearray()

    while len(result) < size:
        chunk = connection.recv(size - len(result))

        if not chunk:
            raise AssertionError(f"Premature EOF: {len(result)} / {size}")

        result.extend(chunk)

    return bytes(result)


def read_to_close(connection):
    """Read until the peer closes (or resets) the connection."""
    result = bytearray()

    while True:
        try:
            chunk = connection.recv(65536)
        except ConnectionResetError:
            break

        if not chunk:
            break

        result.extend(chunk)

    return bytes(result)


class NetworkTests(unittest.TestCase):
    """Transport behaviour observed from the outside."""

    def setUp(self):
        """Start a fresh fixture server for every test."""
        self.server = Server()
        self.addCleanup(self.server.close)

    def test_backend_selection(self):
        """The requested backend is the one actually in use."""
        expected = "epoll" if ARGS.backend == "epoll" else ("WSAPoll" if os.name == "nt" else "poll")

        self.assertEqual(self.server.backend, expected)

    def test_fragmented_and_pipelined_frames(self):
        """Requests split across packets or sent back to back are framed correctly."""
        with self.server.connect() as connection:
            for fragment in (b"EC", b"HO hel", b"lo\nPING\nECHO world\n"):
                connection.sendall(fragment)

            self.assertEqual(read_exact(connection, 18), b"hello\n+PONG\nworld\n")

            connection.sendall(b"ZERO\n" * 100 + b"PING\n")

            self.assertEqual(read_exact(connection, 6), b"+PONG\n")

    def test_multiple_clients_and_slot_reuse(self):
        """Concurrent clients get distinct IDs and freed slots are reusable."""
        with contextlib.ExitStack() as stack:
            clients = [stack.enter_context(self.server.connect()) for _ in range(4)]
            ids = []

            for client in clients:
                client.sendall(b"ID\n")

                with client.makefile("rb") as reader:
                    ids.append(int(reader.readline()))

            self.assertEqual(len(set(ids)), 4)

            def exchange(client):
                for _ in range(100):
                    client.sendall(b"PING\n")
                    self.assertEqual(read_exact(client, 6), b"+PONG\n")

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(exchange, clients))

        for _ in range(40):
            with self.server.connect() as client:
                client.sendall(b"CLOSE\n")

                self.assertEqual(read_to_close(client), b"+OK\n")

    def test_limit_and_recovery(self):
        """The fifth client is refused, and a slot opens up again after a close."""
        with contextlib.ExitStack() as stack:
            clients = [stack.enter_context(self.server.connect()) for _ in range(4)]

            for client in clients:
                client.sendall(b"PING\n")

                self.assertEqual(read_exact(client, 6), b"+PONG\n")

            with self.server.connect() as extra:
                self.assertEqual(read_to_close(extra), b"")

            clients[0].sendall(b"CLOSE\n")

            self.assertEqual(read_to_close(clients[0]), b"+OK\n")

            with self.server.connect() as replacement:
                replacement.sendall(b"PING\n")

                self.assertEqual(read_exact(replacement, 6), b"+PONG\n")

    def test_large_and_invalid_frames(self):
        """The largest legal frame works; oversized frames and NUL bytes are refused."""
        with self.server.connect() as connection:
            connection.sendall(b"A" * (MAX_LINE - 1) + b"\n")

            self.assertEqual(read_exact(connection, 13), b"-ERR unknown\n")

            connection.sendall(b"PING\n")

            self.assertEqual(read_exact(connection, 6), b"+PONG\n")

        for frame, error in ((b"A" * MAX_LINE, b"-ERR frame too large\n"),
                             (b"PI\x00NG\n", b"-ERR invalid frame\n")):
            with self.server.connect() as connection:
                connection.sendall(frame)

                self.assertEqual(read_to_close(connection), error)

    def test_half_close_preserves_responses(self):
        """A client that shuts down its write side still receives every reply."""
        with self.server.connect() as connection:
            connection.sendall(b"PING\n" * 200)
            connection.shutdown(socket.SHUT_WR)

            self.assertEqual(read_to_close(connection), b"+PONG\n" * 200)

        with self.server.connect() as connection:
            connection.sendall(b"PING\npartial")
            connection.shutdown(socket.SHUT_WR)

            self.assertEqual(read_to_close(connection), b"+PONG\n-ERR incomplete frame\n")

    def test_partial_writes_and_slow_reader_isolation(self):
        """Large replies survive partial sends, and a slow reader cannot block others."""
        with self.server.connect() as connection:
            connection.sendall(b"BIG\n" * 8)

            expected = b"B" * (MAX_RESPONSE - 1) + b"\n"

            for _ in range(8):
                self.assertEqual(read_exact(connection, MAX_RESPONSE), expected)

        with self.server.connect() as slow:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow.sendall(b"BIG\n" * 512)

            with self.server.connect() as normal:
                for _ in range(20):
                    normal.sendall(b"PING\n")

                    self.assertEqual(read_exact(normal, 6), b"+PONG\n")

        with self.server.connect() as normal:
            normal.sendall(b"PING\n")

            self.assertEqual(read_exact(normal, 6), b"+PONG\n")

    def test_timeouts(self):
        """An unfinished frame and an idle connection are both closed."""
        with self.server.connect() as partial:
            partial.sendall(b"P")

            started = time.monotonic()

            self.assertEqual(read_to_close(partial), b"")
            self.assertGreaterEqual(time.monotonic() - started, 0.35)

        with self.server.connect() as idle:
            self.assertEqual(read_to_close(idle), b"")

    def test_trickling_does_not_extend_frame_deadline(self):
        """Sending one byte at a time (slowloris) does not postpone the frame deadline."""
        with self.server.connect() as partial:
            started = time.monotonic()

            for byte in (b"P", b"I", b"N"):
                partial.sendall(byte)
                time.sleep(0.10)

            self.assertEqual(read_to_close(partial), b"")
            self.assertLess(time.monotonic() - started, 1.1)

    def test_callback_failures_are_isolated(self):
        """A failing handler closes only its own connection."""
        for request in (b"BAD\n", b"OVERSIZE\n"):
            with self.server.connect() as client:
                client.sendall(request)

                self.assertEqual(read_to_close(client), b"-ERR handler failed\n")

        with self.server.connect() as client:
            client.sendall(b"PING\n")

            self.assertEqual(read_exact(client, 6), b"+PONG\n")

    def test_reset_does_not_terminate_server(self):
        """A connection reset with queued output must not take the server down."""
        # A disconnected peer may still have queued output; send errors stay local.
        with self.server.connect() as reset:
            reset.sendall(b"BIG\n" * 20)

            import struct

            linger = struct.pack("hh" if os.name == "nt" else "ii", 1, 0)

            reset.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)

        with self.server.connect() as normal:
            normal.sendall(b"PING\n")

            self.assertEqual(read_exact(normal, 6), b"+PONG\n")

    def test_graceful_shutdown_drains_and_is_bounded(self):
        """Shutdown finishes within its deadline even if a client refuses to read."""
        with self.server.connect() as slow:
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow.sendall(b"BIG\n" * 512)

            with self.server.connect() as control:
                control.sendall(b"STOP\n")

                self.assertEqual(read_to_close(control), b"+OK\n")
                self.assertEqual(self.server.process.wait(timeout=3), 0)

    def test_production_probes_and_disabled_commands(self):
        """Without a security policy the real server answers only PING and QUIT."""
        real = Server(fixture=False)
        self.addCleanup(real.close)

        with real.connect() as client:
            client.sendall(b"PING\r\nSET key secret\nAUTH password\nQUIT\n")

            self.assertEqual(read_to_close(client), b"+PONG\n" +
                b"-ERR command dispatch not implemented\n" * 2 + b"+OK\n")

        if os.name != "nt":
            real.process.send_signal(signal.SIGTERM)

            self.assertEqual(real.process.wait(timeout=3), 0)

    def test_cli_rejects_invalid_arguments(self):
        """Invalid command-line options make the server exit with status 1."""
        for arguments in (["--port", "-1"], ["--port", "65536"], ["--port", "1x"],
                          ["--max-clients", "0"], ["--max-clients", "1025"],
                          ["--idle-timeout-ms", "0"], ["--backend", "bad"], ["--port"],
                          ["--unknown", "1"], ["--bind", "localhost"]):
            result = subprocess.run([ARGS.server, *arguments], capture_output=True, timeout=5)

            self.assertEqual(result.returncode, 1, arguments)

        if os.name == "nt":
            result = subprocess.run([ARGS.server, "--backend", "epoll"], capture_output=True, timeout=5)

            self.assertEqual(result.returncode, 1)

    def test_cli_help_version_and_option_combinations(self):
        """--help and --version succeed; maintenance commands refuse to mix with other options."""
        result = subprocess.run([ARGS.server, "--help"], capture_output=True, timeout=5)

        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Usage: cvault-server", result.stdout)
        self.assertIn(b"--dump-audit", result.stdout)
        self.assertIn(b"TCP transport", result.stdout)

        result = subprocess.run([ARGS.server, "--version"], capture_output=True, timeout=5)

        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith(b"cvault-server "))

        for arguments in (["--version", "--port", "0"], ["--version", "--hash-password"],
                          ["--generate-key", "unused.key", "--port", "0"], ["--no-version"],
                          ["--dump-audit", "unused.bin"], ["stray"]):
            result = subprocess.run([ARGS.server, *arguments], capture_output=True, timeout=5)

            self.assertEqual(result.returncode, 1, arguments)
            self.assertNotIn(b"Listening", result.stdout)

    def test_cli_accepts_equals_syntax(self):
        """Options may be written as --name=value as well as --name value."""
        real = Server(fixture=False, extra=("--max-clients=2", "--idle-timeout-ms=5000"))
        self.addCleanup(real.close)

        with real.connect() as client:
            client.sendall(b"PING\nQUIT\n")

            self.assertEqual(read_to_close(client), b"+PONG\n+OK\n")

    def test_ipv6_loopback(self):
        """The server can bind to and serve the IPv6 loopback address."""
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable on this host")

        real = Server(fixture=False, extra=("--bind", "::1"))
        self.addCleanup(real.close)

        with real.connect("::1") as client:
            client.sendall(b"PING\nQUIT\n")

            self.assertEqual(read_to_close(client), b"+PONG\n+OK\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--backend", choices=("poll", "epoll"), required=True)

    ARGS, remaining = parser.parse_known_args()

    unittest.main(argv=[__file__, *remaining], verbosity=2)
