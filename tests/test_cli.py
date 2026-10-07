"""End-to-end tests of ``cvault-cli`` against a real ``cvault-server``.

The client is run as a subprocess in each of its three modes (one command from the
arguments, commands from stdin, and a scripted session) and its output, exit status
and reconnection behaviour are checked against a server started with a security
policy.
"""

import argparse
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import tempfile
import threading
import time
import unittest


# Command-line arguments, filled in by the ``__main__`` block below.
ARGS = None

# Password of the test account; it deliberately contains spaces.
PASSWORD = b"cli test password"


def run_server_tool(*arguments, **kwargs):
    """Run a one-shot maintenance command of the server executable."""
    return subprocess.run([ARGS.server, *map(str, arguments)], capture_output=True, timeout=15, **kwargs)


class Server:
    """A ``cvault-server`` process with one user, ``alice``, who owns the ``app/`` prefix."""

    def __init__(self, root, password_hash, extra=()):
        """Start the server on an ephemeral port and wait until it is listening."""
        policy = root / "security.conf"
        key = root / "audit.key"

        policy.write_bytes(
            f"CVAULT-SECURITY-1\nuser alice {password_hash}\nallow alice rw app/\n".encode())
        policy.chmod(0o600)

        result = run_server_tool("--generate-key", key)

        if result.returncode != 0:
            raise AssertionError(result.stderr)

        self.errors = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            [ARGS.server, "--port", "0", "--security", str(policy), "--audit", str(root / "audit.bin"),
             "--audit-key-file", str(key), *map(str, extra)], stdout=subprocess.PIPE, stderr=self.errors,
            **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}))

        lines = queue.Queue()

        threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()

        try:
            match = re.search(rb"Listening on .*:(\d+)", lines.get(timeout=15))

            if not match:
                raise AssertionError("Missing readiness line")

            self.port = int(match[1])
        except BaseException:
            self.close()
            raise

    def close(self):
        """Stop the server gracefully and fail on a bad exit or sanitizer report."""
        if self.process.poll() is None:
            self.process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)

            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

                raise AssertionError("Server did not stop")

        self.process.stdout.close()
        self.errors.seek(0)

        errors = self.errors.read()

        self.errors.close()

        if self.process.returncode != 0 or b"AddressSanitizer" in errors or b"runtime error:" in errors:
            raise AssertionError(f"Server exit {self.process.returncode}: {errors!r}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Cli(unittest.TestCase):
    """Behaviour of the command-line client."""

    @classmethod
    def setUpClass(cls):
        """Hash the shared test password once (Argon2id is deliberately slow)."""
        result = run_server_tool("--hash-password", input=PASSWORD + b"\n")

        if result.returncode != 0:
            raise AssertionError(result.stderr)

        cls.hash = result.stdout.decode().strip()

    def setUp(self):
        """Create a private directory holding a password file."""
        self.temp = tempfile.TemporaryDirectory(prefix="cvault-cli-")
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.password_file = self.root / "alice.pw"

        self.password_file.write_bytes(PASSWORD + b"\n")
        self.password_file.chmod(0o600)

    def server(self, *extra):
        """Start a server for this test."""
        return Server(self.root, self.hash, extra)

    def cli(self, server, *arguments, user=True, **kwargs):
        """Run the client against a server; returns the completed process.

        The server only verifies a few passwords per second across all clients, so
        runs that authenticate are spaced out instead of relying on the client retry.
        """
        options = ["--port", str(server.port)]

        if user:
            time.sleep(0.3)
            options += ["--user", "alice", "--password-file", str(self.password_file)]

        result = subprocess.run([ARGS.cli, *options, *map(str, arguments)], capture_output=True, timeout=30, **kwargs)

        if b"AddressSanitizer" in result.stderr or b"runtime error:" in result.stderr:
            raise AssertionError(result.stderr.decode(errors="replace"))

        return result

    def test_version_and_help(self):
        """--version prints the version; --help describes the client."""
        version = subprocess.run([ARGS.cli, "--version"], capture_output=True, timeout=10)
        helptext = subprocess.run([ARGS.cli, "--help"], capture_output=True, timeout=10)

        self.assertEqual(version.returncode, 0)
        self.assertTrue(version.stdout.startswith(b"cvault-cli "))
        self.assertNotIn(b"scaffold", version.stdout)
        self.assertIn(b"Command-line client", helptext.stdout)

    def test_single_commands(self):
        """SET, GET, TTL, EXPIRE and DEL work, values keep their spaces and nil is reported."""
        with self.server() as server:
            self.assertEqual(self.cli(server, "SET", "app/title", "a value  with   spaces").stdout, b"OK\n")
            self.assertEqual(self.cli(server, "GET", "app/title").stdout, b"a value  with   spaces\n")
            self.assertEqual(self.cli(server, "TTL", "app/title").stdout, b"-1\n")
            self.assertEqual(self.cli(server, "EXPIRE", "app/title", "100").stdout, b"OK\n")
            self.assertIn(int(self.cli(server, "TTL", "app/title").stdout), range(60, 101))
            self.assertEqual(self.cli(server, "DEL", "app/title").stdout, b"OK\n")

            missing = self.cli(server, "GET", "app/title")

            self.assertEqual(missing.returncode, 0)
            self.assertEqual(missing.stdout, b"(nil)\n")

    def test_command_word_case_and_ping_without_login(self):
        """The command word is upper-cased for the user; PING needs no login."""
        with self.server() as server:
            self.assertEqual(self.cli(server, "set", "app/k", "v").stdout, b"OK\n")
            self.assertEqual(self.cli(server, "get", "app/k").stdout, b"v\n")

            ping = self.cli(server, "ping", user=False)

            self.assertEqual(ping.returncode, 0)
            self.assertEqual(ping.stdout, b"PONG\n")

    def test_server_errors_set_the_exit_status(self):
        """An access-denied or malformed command prints an error on stderr and exits 1."""
        with self.server() as server:
            denied = self.cli(server, "GET", "other/key")

            self.assertEqual(denied.returncode, 1)
            self.assertEqual(denied.stdout, b"")
            self.assertIn(b"(error)", denied.stderr)

            self.assertEqual(self.cli(server, "NOPE").returncode, 1)
            self.assertEqual(self.cli(server, "GET", user=False).returncode, 1)

    def test_authentication_failure(self):
        """A wrong password and an unknown user both fail with exit status 1."""
        with self.server() as server:
            wrong = self.root / "wrong.pw"

            wrong.write_bytes(b"not the password\n")
            wrong.chmod(0o600)

            time.sleep(0.3)

            result = subprocess.run([ARGS.cli, "--port", str(server.port), "--user", "alice",
                                     "--password-file", str(wrong), "PING"], capture_output=True, timeout=30)

            self.assertEqual(result.returncode, 1)
            self.assertIn(b"authentication failed", result.stderr)
            self.assertEqual(result.stdout, b"")

            time.sleep(0.3)

            result = subprocess.run([ARGS.cli, "--port", str(server.port), "--user", "nobody",
                                     "--password-file", str(self.password_file), "PING"],
                                    capture_output=True, timeout=30)

            self.assertEqual(result.returncode, 1)
            self.assertIn(b"authentication failed", result.stderr)

    def test_back_to_back_logins_survive_the_verification_gate(self):
        """Two runs started immediately one after the other both authenticate."""
        with self.server() as server:
            for _ in range(3):
                result = subprocess.run(
                    [ARGS.cli, "--port", str(server.port), "--user", "alice",
                     "--password-file", str(self.password_file), "SET", "app/gate", "1"],
                    capture_output=True, timeout=30)

                self.assertEqual(result.returncode, 0, result.stderr)

    def test_password_from_stdin(self):
        """Without --password-file the first stdin line is the password; the rest are commands."""
        with self.server() as server:
            time.sleep(0.3)

            script = PASSWORD + b"\nSET app/stdin from stdin\nGET app/stdin\n"
            result = subprocess.run([ARGS.cli, "--port", str(server.port), "--user", "alice"],
                                    input=script, capture_output=True, timeout=30)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"OK\nfrom stdin\n")

    def test_stdin_script_mode(self):
        """Commands read from stdin run in order; a failing one makes the exit status 1."""
        with self.server() as server:
            ok = self.cli(server, input=b"SET app/a 1\n\nSET app/b 2\nGET app/a\nGET app/b\n")

            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout, b"OK\nOK\n1\n2\n")

            mixed = self.cli(server, input=b"GET app/a\nGET forbidden\nGET app/b\n")

            self.assertEqual(mixed.returncode, 1)
            self.assertEqual(mixed.stdout, b"1\n2\n")
            self.assertIn(b"(error)", mixed.stderr)

    def test_export_follows_every_page(self):
        """EXPORT prints all entries, even when the server splits them over several pages."""
        with self.server() as server:
            big = b"x" * 60000
            names = [f"app/big/{index}" for index in range(6)]
            script = b"".join(b"SET " + name.encode() + b" " + big + b"\n" for name in names)

            self.assertEqual(self.cli(server, input=script).returncode, 0)
            self.assertEqual(self.cli(server, "SET", "app/other", "v").returncode, 0)
            self.assertEqual(self.cli(server, "EXPIRE", "app/big/0", "500").returncode, 0)

            result = self.cli(server, "EXPORT", "app/big/")

            self.assertEqual(result.returncode, 0, result.stderr)

            lines = result.stdout.split(b"\n")[:-1]

            self.assertEqual(len(lines), 6)
            self.assertEqual([line.split(b"\t")[0] for line in lines], [name.encode() for name in names])
            self.assertTrue(all(line.endswith(b"\t" + big) for line in lines))
            self.assertIn(int(lines[0].split(b"\t")[1]), range(400, 501))
            self.assertEqual(lines[1].split(b"\t")[1], b"-1")

    def test_purge_reports_the_count(self):
        """PURGE prints how many entries were erased."""
        with self.server() as server:
            self.assertEqual(self.cli(server, input=b"SET app/p/1 a\nSET app/p/2 b\n").returncode, 0)
            self.assertEqual(self.cli(server, "PURGE", "app/p/").stdout, b"2\n")
            self.assertEqual(self.cli(server, "GET", "app/p/1").stdout, b"(nil)\n")

    def test_reconnects_after_the_server_drops_an_idle_connection(self):
        """A connection closed by the idle timeout is re-established and re-authenticated."""
        with self.server("--idle-timeout-ms", "700") as server:
            time.sleep(0.3)

            process = subprocess.Popen(
                [ARGS.cli, "--port", str(server.port), "--user", "alice", "--password-file",
                 str(self.password_file)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            try:
                process.stdin.write(b"SET app/idle kept\n")
                process.stdin.flush()

                time.sleep(1.5)

                stdout, stderr = process.communicate(input=b"GET app/idle\n", timeout=30)
            finally:
                process.kill()
                process.wait()

            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, b"OK\nkept\n")
            self.assertIn(b"(reconnected)", stderr)

    def test_connection_failure(self):
        """An unreachable server gives a clear message and exit status 1."""
        with self.server() as server:
            port = server.port

        result = subprocess.run([ARGS.cli, "--port", str(port), "--timeout-ms", "2000", "PING"],
                                capture_output=True, timeout=30)

        self.assertEqual(result.returncode, 1)
        self.assertIn(b"cannot connect", result.stderr)

    def test_invalid_options(self):
        """Out-of-range numbers, a missing user and unknown options are rejected."""
        for arguments in (["--port", "0", "PING"], ["--port", "70000", "PING"], ["--port", "x", "PING"],
                          ["--timeout-ms", "0", "PING"], ["--password-file", "x", "PING"],
                          ["--user", "bad user", "PING"], ["--unknown"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([ARGS.cli, *arguments], capture_output=True, timeout=10)

                self.assertEqual(result.returncode, 1)

    @unittest.skipIf(os.name == "nt", "needs a POSIX pseudo-terminal")
    def test_interactive_prompt_hides_the_password(self):
        """On a terminal the client prompts, never echoes the password and runs commands."""
        import pty
        import select

        transcript = bytearray()
        pending = bytearray()

        def read_until(descriptor, marker):
            """Read terminal output until the marker appears; keep everything for later checks."""
            deadline = time.monotonic() + 15

            while marker not in pending and time.monotonic() < deadline:
                if select.select([descriptor], [], [], 0.2)[0]:
                    data = os.read(descriptor, 4096)

                    pending.extend(data)
                    transcript.extend(data)

            self.assertIn(marker, pending, bytes(transcript))

            del pending[:pending.index(marker) + len(marker)]

        with self.server() as server:
            time.sleep(0.3)

            master, slave = pty.openpty()
            process = subprocess.Popen([ARGS.cli, "--port", str(server.port), "--user", "alice"],
                                       stdin=slave, stdout=slave, stderr=slave)

            os.close(slave)

            try:
                read_until(master, b"Password: ")
                os.write(master, PASSWORD + b"\n")
                read_until(master, b"cvault> ")

                os.write(master, b"help\n")
                read_until(master, b"EXPORT <prefix>")
                read_until(master, b"cvault> ")

                os.write(master, b"set app/tty typed value\n")
                read_until(master, b"OK\r\n")
                read_until(master, b"cvault> ")

                os.write(master, b"get app/tty\n")
                read_until(master, b"typed value\r\n")
                read_until(master, b"cvault> ")

                os.write(master, b"exit\n")

                self.assertEqual(process.wait(timeout=15), 0)
                self.assertNotIn(PASSWORD, bytes(transcript))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

                os.close(master)

    @unittest.skipIf(os.name == "nt", "POSIX owner/mode validation")
    def test_password_file_must_be_private(self):
        """A group- or world-readable password file is refused."""
        with self.server() as server:
            self.password_file.chmod(0o644)

            result = self.cli(server, "PING")

            self.assertEqual(result.returncode, 1)
            self.assertIn(b"password file", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--cli", required=True)

    ARGS, remaining = parser.parse_known_args()

    unittest.main(argv=[__file__, *remaining])
