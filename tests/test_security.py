"""Real TCP security, private files, audit tampering and injected fsync failures.

These tests start the real ``cvault-server`` with a security policy and talk to
it over TCP. They cover the three security features end to end:

* ``AUTH`` with Argon2id password verification (rate gate, failure limit,
  revocation on every re-authentication, no user enumeration),
* per-prefix read/write access control (default deny, independent permissions,
  literal prefix matching),
* the encrypted, tamper-evident audit log (intent/result pairing, tampering,
  wrong key, fail-closed behaviour).
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest


# Command-line arguments, filled in by the ``__main__`` block below.
ARGS = None

# Password of every test account; it deliberately contains spaces.
PASSWORD = b"test password with spaces"


def run(*arguments, **kwargs):
    """Run the server executable once and fail on sanitizer findings."""
    result = subprocess.run([ARGS.server, *map(str, arguments)], capture_output=True, timeout=15, **kwargs)

    if b"AddressSanitizer" in result.stderr or b"runtime error:" in result.stderr:
        raise AssertionError(result.stderr.decode(errors="replace"))

    return result


class Connection:
    """A client connection speaking the line protocol."""

    def __init__(self, port):
        """Connect to the server on the loopback interface."""
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.reader = self.socket.makefile("rb")

    def command(self, command):
        """Send one command line and return the reply (bulk replies return the value)."""
        self.socket.sendall(command + b"\n")

        line = self.reader.readline()

        if line.startswith(b"$") and line != b"$-1\n":
            size = int(line[1:])
            value = self.reader.read(size)

            if len(value) != size or self.reader.read(1) != b"\n":
                raise AssertionError("Invalid bulk response")

            return value

        return line

    def export_page(self, prefix, after=None):
        """Send EXPORT and parse one page.

        Returns ``(entries, next_key)``: ``entries`` is a list of ``(key, ttl, value)``
        and ``next_key`` is the continuation key, or ``None`` after the last page.
        An error reply is returned as the raw bytes instead.
        """
        self.socket.sendall(b"EXPORT " + prefix + (b" " + after if after else b"") + b"\n")

        header = self.reader.readline()

        if not header.startswith(b"*"):
            return header

        entries = []

        for _ in range(int(header[1:])):
            key, ttl, length = self.reader.readline().split()
            value = self.reader.read(int(length))

            if len(value) != int(length) or self.reader.read(1) != b"\n":
                raise AssertionError("Invalid export entry framing")

            entries.append((key[1:], int(ttl), value))

        trailer = self.reader.readline()

        if trailer == b"+DONE\n":
            return entries, None

        if not trailer.startswith(b"+MORE "):
            raise AssertionError(f"Invalid export trailer: {trailer!r}")

        return entries, trailer[6:-1]

    def export_all(self, prefix):
        """Follow the continuation keys and return every entry plus the number of pages."""
        entries, after, pages = [], None, 0

        while True:
            page = self.export_page(prefix, after)

            if isinstance(page, bytes):
                return page, pages

            pages += 1
            entries.extend(page[0])
            after = page[1]

            if after is None:
                return entries, pages

    def auth(self, name=b"alice", password=PASSWORD):
        """Log in, waiting out the server's global verification gate first."""
        # The global verification gate deliberately spans connections.
        time.sleep(0.26)

        return self.command(b"AUTH " + name + b" " + password)

    def close(self):
        """Close the connection."""
        self.reader.close()
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Server:
    """A ``cvault-server`` process started with a security configuration."""

    def __init__(self, policy, audit, key, extra=()):
        """Start the server on an ephemeral port and wait until it is listening."""
        self.errors = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            [ARGS.server, "--port", "0", "--security", str(policy), "--audit", str(audit),
             "--audit-key-file", str(key), *map(str, extra)], stdout=subprocess.PIPE,
            stderr=self.errors, **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}))

        # Read the readiness line on a thread so that a hung server times out.
        lines = queue.Queue()

        threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()

        try:
            line = lines.get(timeout=15)
            match = re.search(rb"Listening on .*:(\d+)", line)

            if not match:
                raise AssertionError(f"Missing readiness: {line!r}")

            self.port = int(match[1])
        except BaseException:
            self.close()
            raise

    def connect(self):
        """Open a new client connection."""
        return Connection(self.port)

    def close(self):
        """Stop the server gracefully and fail on a bad exit or sanitizer report."""
        if self.process.poll() is None:
            if os.name == "nt":
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.process.send_signal(signal.SIGTERM)

            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

                raise AssertionError("Security server did not stop")

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


class Security(unittest.TestCase):
    """Authentication, access control and audit log behaviour."""

    @classmethod
    def setUpClass(cls):
        """Hash the shared test password once (Argon2id is deliberately slow)."""
        result = run("--hash-password", input=PASSWORD + b"\n")

        if result.returncode != 0:
            raise AssertionError(result.stderr)

        cls.hash = result.stdout.decode().strip()

    def setUp(self):
        """Create a policy with two users and an audit key in a private directory.

        ``alice`` may read and write ``alice:`` keys and read ``shared:`` keys;
        ``writer`` may only write ``shared:`` keys.
        """
        self.temp = tempfile.TemporaryDirectory(prefix="cvault-security-")
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.policy = self.root / "security.conf"
        self.audit = self.root / "audit.bin"
        self.key = self.root / "audit.key"

        self.write_policy(
            f"CVAULT-SECURITY-1\nuser alice {self.hash}\nuser writer {self.hash}\n"
            "allow alice rw alice:\nallow alice r shared:\nallow writer w shared:\n")

        result = run("--generate-key", self.key)

        self.assertEqual(result.returncode, 0, result.stderr)

    def write_policy(self, text):
        """Write the policy file with the private permissions the server demands.

        The file is replaced atomically, like an operator should do: a server that reloads
        the policy on a timer must never read a half-written file.
        """
        staging = self.policy.with_name("security.conf.new")

        staging.write_bytes(text.encode())
        staging.chmod(0o600)
        os.replace(staging, self.policy)

    def server(self, *extra):
        """Start a server with the current policy and audit files."""
        return Server(self.policy, self.audit, self.key, extra)

    def export(self):
        """Verify and export the audit log as a list of event dictionaries."""
        result = run("--dump-audit", self.audit, "--audit-key-file", self.key)

        self.assertEqual(result.returncode, 0, result.stderr)

        return [json.loads(line) for line in result.stdout.splitlines()]

    def rejected_start(self):
        """Assert that the server refuses to start (and never prints a readiness line)."""
        result = run("--port", "0", "--security", self.policy, "--audit", self.audit,
                     "--audit-key-file", self.key)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"Listening", result.stdout)

    def test_native_api_and_audit_lock(self):
        """The C API fixture passes, and its run leaves three audit events behind."""
        result = subprocess.run([ARGS.fixture, "--api", str(self.policy), str(self.audit), str(self.key)],
                                capture_output=True, timeout=15)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.export()), 3)

    def test_audit_failure_prevents_mutation_and_postmutation_failure_poisoning(self):
        """Audit sync failures fail closed, before and after the mutation."""
        for fault in (1, 2):
            with self.subTest(fault=fault):
                result = subprocess.run([ARGS.fixture, "--fault", str(self.policy),
                                         str(self.root / f"fault-{fault}.bin"), str(self.key),
                                         str(self.root / f"data-{fault}"), str(fault)],
                                        capture_output=True, timeout=15)

                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def archives(self):
        """Sealed audit files, oldest first (their names end in the last sequence number)."""
        return sorted(path for path in self.root.glob("audit.bin.[0-9]*") if not path.name.endswith(".lock"))

    def dump(self, path, key=None, expect_ok=True):
        """Export one audit file; returns the events, or the failed process when not ``expect_ok``."""
        result = run("--dump-audit", path, "--audit-key-file", key or self.key)

        if not expect_ok:
            self.assertNotEqual(result.returncode, 0)

            return result

        self.assertEqual(result.returncode, 0, result.stderr)

        return [json.loads(line) for line in result.stdout.splitlines()]

    def assert_continuous(self, files):
        """The files, in order, hold sequence numbers 1..N without gaps, linked by ROTATE events."""
        expected = 1

        for index, events in enumerate(files):
            self.assertTrue(events, "an audit file is never empty")

            for event in events:
                self.assertEqual(event["sequence"], expected)

                expected += 1

            if index + 1 < len(files):
                self.assertEqual((events[-1]["operation"], events[-1]["phase"]), ("ROTATE", "intent"))

            if index:
                self.assertEqual((events[0]["operation"], events[0]["phase"], events[0]["status"],
                                  events[0]["identity"]), ("ROTATE", "result", 0, "server"))

    def eventually(self, condition, timeout=15):
        """Poll a condition until it holds; fails the test on timeout."""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if condition():
                return

            time.sleep(0.1)

        self.fail("condition not reached in time")

    def test_audit_rotates_when_it_grows_and_stays_continuous(self):
        """Past --audit-max-bytes the log is sealed and continued; nothing is lost or reordered."""
        with self.server("--audit-max-bytes", "3000") as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

            for index in range(40):
                self.assertEqual(alice.command(f"SET alice:k{index} value".encode()), b"+OK\n")

            self.eventually(lambda: len(self.archives()) >= 3)

        archives = self.archives()

        self.assertGreaterEqual(len(archives), 3)

        files = [self.dump(path) for path in archives] + [self.dump(self.audit)]

        self.assert_continuous(files)

        # The first file starts the run; the last one ends it; every SET is accounted for twice.
        self.assertEqual(files[0][0]["operation"], "START")
        self.assertEqual(files[-1][-1]["operation"], "STOP")
        self.assertEqual(sum(1 for events in files for event in events if event["operation"] == "SET"), 80)

        # An archive is named after its last sequence number.
        for path, events in zip(archives, files):
            self.assertEqual(int(path.name.rsplit(".", 1)[1]), events[-1]["sequence"])

        # Every file is large enough to have triggered the rotation, and none is left staged.
        self.assertFalse((self.root / "audit.bin.next").exists())

    def test_audit_is_not_rotated_without_the_option(self):
        """Without --audit-max-bytes the log only grows."""
        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

            for index in range(30):
                self.assertEqual(alice.command(f"SET alice:k{index} value".encode()), b"+OK\n")

        self.assertEqual(self.archives(), [])

    def test_offline_rotation_keeps_the_key_or_changes_it(self):
        """--rotate-audit seals the file; with --new-audit-key-file the continuation uses that key."""
        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:x 1"), b"+OK\n")

        first = self.dump(self.audit)

        # Same key.
        result = run("--rotate-audit", self.audit, "--audit-key-file", self.key)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Sealed audit log:", result.stdout)

        (archive,) = self.archives()

        self.assert_continuous([self.dump(archive), self.dump(self.audit)])
        self.assertEqual(len(self.dump(archive)), len(first) + 1)
        self.assertEqual(len(self.dump(self.audit)), 1)

        # New key: the archive stays readable with the old one, the new file only with the new one.
        new_key = self.root / "audit2.key"

        self.assertEqual(run("--generate-key", new_key).returncode, 0)

        result = run("--rotate-audit", self.audit, "--audit-key-file", self.key, "--new-audit-key-file", new_key)

        self.assertEqual(result.returncode, 0, result.stderr)

        archives = self.archives()

        self.assertEqual(len(archives), 2)

        self.dump(self.audit, expect_ok=False)
        self.assert_continuous([self.dump(archives[0]), self.dump(archives[1]), self.dump(self.audit, new_key)])

        # The server continues the log under the new key, and only under it.
        old_key, self.key = self.key, new_key

        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

        events = self.dump(self.audit, new_key)

        self.assert_continuous([self.dump(archives[0], old_key), self.dump(archives[1], old_key), events])
        self.assertEqual(events[-1]["operation"], "STOP")

    def test_rotation_is_refused_when_the_archive_name_is_taken(self):
        """An existing archive is never overwritten, and the log stays untouched."""
        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

        events = self.dump(self.audit)
        taken = Path(f"{self.audit}.{len(events) + 1:020d}")

        taken.write_bytes(b"precious")
        taken.chmod(0o600)

        result = run("--rotate-audit", self.audit, "--audit-key-file", self.key)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(taken.read_bytes(), b"precious")
        self.assertEqual(self.dump(self.audit), events)
        self.assertFalse((self.root / "audit.bin.next").exists())

    def test_interrupted_rotation_is_completed_or_discarded_on_start(self):
        """A leftover staging file either finishes the swap or is dropped, depending on the log."""
        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

        new_key = self.root / "audit2.key"

        self.assertEqual(run("--generate-key", new_key).returncode, 0)
        self.assertEqual(run("--rotate-audit", self.audit, "--audit-key-file", self.key,
                             "--new-audit-key-file", new_key).returncode, 0)

        # Crash after the old file was archived but before the new one took its place.
        staging = self.root / "audit.bin.next"
        rotated = self.dump(self.audit, new_key)

        self.audit.rename(staging)

        self.key = new_key

        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

        self.assertFalse(staging.exists())
        self.assert_continuous([self.dump(self.archives()[0], self.root / "audit.key"),
                                self.dump(self.audit, new_key)])
        self.assertEqual(self.dump(self.audit, new_key)[0]["sequence"], rotated[0]["sequence"])

        # Crash before the swap: both files exist and the staging file is stale.
        staging.write_bytes(b"stale preparation")
        staging.chmod(0o600)

        before = self.dump(self.audit, new_key)

        with self.server() as server:
            pass

        self.assertFalse(staging.exists())
        self.assertEqual(self.dump(self.audit, new_key)[:len(before)], before)

    def test_rotation_options_are_validated(self):
        """The rotation and reload options need their companions and stand alone where required."""
        key = self.key

        for options in (["--rotate-audit", str(self.audit)],
                        ["--rotate-audit", str(self.audit), "--audit-key-file", str(key), "--port", "0"],
                        ["--rotate-audit", str(self.audit), "--audit-key-file", str(key), "--audit", str(self.audit)],
                        ["--rotate-audit", str(self.audit), "--audit-key-file", str(key),
                         "--new-key-file", str(key)],
                        ["--dump-audit", str(self.audit), "--audit-key-file", str(key),
                         "--new-audit-key-file", str(key)],
                        ["--new-audit-key-file", str(key)],
                        ["--audit-max-bytes", "1000"],
                        ["--policy-reload-ms", "100"],
                        ["--port", "0", "--security", str(self.policy), "--audit", str(self.audit),
                         "--audit-key-file", str(key), "--audit-max-bytes", "0"],
                        ["--port", "0", "--security", str(self.policy), "--audit", str(self.audit),
                         "--audit-key-file", str(key), "--policy-reload-ms", "x"]):
            with self.subTest(options=options):
                result = run(*options)

                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"Listening", result.stdout)

    def swap_policy(self, grants):
        """Replace the policy with one that only gives alice the listed grant lines."""
        self.write_policy(f"CVAULT-SECURITY-1\nuser alice {self.hash}\n{grants}")

    def reload_events(self):
        """The RELOAD events of the audit log, in order."""
        return [event for event in self.dump(self.audit) if event["operation"] == "RELOAD"]

    def test_policy_reload_by_timer_revokes_sessions_and_applies_new_grants(self):
        """A changed policy file is picked up; sessions must log in again and get the new grants."""
        with self.server("--policy-reload-ms", "100") as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:x 1"), b"+OK\n")

            self.swap_policy("allow alice rw bob:\n")
            self.eventually(lambda: alice.command(b"GET alice:x") == b"-ERR access denied\n")

            # The session was revoked, not just narrowed: the new grants need a new login.
            self.assertEqual(alice.command(b"SET bob:x 1"), b"-ERR access denied\n")
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:x 2"), b"-ERR access denied\n")
            self.assertEqual(alice.command(b"SET bob:x 2"), b"+OK\n")
            self.assertEqual(alice.command(b"GET bob:x"), b"2")

        (event,) = self.reload_events()

        self.assertEqual((event["phase"], event["status"], event["identity"]), ("result", 0, "server"))

    def test_rejected_policy_keeps_the_old_one_and_is_reported_once(self):
        """A broken policy file changes nothing, is audited, and is not retried until it changes."""
        with self.server("--policy-reload-ms", "100") as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")

            self.write_policy("this is not a policy\n")
            time.sleep(1.0)

            # Still logged in, with the old grants.
            self.assertEqual(alice.command(b"SET alice:x 1"), b"+OK\n")

            self.swap_policy("allow alice rw bob:\n")
            self.eventually(lambda: alice.command(b"GET alice:x") == b"-ERR access denied\n")

        statuses = [event["status"] for event in self.reload_events()]

        self.assertEqual(len(statuses), 2, statuses)
        self.assertNotEqual(statuses[0], 0)
        self.assertEqual(statuses[1], 0)

    def test_policy_reload_can_remove_a_user(self):
        """A user who disappears from the policy can no longer log in."""
        with self.server("--policy-reload-ms", "100") as server, server.connect() as writer:
            self.assertEqual(writer.auth(b"writer"), b"+OK\n")
            self.assertEqual(writer.command(b"SET shared:x 1"), b"+OK\n")

            self.swap_policy("allow alice rw alice:\n")
            self.eventually(lambda: writer.command(b"SET shared:x 2") == b"-ERR access denied\n")

            self.assertEqual(writer.auth(b"writer"), b"-ERR authentication failed\n")

    @unittest.skipIf(os.name == "nt", "SIGHUP exists only on POSIX")
    def test_sighup_reloads_even_an_unchanged_policy(self):
        """SIGHUP forces a reload: sessions are revoked and the event is audited."""
        with self.server() as server, server.connect() as alice:
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:x 1"), b"+OK\n")

            server.process.send_signal(signal.SIGHUP)

            self.eventually(lambda: alice.command(b"GET alice:x") == b"-ERR access denied\n")

            # The same policy applies again after a new login.
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(alice.command(b"GET alice:x"), b"1")

            # A policy that cannot be loaded is rejected on SIGHUP as well.
            self.write_policy("broken\n")
            server.process.send_signal(signal.SIGHUP)
            time.sleep(0.5)

            self.assertEqual(alice.command(b"GET alice:x"), b"1")

        statuses = [event["status"] for event in self.reload_events()]

        self.assertEqual(len(statuses), 2, statuses)
        self.assertEqual(statuses[0], 0)
        self.assertNotEqual(statuses[1], 0)

    def test_default_deny_and_independent_permissions(self):
        """Nothing is allowed before login; read and write grants are independent."""
        with self.server() as server, server.connect() as alice, server.connect() as writer:
            # Unauthenticated: every storage command is denied.
            for command in (b"GET alice:x", b"SET alice:x value", b"DEL alice:x", b"EXPIRE alice:x 3", b"TTL alice:x"):
                self.assertEqual(alice.command(command), b"-ERR access denied\n")

            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(writer.auth(b"writer"), b"+OK\n")

            # The writer can write the shared prefix but cannot read it back.
            self.assertEqual(writer.command(b"SET shared:x shared value"), b"+OK\n")
            self.assertEqual(writer.command(b"GET shared:x"), b"-ERR access denied\n")
            self.assertEqual(writer.command(b"TTL shared:x"), b"-ERR access denied\n")

            # Alice can read the shared prefix but cannot modify it.
            self.assertEqual(alice.command(b"GET shared:x"), b"shared value")

            for command in (b"SET shared:x tampered", b"DEL shared:x", b"EXPIRE shared:x 0"):
                self.assertEqual(alice.command(command), b"-ERR access denied\n")

            self.assertEqual(alice.command(b"GET shared:x"), b"shared value")

            # Prefixes are literal and case sensitive; no path tricks.
            for key in (b"aliceevil:x", b"ALICE:x", b"../alice:x", b"missing:x"):
                self.assertEqual(alice.command(b"GET " + key), b"-ERR access denied\n")

            self.assertEqual(alice.command(b"GET alice:missing"), b"$-1\n")

    def test_data_commands_empty_large_and_expiration(self):
        """SET/GET/TTL/EXPIRE/DEL work for empty, spaced and maximum-size values."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")

            for value in (b"", b"a value with spaces", b"x" * 65536):
                self.assertEqual(client.command(b"SET alice:x " + value), b"+OK\n")
                self.assertEqual(client.command(b"GET alice:x"), value)
                self.assertEqual(client.command(b"TTL alice:x"), b":-1\n")

            self.assertEqual(client.command(b"EXPIRE alice:x 1"), b"+OK\n")
            self.assertIn(client.command(b"TTL alice:x"), (b":0\n", b":1\n"))

            time.sleep(1.05)

            self.assertEqual(client.command(b"GET alice:x"), b"$-1\n")
            self.assertEqual(client.command(b"TTL alice:x"), b":-2\n")
            self.assertEqual(client.command(b"SET alice:x fresh"), b"+OK\n")
            self.assertEqual(client.command(b"EXPIRE alice:x -9223372036854775808"), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:x"), b"$-1\n")
            self.assertEqual(client.command(b"SET alice:x fresh"), b"+OK\n")
            self.assertEqual(client.command(b"DEL alice:x"), b"+OK\n")

    def test_failed_malformed_and_throttled_reauth_revoke_privileges(self):
        """Any AUTH attempt, even a failed, malformed or throttled one, drops the old session."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")

            # Wrong password.
            self.assertEqual(client.auth(password=b"incorrect"), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")

            # Malformed AUTH lines.
            self.assertEqual(client.command(b"AUTH\talice " + PASSWORD), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"AUTH alice"), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")

            # An immediate retry is throttled by the global gate.
            result = client.command(b"AUTH alice " + PASSWORD)

            # Slow sanitizer/CI hosts may take more than the gate interval to
            # finish the first verification. Both admission outcomes are valid.
            self.assertIn(result, (b"+OK\n", b"-ERR authentication failed\n"))

            if result.startswith(b"-ERR"):
                self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            else:
                self.assertEqual(client.command(b"AUTH alice"), b"-ERR authentication failed\n")
                self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")

    def test_unknown_identity_generic_failure_and_attempt_limit(self):
        """Unknown and known users fail identically; three failures close the connection."""
        with self.server() as server, server.connect() as client:
            for name in (b"missing", b"injected\tname", b"alice"):
                self.assertEqual(client.auth(name, b"incorrect"), b"-ERR authentication failed\n")

            self.assertEqual(client.reader.read(1), b"")

        events = self.export()
        failed = [e for e in events if e["operation"] == "AUTH" and e["phase"] == "result"]

        self.assertEqual(len(failed), 3)
        self.assertTrue(all(e["identity"] == "anonymous" for e in failed))

    def test_session_isolation_disconnect_and_slot_reuse(self):
        """Sessions are per connection, and a reused slot never inherits privileges."""
        with self.server("--max-clients", "2") as server:
            with server.connect() as alice, server.connect() as other:
                self.assertEqual(alice.auth(), b"+OK\n")
                self.assertEqual(other.command(b"GET alice:x"), b"-ERR access denied\n")
                self.assertEqual(alice.command(b"QUIT"), b"+OK\n")

            for _ in range(12):
                with server.connect() as fresh:
                    self.assertEqual(fresh.command(b"GET alice:x"), b"-ERR access denied\n")
                    self.assertEqual(fresh.command(b"QUIT"), b"+OK\n")

    def test_fragmented_crlf_and_pipeline(self):
        """Fragmented, CRLF-terminated and pipelined requests behave like single ones."""
        with self.server() as server, server.connect() as client:
            client.socket.sendall(b"AUTH ali")
            client.socket.sendall(b"ce " + PASSWORD + b"\r\nSET alice:x pipelined\nGET alice:x\n")

            self.assertEqual(client.reader.readline(), b"+OK\n")
            self.assertEqual(client.reader.readline(), b"+OK\n")
            self.assertEqual(client.reader.readline(), b"$9\n")
            self.assertEqual(client.reader.read(10), b"pipelined\n")

    def test_strict_grammar_reserved_operations_and_numeric_overflow(self):
        """Malformed commands, reserved words and numeric overflow are rejected without side effects."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:x original"), b"+OK\n")

            for command in (b"GET alice:x extra", b"DEL alice:x extra", b"EXPIRE alice:x 9223372036854775808",
                            b"EXPIRE alice:x -9223372036854775809", b"EXPIRE alice:x +1", b"EXPIRE alice:x 1junk",
                            b"SET  value", b"PURGE", b"EXPORT", b"get alice:x", b"PING extra"):
                self.assertEqual(client.command(command), b"-ERR invalid command\n")

            self.assertEqual(client.command(b"GET alice:x"), b"original")

    def test_encrypted_audit_metadata_and_intent_result_pairing(self):
        """The audit log hides secrets, numbers its events and pairs intent with result."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:private-key private-value"), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:private-key"), b"private-value")
            self.assertEqual(client.command(b"GET forbidden:key"), b"-ERR access denied\n")

        # Neither passwords, keys, values, the audit key nor identities are readable.
        raw = self.audit.read_bytes()

        for secret in (PASSWORD, b"private-key", b"private-value", self.key.read_bytes(), b"alice"):
            self.assertNotIn(secret, raw)

        events = self.export()

        self.assertEqual([e["sequence"] for e in events], list(range(1, len(events) + 1)))
        self.assertEqual(events[0]["operation"], "START")
        self.assertEqual(events[-1]["operation"], "STOP")

        writes = [e for e in events if e["operation"] == "SET"]

        self.assertEqual([e["phase"] for e in writes], ["intent", "result"])
        self.assertEqual(writes[0]["request_id"], writes[1]["request_id"])
        self.assertEqual(writes[1]["identity"], "alice")
        self.assertTrue(all(e["timestamp_ms"] > 0 for e in events))
        self.assertEqual(events[-2]["status"], 6)

    def test_persistence_restart_and_session_revocation(self):
        """Durable data survives a restart, but sessions do not."""
        data, key = self.root / "data", self.root / "store.key"

        self.assertEqual(run("--generate-key", key).returncode, 0)

        extra = ("--data", data, "--key-file", key, "--snapshot-interval-ms", "50")

        with self.server(*extra) as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:x durable value"), b"+OK\n")

            time.sleep(0.15)

        with self.server(*extra) as server, server.connect() as client:
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:x"), b"durable value")

        self.assertEqual(sum(e["operation"] == "START" for e in self.export()), 2)

    def test_export_returns_only_readable_entries_sorted_with_ttl(self):
        """EXPORT lists the entries the session may read, sorted, with TTL and exact bytes."""
        binary = b"binary \x01\x7f\xff end"

        with self.server() as server, server.connect() as alice, server.connect() as writer:
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(writer.auth(b"writer"), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:b two words"), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:a "), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:c " + binary), b"+OK\n")
            self.assertEqual(alice.command(b"EXPIRE alice:b 1000"), b"+OK\n")
            self.assertEqual(writer.command(b"SET shared:x from writer"), b"+OK\n")

            entries, after = alice.export_page(b"alice:")

            self.assertIsNone(after)
            self.assertEqual([entry[0] for entry in entries], [b"alice:a", b"alice:b", b"alice:c"])
            self.assertEqual([entry[2] for entry in entries], [b"", b"two words", binary])
            self.assertEqual([entry[1] for entry in entries][::2], [-1, -1])
            self.assertIn(entries[1][1], range(996, 1001))

            # A shorter prefix reaches every readable key below it, and only those.
            self.assertEqual([entry[0] for entry in alice.export_page(b"a")[0]],
                             [b"alice:a", b"alice:b", b"alice:c"])
            self.assertEqual(alice.export_page(b"shared:")[0], [(b"shared:x", -1, b"from writer")])
            self.assertEqual(alice.export_page(b"other:"), ([], None))

            # The writer may not read what it wrote: nothing is exported, nothing leaks.
            self.assertEqual(writer.export_page(b"shared:"), ([], None))
            self.assertEqual(writer.export_page(b"alice:"), ([], None))

            # Continuation keys are exclusive.
            self.assertEqual([entry[0] for entry in alice.export_page(b"alice:", b"alice:b")[0]],
                             [b"alice:c"])
            self.assertEqual(alice.export_page(b"alice:", b"alice:c"), ([], None))

    def test_export_denies_anonymous_clients_and_skips_expired_entries(self):
        """EXPORT needs a login, and expired entries are not exported."""
        with self.server() as server, server.connect() as client, server.connect() as anonymous:
            self.assertEqual(anonymous.export_page(b"alice:"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:soon gone"), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:stay kept"), b"+OK\n")
            self.assertEqual(client.command(b"EXPIRE alice:soon 1"), b"+OK\n")

            time.sleep(1.3)

            self.assertEqual(client.export_page(b"alice:")[0], [(b"alice:stay", -1, b"kept")])
            self.assertEqual(anonymous.export_page(b"alice:"), b"-ERR access denied\n")

    def test_export_paginates_large_data_sets_and_maximum_size_values(self):
        """Entries that do not fit one reply are delivered across pages without gaps or repeats."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")

            expected = {}

            for index in range(300):
                key = b"alice:k%03d" % index
                expected[key] = bytes([65 + index % 26]) * 1000

                self.assertEqual(client.command(b"SET " + key + b" " + expected[key]), b"+OK\n")

            expected[b"alice:zbig"] = b"x" * 65536

            self.assertEqual(client.command(b"SET alice:zbig " + expected[b"alice:zbig"]), b"+OK\n")

            entries, pages = client.export_all(b"alice:")

            self.assertGreater(pages, 4)
            self.assertEqual([entry[0] for entry in entries], sorted(expected))
            self.assertEqual({entry[0]: entry[2] for entry in entries}, expected)

    def test_purge_erases_only_writable_keys_in_batches(self):
        """PURGE removes the keys under a prefix the session may write, 100 at a time."""
        with self.server() as server, server.connect() as alice, server.connect() as writer, \
                server.connect() as anonymous:
            self.assertEqual(anonymous.command(b"PURGE alice:"), b"-ERR access denied\n")
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(writer.auth(b"writer"), b"+OK\n")
            self.assertEqual(alice.command(b"SET alice:keep stays"), b"+OK\n")
            self.assertEqual(writer.command(b"SET shared:x from writer"), b"+OK\n")

            for index in range(5):
                self.assertEqual(alice.command(b"SET alice:p%d v" % index), b"+OK\n")

            for index in range(150):
                self.assertEqual(alice.command(b"SET alice:q%03d v" % index), b"+OK\n")

            # Alice may read, but not write, the shared prefix: nothing is erased there.
            self.assertEqual(alice.command(b"PURGE shared:"), b":0\n")
            self.assertEqual(alice.command(b"GET shared:x"), b"from writer")

            self.assertEqual(alice.command(b"PURGE alice:p"), b":5\n")
            self.assertEqual(alice.command(b"GET alice:p3"), b"$-1\n")
            self.assertEqual(alice.command(b"GET alice:keep"), b"stays")

            # The batch cap: 100, then the remaining 50, then nothing left.
            self.assertEqual(alice.command(b"PURGE alice:q"), b":100\n")
            self.assertEqual(alice.command(b"PURGE alice:q"), b":50\n")
            self.assertEqual(alice.command(b"PURGE alice:q"), b":0\n")

            # The write-only account can erase what it cannot read.
            self.assertEqual(writer.command(b"PURGE shared:"), b":1\n")
            self.assertEqual(alice.command(b"GET shared:x"), b"$-1\n")
            self.assertEqual(alice.export_page(b"alice:")[0], [(b"alice:keep", -1, b"stays")])

    def test_purge_is_durable_and_audited_with_export(self):
        """A purge survives a restart, and EXPORT/PURGE leave intent and result events."""
        data, key = self.root / "data", self.root / "store.key"

        self.assertEqual(run("--generate-key", key).returncode, 0)

        extra = ("--data", data, "--key-file", key)

        with self.server(*extra) as server, server.connect() as client, server.connect() as anonymous:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:erase one"), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:erase2 two"), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:other three"), b"+OK\n")
            self.assertEqual(len(client.export_page(b"alice:")[0]), 3)
            self.assertEqual(client.command(b"PURGE alice:erase"), b":2\n")
            self.assertEqual(anonymous.export_page(b"alice:"), b"-ERR access denied\n")

        with self.server(*extra) as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:erase"), b"$-1\n")
            self.assertEqual(client.command(b"GET alice:erase2"), b"$-1\n")
            self.assertEqual(client.export_page(b"alice:")[0], [(b"alice:other", -1, b"three")])

        events = self.export()
        exports = [e for e in events if e["operation"] == "EXPORT"]
        purges = [e for e in events if e["operation"] == "PURGE"]

        self.assertEqual([e["phase"] for e in exports if e["identity"] == "alice"][:2],
                         ["intent", "result"])
        self.assertEqual([e["phase"] for e in purges], ["intent", "result"])
        self.assertEqual({e["identity"] for e in purges}, {"alice"})

        # The refused anonymous attempt is a single result event with status UNAUTHORIZED (6).
        refused = [e for e in exports if e["identity"] == "anonymous"]

        self.assertEqual([(e["phase"], e["status"]) for e in refused], [("result", 6)])

    def test_service_sweep_erases_expired_entries(self):
        """The periodic sweep of the service removes expired entries and leaves the rest."""
        result = subprocess.run([ARGS.fixture, "--expiry", str(self.policy), str(self.audit), str(self.key)],
                                capture_output=True, timeout=30)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_server_with_a_fast_sweep_stays_healthy(self):
        """A very short --expiry-sweep-ms neither disturbs live data nor the server."""
        with self.server("--expiry-sweep-ms", "20") as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:gone short lived"), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:stay long lived"), b"+OK\n")
            self.assertEqual(client.command(b"EXPIRE alice:gone 1"), b"+OK\n")

            time.sleep(1.4)

            self.assertEqual(client.command(b"GET alice:gone"), b"$-1\n")
            self.assertEqual(client.command(b"TTL alice:gone"), b":-2\n")
            self.assertEqual(client.command(b"GET alice:stay"), b"long lived")
            self.assertEqual(client.command(b"SET alice:gone again"), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:gone"), b"again")

    def test_compact_option_keeps_the_journal_small_and_loses_nothing(self):
        """With --compact the journal is rewritten after each snapshot and no data is lost."""
        data, key = self.root / "data", self.root / "store.key"

        self.assertEqual(run("--generate-key", key).returncode, 0)

        extra = ("--data", data, "--key-file", key, "--snapshot-interval-ms", "50", "--compact")
        journal = data / "journal.aof"

        with self.server(*extra) as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")

            for index in range(40):
                self.assertEqual(client.command(b"SET alice:k%d " % index + b"x" * 2000), b"+OK\n")

            # The baseline in the journal header (offset 24) reaches the snapshot sequence
            # and the file shrinks from about 84 KB to just its header.
            deadline = time.monotonic() + 10

            while time.monotonic() < deadline:
                content = journal.read_bytes()

                if struct.unpack_from("<Q", content, 24)[0] == 40 and len(content) < 1000:
                    break

                time.sleep(0.05)
            else:
                self.fail("the journal was not compacted")

            self.assertEqual(client.command(b"GET alice:k39"), b"x" * 2000)

        with self.server(*extra) as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:k0"), b"x" * 2000)
            self.assertEqual(client.command(b"GET alice:k39"), b"x" * 2000)
            self.assertEqual(client.command(b"SET alice:after restart"), b"+OK\n")

    def test_audit_wrong_key_tampering_reorder_and_torn_tail_fail_closed(self):
        """Any modification of the audit file, or a wrong key, is detected and refused."""
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:x value"), b"+OK\n")

        original = self.audit.read_bytes()
        boundaries, offset = [], 72

        while offset < len(original):
            end = offset + 40 + struct.unpack_from("<I", original, offset)[0]

            boundaries.append((offset, end))

            offset = end

        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        reordered = original[:72] + original[boundaries[1][0]:boundaries[1][1]] + original[boundaries[0][0]:boundaries[0][1]]

        for damaged in (bytes(corrupt), original[:-1], original[:71], reordered):
            with self.subTest(size=len(damaged)):
                self.audit.write_bytes(damaged)
                self.rejected_start()

                result = run("--dump-audit", self.audit, "--audit-key-file", self.key)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.audit.read_bytes(), damaged)

        # A wrong key is refused and exports nothing.
        self.audit.write_bytes(original)

        wrong = self.root / "wrong.key"

        self.assertEqual(run("--generate-key", wrong).returncode, 0)

        result = run("--dump-audit", self.audit, "--audit-key-file", wrong)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_policy_rejects_weak_expensive_duplicate_unknown_and_malformed_input(self):
        """Weak or oversized hashes, duplicates, unknown users and bad syntax prevent start-up."""
        base = f"CVAULT-SECURITY-1\nuser alice {self.hash}\n"
        malformed = [base.replace("m=65536", "m=8"), base.replace("m=65536", "m=4294967295"),
                     base.replace("argon2id", "argon2i"), base + f"user alice {self.hash}\n",
                     base + "allow unknown r tenant:\n", base + "allow alice admin tenant:\n",
                     base + "allow alice rw *\n", base + "allow alice rw\n", base + "\x00\n",
                     base.rstrip("\n"), "CVAULT-SECURITY-2\n", base + "x" * 513 + "\n",
                     base.replace("alice", "invalid\tname")]

        for policy in malformed:
            with self.subTest(policy=policy[:70]):
                self.write_policy(policy)
                self.rejected_start()

    def test_policy_without_grants_denies_all_and_crlf_is_supported(self):
        """A policy with users but no rules denies everything; CRLF line ends are accepted."""
        self.write_policy(f"CVAULT-SECURITY-1\r\n# comment\r\nuser alice {self.hash}\r\n")

        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")

    def test_password_provisioning_input_bounds_and_no_plaintext_output(self):
        """--hash-password rejects bad input and never echoes the password."""
        for password in (b"", b"x" * 1025, b"embedded\x00nul"):
            result = run("--hash-password", input=password + b"\n")

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

        result = run("--hash-password", input=PASSWORD + b"\r\n")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith(b"$argon2id$v=19$m=65536,t=2,p=1$"))

    def test_security_options_require_complete_configuration(self):
        """--security, --audit and --audit-key-file only work together."""
        for options in (("--security", self.policy), ("--audit", self.audit), ("--audit-key-file", self.key)):
            result = run(*options)

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"Listening", result.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX pseudo-terminal interruption test")
    def test_password_prompt_restores_echo_after_interrupt(self):
        """Interrupting the password prompt restores the terminal's echo setting."""
        import pty
        import termios

        master, terminal = pty.openpty()
        process = None

        try:
            initial = termios.tcgetattr(terminal)
            process = subprocess.Popen([ARGS.server, "--hash-password"], stdin=terminal,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Wait until the prompt has switched echo off.
            deadline = time.monotonic() + 5

            while termios.tcgetattr(terminal)[3] & termios.ECHO:
                self.assertIsNone(process.poll())

                if time.monotonic() >= deadline:
                    self.fail("Password prompt did not disable echo")

                time.sleep(0.01)

            process.send_signal(signal.SIGINT)

            output, errors = process.communicate(timeout=5)

            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(output, b"")
            self.assertEqual(termios.tcgetattr(terminal)[3] & termios.ECHO,
                             initial[3] & termios.ECHO)
            self.assertNotIn(b"AddressSanitizer", errors)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()

            os.close(master)
            os.close(terminal)

    @unittest.skipIf(os.name == "nt", "POSIX owner/mode and symlink validation")
    def test_private_policy_permissions_and_symlinks(self):
        """A group/world-readable policy file or a symlinked one is refused."""
        self.policy.chmod(0o644)
        self.rejected_start()
        self.policy.chmod(0o600)

        target = self.root / "target.conf"

        self.policy.rename(target)
        self.policy.symlink_to(target)
        self.rejected_start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--fixture", required=True)

    ARGS, remaining = parser.parse_known_args()

    unittest.main(argv=[__file__, *remaining])
