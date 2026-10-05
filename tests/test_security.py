"""Real TCP security, private files, audit tampering and injected fsync failures."""
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

ARGS = None
PASSWORD = b"test password with spaces"


def run(*arguments, **kwargs):
    result = subprocess.run([ARGS.server, *map(str, arguments)], capture_output=True, timeout=15, **kwargs)
    if b"AddressSanitizer" in result.stderr or b"runtime error:" in result.stderr:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result


class Connection:
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.reader = self.socket.makefile("rb")

    def command(self, command):
        self.socket.sendall(command + b"\n")
        line = self.reader.readline()
        if line.startswith(b"$") and line != b"$-1\n":
            size = int(line[1:])
            value = self.reader.read(size)
            if len(value) != size or self.reader.read(1) != b"\n":
                raise AssertionError("Invalid bulk response")
            return value
        return line

    def auth(self, name=b"alice", password=PASSWORD):
        # The global verification gate deliberately spans connections.
        time.sleep(0.26)
        return self.command(b"AUTH " + name + b" " + password)

    def close(self):
        self.reader.close()
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Server:
    def __init__(self, policy, audit, key, extra=()):
        self.errors = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            [ARGS.server, "--port", "0", "--security", str(policy), "--audit", str(audit),
             "--audit-key-file", str(key), *map(str, extra)], stdout=subprocess.PIPE,
            stderr=self.errors, **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}))
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
        return Connection(self.port)

    def close(self):
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
    @classmethod
    def setUpClass(cls):
        result = run("--hash-password", input=PASSWORD + b"\n")
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        cls.hash = result.stdout.decode().strip()

    def setUp(self):
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
        self.policy.write_bytes(text.encode())
        self.policy.chmod(0o600)

    def server(self, *extra):
        return Server(self.policy, self.audit, self.key, extra)

    def export(self):
        result = run("--dump-audit", self.audit, "--audit-key-file", self.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def rejected_start(self):
        result = run("--port", "0", "--security", self.policy, "--audit", self.audit,
                     "--audit-key-file", self.key)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"Listening", result.stdout)

    def test_native_api_and_audit_lock(self):
        result = subprocess.run([ARGS.fixture, "--api", str(self.policy), str(self.audit), str(self.key)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.export()), 3)

    def test_audit_failure_prevents_mutation_and_postmutation_failure_poisoning(self):
        for fault in (1, 2):
            with self.subTest(fault=fault):
                result = subprocess.run([ARGS.fixture, "--fault", str(self.policy),
                                         str(self.root / f"fault-{fault}.bin"), str(self.key),
                                         str(self.root / f"data-{fault}"), str(fault)],
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_default_deny_and_independent_permissions(self):
        with self.server() as server, server.connect() as alice, server.connect() as writer:
            for command in (b"GET alice:x", b"SET alice:x value", b"DEL alice:x", b"EXPIRE alice:x 3", b"TTL alice:x"):
                self.assertEqual(alice.command(command), b"-ERR access denied\n")
            self.assertEqual(alice.auth(), b"+OK\n")
            self.assertEqual(writer.auth(b"writer"), b"+OK\n")
            self.assertEqual(writer.command(b"SET shared:x shared value"), b"+OK\n")
            self.assertEqual(writer.command(b"GET shared:x"), b"-ERR access denied\n")
            self.assertEqual(writer.command(b"TTL shared:x"), b"-ERR access denied\n")
            self.assertEqual(alice.command(b"GET shared:x"), b"shared value")
            for command in (b"SET shared:x tampered", b"DEL shared:x", b"EXPIRE shared:x 0"):
                self.assertEqual(alice.command(command), b"-ERR access denied\n")
            self.assertEqual(alice.command(b"GET shared:x"), b"shared value")
            for key in (b"aliceevil:x", b"ALICE:x", b"../alice:x", b"missing:x"):
                self.assertEqual(alice.command(b"GET " + key), b"-ERR access denied\n")
            self.assertEqual(alice.command(b"GET alice:missing"), b"$-1\n")

    def test_data_commands_empty_large_and_expiration(self):
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
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.auth(password=b"incorrect"), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"AUTH\talice " + PASSWORD), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"AUTH alice"), b"-ERR authentication failed\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")
            self.assertEqual(client.auth(), b"+OK\n")
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
        with self.server() as server, server.connect() as client:
            for name in (b"missing", b"injected\tname", b"alice"):
                self.assertEqual(client.auth(name, b"incorrect"), b"-ERR authentication failed\n")
            self.assertEqual(client.reader.read(1), b"")
        events = self.export()
        failed = [e for e in events if e["operation"] == "AUTH" and e["phase"] == "result"]
        self.assertEqual(len(failed), 3)
        self.assertTrue(all(e["identity"] == "anonymous" for e in failed))

    def test_session_isolation_disconnect_and_slot_reuse(self):
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
        with self.server() as server, server.connect() as client:
            client.socket.sendall(b"AUTH ali")
            client.socket.sendall(b"ce " + PASSWORD + b"\r\nSET alice:x pipelined\nGET alice:x\n")
            self.assertEqual(client.reader.readline(), b"+OK\n")
            self.assertEqual(client.reader.readline(), b"+OK\n")
            self.assertEqual(client.reader.readline(), b"$9\n")
            self.assertEqual(client.reader.read(10), b"pipelined\n")

    def test_strict_grammar_reserved_operations_and_numeric_overflow(self):
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:x original"), b"+OK\n")
            for command in (b"GET alice:x extra", b"DEL alice:x extra", b"EXPIRE alice:x 9223372036854775808",
                            b"EXPIRE alice:x -9223372036854775809", b"EXPIRE alice:x +1", b"EXPIRE alice:x 1junk",
                            b"SET  value", b"EXPORT alice:x", b"PURGE", b"get alice:x", b"PING extra"):
                self.assertEqual(client.command(command), b"-ERR invalid command\n")
            self.assertEqual(client.command(b"GET alice:x"), b"original")

    def test_encrypted_audit_metadata_and_intent_result_pairing(self):
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"SET alice:private-key private-value"), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:private-key"), b"private-value")
            self.assertEqual(client.command(b"GET forbidden:key"), b"-ERR access denied\n")
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

    def test_audit_wrong_key_tampering_reorder_and_torn_tail_fail_closed(self):
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
        self.audit.write_bytes(original)
        wrong = self.root / "wrong.key"
        self.assertEqual(run("--generate-key", wrong).returncode, 0)
        result = run("--dump-audit", self.audit, "--audit-key-file", wrong)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_policy_rejects_weak_expensive_duplicate_unknown_and_malformed_input(self):
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
        self.write_policy(f"CVAULT-SECURITY-1\r\n# comment\r\nuser alice {self.hash}\r\n")
        with self.server() as server, server.connect() as client:
            self.assertEqual(client.auth(), b"+OK\n")
            self.assertEqual(client.command(b"GET alice:x"), b"-ERR access denied\n")

    def test_password_provisioning_input_bounds_and_no_plaintext_output(self):
        for password in (b"", b"x" * 1025, b"embedded\x00nul"):
            result = run("--hash-password", input=password + b"\n")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        result = run("--hash-password", input=PASSWORD + b"\r\n")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith(b"$argon2id$v=19$m=65536,t=2,p=1$"))

    def test_security_options_require_complete_configuration(self):
        for options in (("--security", self.policy), ("--audit", self.audit), ("--audit-key-file", self.key)):
            result = run(*options)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"Listening", result.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX pseudo-terminal interruption test")
    def test_password_prompt_restores_echo_after_interrupt(self):
        import pty
        import termios
        master, terminal = pty.openpty()
        process = None
        try:
            initial = termios.tcgetattr(terminal)
            process = subprocess.Popen([ARGS.server, "--hash-password"], stdin=terminal,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
