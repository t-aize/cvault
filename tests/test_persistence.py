"""Black-box persistence tests: real encrypted files, processes and fault injection.

The tests drive the *persistence fixture* (a small harness around the public C
API, see ``persistence_fixture.c``) and the real ``cvault-server``. They create
real data directories, damage the files in controlled ways and check that
recovery either succeeds with exactly the acknowledged data or fails closed.

Status codes returned by the fixture are the numeric values of ``cv_status``.
"""

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest


# Command-line arguments, filled in by the ``__main__`` block below.
ARGS = None

# Numeric values of cv_status (include/cvault/common.h).
OK, INVALID, NOT_FOUND, NO_MEMORY, CRYPTO, IO, LIMIT, CORRUPT, BUSY = 0, 1, 3, 4, 5, 7, 8, 9, 10


class Session:
    """One fixture process holding an open store, driven line by line."""

    def __init__(self, directory, key, now=1_000_000, faults=False, expected=OK):
        """Start the fixture and check the status of ``cv_persist_open``.

        ``now`` is the deterministic wall clock in epoch milliseconds, ``faults``
        selects the fault-injecting build, and ``expected`` is the open status
        that the test anticipates (anything but ``OK`` means the process must
        also exit with a failure).
        """
        executable = ARGS.faults if faults else ARGS.fixture

        self.process = subprocess.Popen([executable, str(directory), str(key), str(now)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8")

        status = self.process.stdout.readline().strip()

        if status != str(expected):
            self.process.kill()
            _, error = self.process.communicate()

            raise AssertionError(f"open: expected {expected}, got {status!r}: {error}")

        if expected != OK:
            self.process.communicate(timeout=5)

            if self.process.returncode == 0:
                raise AssertionError("failed open returned success")

    def command(self, command, expected=None):
        """Send one command and return its reply line, optionally asserting it."""
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

        result = self.process.stdout.readline().strip()

        if expected is not None and result != str(expected):
            raise AssertionError(f"{command[:80]}: expected {expected!r}, got {result!r}")

        return result

    def close(self):
        """Ask the fixture to close the store and check its exit status."""
        if self.process.poll() is None:
            self.process.stdin.write("EXIT\n")
            self.process.stdin.flush()

        _, error = self.process.communicate(timeout=15)

        if self.process.returncode != 0:
            raise AssertionError(f"fixture exit {self.process.returncode}: {error}")

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        if kind:
            self.process.kill()
            self.process.communicate()
        else:
            self.close()


def frames(data):
    """Parse public framing only; tests never know plaintext AEAD record bodies.

    Returns the ``(start, end)`` byte offsets of every record that follows the
    72-byte file header. Each record is a 40-byte frame plus its ciphertext.
    """
    offset = 72
    result = []

    while offset < len(data):
        length = struct.unpack_from("<I", data, offset)[0]
        end = offset + 40 + length

        result.append((offset, end))

        offset = end

    assert offset == len(data)

    return result


class Persistence(unittest.TestCase):
    """Durability, recovery, corruption handling and fault behaviour."""

    def setUp(self):
        """Create a private temporary directory and a fresh encryption key."""
        self.temporary = tempfile.TemporaryDirectory(prefix="cvault-persistence-")
        self.root = Path(self.temporary.name)
        self.key = self.root / "master.key"

        result = subprocess.run([ARGS.server, "--generate-key", str(self.key)], capture_output=True)

        self.assertEqual(result.returncode, 0, result.stderr)

        self.data = self.root / "data"

    def tearDown(self):
        """Remove the temporary directory."""
        self.temporary.cleanup()

    def seed(self, snapshot=False):
        """Write three keys (optionally with a snapshot after two) and return the journal path."""
        with Session(self.data, self.key) as session:
            session.command("SET private-key 0073656372657400ff", OK)
            session.command("SET empty -", OK)

            if snapshot:
                session.command("SNAP", OK)

            session.command("SET tail 7461696c", OK)

        return self.data / "journal.aof"

    def replica(self, name):
        """Copy the data directory so a test can damage a private copy."""
        target = self.root / name

        shutil.copytree(self.data, target)

        return target

    def test_binary_empty_bounds_and_replay(self):
        """Binary and empty values and maximum sizes survive a restart."""
        with Session(self.data, self.key) as session:
            session.command("SET private-key 0073656372657400ff", OK)
            session.command("SET empty -", OK)
            session.command("SET large " + bytes(range(256)).hex() * 256, OK)
            session.command("SET " + "k" * 256 + " 00", OK)
            session.command("SET " + "k" * 257 + " 00", LIMIT)
            session.command("DEL absent", NOT_FOUND)
            session.command("EXPIRE absent 1", NOT_FOUND)
            session.command("SET deleted ff", OK)
            session.command("DEL deleted", OK)
            session.command("STATS", "0 6 0 0 0")

        with Session(self.data, self.key) as session:
            session.command("GET private-key", "0 0073656372657400ff")
            session.command("GET empty", "0")
            session.command("GET deleted", "3")

            self.assertEqual(session.command("GET large"), "0 " + bytes(range(256)).hex() * 256)

            session.command("GET " + "k" * 256, "0 00")

    def test_ciphertext_hides_user_keys_and_values(self):
        """No plaintext key or value appears in the journal or the snapshot."""
        self.seed(True)

        for name in ("journal.aof", "snapshot.cvs"):
            data = (self.data / name).read_bytes()

            self.assertNotIn(b"private-key", data)
            self.assertNotIn(b"\x00secret\x00\xff", data)
            self.assertNotIn(b"tail", data)

    def test_ttl_survives_downtime_and_set_clears_it(self):
        """TTLs keep counting while the server is down, and SET clears a TTL."""
        with Session(self.data, self.key) as session:
            session.command("SET short 01", OK)
            session.command("EXPIRE short 10", OK)
            session.command("SET long 02", OK)
            session.command("EXPIRE long 100", OK)
            session.command("SET reset 03", OK)
            session.command("EXPIRE reset 1", OK)
            session.command("SET reset 04", OK)
            session.command("EXPIRE long 9223372036854775807", LIMIT)
            session.command("SNAP", OK)

        with Session(self.data, self.key, now=1_010_000) as session:
            session.command("GET short", "3")
            session.command("GET long", "0 02")

            ttl = session.command("TTL long").split()

            self.assertEqual(ttl[0], "0")
            self.assertIn(int(ttl[1]), (89, 90))

            session.command("TTL reset", "0 -1")

    def test_historical_expire_extension_is_replayed_before_filtering(self):
        """A later EXPIRE that extends a TTL must not lose a key that had already lapsed."""
        with Session(self.data, self.key) as session:
            session.command("SET key 01", OK)
            session.command("EXPIRE key 1", OK)
            session.command("SNAP", OK)
            session.command("NOW 1100000", OK)
            session.command("EXPIRE key 1000", OK)

        with Session(self.data, self.key, now=1_100_000) as session:
            session.command("GET key", "0 01")

            self.assertGreaterEqual(int(session.command("TTL key").split()[1]), 999)

    def test_nonpositive_expire_is_durable_delete(self):
        """EXPIRE with zero or negative seconds is journaled as a delete."""
        with Session(self.data, self.key) as session:
            for seconds in ("0", "-10"):
                session.command("SET key 01", OK)
                session.command("EXPIRE key " + seconds, OK)

            session.command("STATS", "0 4 0 0 0")

        with Session(self.data, self.key) as session:
            session.command("GET key", "3")

    def test_incomplete_final_record_repair_and_append(self):
        """A write cut at any byte of the last record is truncated and logging resumes."""
        journal = self.seed()
        original = journal.read_bytes()
        start, end = frames(original)[-1]

        # Cover every byte of both the final header and final encrypted body.
        for length in range(start + 1, end):
            target = self.replica(f"cut-{length}")
            path = target / "journal.aof"

            path.write_bytes(original[:length])

            with Session(target, self.key) as session:
                session.command("GET private-key", "0 0073656372657400ff")
                session.command("GET tail", "3")
                session.command("STATS", "0 2 0 1 0")
                session.command("SET recovered 01", OK)

            with Session(target, self.key) as session:
                session.command("GET recovered", "0 01")

    def test_torn_header_is_fatal_without_modifying_files(self):
        """A truncated file header is corruption, and the file is left untouched."""
        journal = self.seed()
        original = journal.read_bytes()

        for size in (0, 1, 8, 32, 56, 71):
            target = self.replica(f"header-{size}")
            path = target / "journal.aof"
            data = original[:size]

            path.write_bytes(data)

            Session(target, self.key, expected=CORRUPT)

            self.assertEqual(path.read_bytes(), data)

    def test_complete_corruption_is_fatal_without_tail_repair(self):
        """A flipped bit in a complete record is never silently repaired."""
        journal = self.seed(True)
        original = journal.read_bytes()
        first, end = frames(original)[0]

        for position in (0, 8, 24, 32, 56, first, first + 4, first + 8,
                         first + 16, first + 40, end - 1, len(original) - 1):
            target = self.replica(f"corrupt-{position}")
            path = target / "journal.aof"
            damaged = bytearray(original)

            damaged[position] ^= 0x80

            path.write_bytes(damaged)

            process = subprocess.run([ARGS.fixture, str(target), str(self.key)], capture_output=True, text=True)

            self.assertNotEqual(process.returncode, 0)
            self.assertIn(process.stdout.strip(), (str(CORRUPT), str(CRYPTO)))
            self.assertEqual(path.read_bytes(), damaged)

    def test_reordering_or_duplicate_records_is_detected(self):
        """Swapping or duplicating records breaks the authentication chain."""
        journal = self.seed()
        data = journal.read_bytes()
        chunks = [data[a:b] for a, b in frames(data)]

        for name, tail in (("reorder", chunks[1] + chunks[0] + chunks[2]),
                           ("duplicate", chunks[0] + chunks[0] + chunks[1] + chunks[2])):
            target = self.replica(name)

            (target / "journal.aof").write_bytes(data[:72] + tail)

            Session(target, self.key, expected=CORRUPT)

    def test_snapshot_requires_footer_and_exact_eof(self):
        """A snapshot truncated anywhere, or with trailing bytes, is rejected."""
        self.seed(True)

        snapshot = (self.data / "snapshot.cvs").read_bytes()
        boundaries = {0, 1, 71, 72, len(snapshot) - 1}

        boundaries.update(a for a, _ in frames(snapshot))
        boundaries.update(b for _, b in frames(snapshot)[:-1])

        for size in sorted(boundaries):
            target = self.replica(f"snapshot-cut-{size}")

            (target / "snapshot.cvs").write_bytes(snapshot[:size])

            Session(target, self.key, expected=CORRUPT)

        target = self.replica("snapshot-trailing")

        (target / "snapshot.cvs").write_bytes(snapshot + b"x")

        Session(target, self.key, expected=CORRUPT)

    def test_snapshot_and_tail_and_standalone_restore(self):
        """Recovery combines snapshot and journal tail, and works from a snapshot alone."""
        self.seed(True)

        with Session(self.data, self.key) as session:
            session.command("STATS", "0 3 2 0 0")
            session.command("GET tail", "0 7461696c")

        target = self.replica("standalone")

        (target / "journal.aof").unlink()

        with Session(target, self.key) as session:
            session.command("GET private-key", "0 0073656372657400ff")
            session.command("GET tail", "3")
            session.command("SET new 01", OK)
            session.command("STATS", "0 3 2 0 0")

        with Session(target, self.key) as session:
            session.command("GET new", "0 01")

    def test_snapshot_cannot_reference_missing_journal_history(self):
        """A journal shorter than the snapshot's sequence is corruption."""
        self.seed(True)

        journal = self.data / "journal.aof"

        journal.write_bytes(journal.read_bytes()[:72])

        Session(self.data, self.key, expected=CORRUPT)

    def test_wrong_key_and_dataset_mismatch(self):
        """A wrong key fails authentication; a foreign snapshot is rejected."""
        self.seed(True)

        other_key = self.root / "other.key"

        self.assertEqual(subprocess.run([ARGS.server, "--generate-key", str(other_key)], capture_output=True).returncode, 0)

        Session(self.data, other_key, expected=CRYPTO)

        other = self.root / "other"

        with Session(other, self.key) as session:
            session.command("SNAP", OK)

        shutil.copyfile(other / "snapshot.cvs", self.data / "snapshot.cvs")

        Session(self.data, self.key, expected=CORRUPT)

    def test_single_writer_lock_survives_snapshot_child(self):
        """Only one process may open a directory, even while a snapshot child runs."""
        with Session(self.data, self.key) as session:
            Session(self.data, self.key, expected=BUSY)

            session.command("SET key 01", OK)
            session.command("ASYNC", OK)
            session.command("WAIT", OK)

            Session(self.data, self.key, expected=BUSY)

        with Session(self.data, self.key):
            pass

    def test_background_snapshot_boundary_and_concurrent_tail(self):
        """Writes made during a background snapshot stay in the journal, not in the snapshot."""
        with Session(self.data, self.key) as session:
            for index in range(40):
                session.command(f"SET key{index} " + "ab" * 8192, OK)

            session.command("SET before 01", OK)
            session.command("ASYNC", OK)
            session.command("ASYNC", BUSY)
            session.command("SNAP", BUSY)
            session.command("SET before 02", OK)
            session.command("DEL key0", OK)
            session.command("SET after 03", OK)
            session.command("WAIT", OK)
            session.command("POLL", "0 1")
            session.command("STATS", "0 44 41 0 0")

        with Session(self.data, self.key) as session:
            session.command("GET before", "0 02")
            session.command("GET key0", "3")
            session.command("GET after", "0 03")

        target = self.replica("boundary")

        (target / "journal.aof").unlink()

        with Session(target, self.key) as session:
            session.command("GET before", "0 01")
            session.command("GET after", "3")

            self.assertTrue(session.command("GET key0").startswith("0 abab"))

    def test_close_joins_active_snapshot(self):
        """Closing the store waits for a running background snapshot."""
        with Session(self.data, self.key) as session:
            session.command("SET key 01", OK)
            session.command("ASYNC", OK)

        with Session(self.data, self.key) as session:
            session.command("STATS", "0 1 1 0 0")

    def test_crash_releases_lock_and_preserves_acknowledged_write(self):
        """After a hard crash the lock is released and acknowledged writes are intact."""
        process = Session(self.data, self.key)

        process.command("SET key 01", OK)
        process.process.stdin.write("CRASH\n")
        process.process.stdin.flush()
        process.process.communicate(timeout=5)

        with Session(self.data, self.key) as session:
            session.command("GET key", "0 01")

    def test_orphan_temporary_files_are_ignored(self):
        """Leftover snapshot temporary files from a crash do not affect recovery."""
        self.seed()

        (self.data / ".snapshot-crashed.tmp").write_bytes(b"garbage")

        with Session(self.data, self.key) as session:
            session.command("GET tail", "0 7461696c")

    def test_allocation_failure_does_not_change_memory_or_journal(self):
        """A failed table clone leaves both the live data and the journal untouched."""
        with Session(self.data, self.key, faults=True) as session:
            session.command("SET key 01", OK)

            before = (self.data / "journal.aof").read_bytes()

            session.command("FAULT 3", OK)
            session.command("SET key 02", NO_MEMORY)
            session.command("GET key", "0 01")
            session.command("STATS", "0 1 0 0 0")

            self.assertEqual((self.data / "journal.aof").read_bytes(), before)

    def test_uncertain_sync_failure_requires_reopen(self):
        """After a failed sync the handle refuses all work until the store is reopened."""
        with Session(self.data, self.key, faults=True) as session:
            session.command("SET key 01", OK)
            session.command("FAULT 1", OK)
            session.command("SET key 02", IO)
            session.command("GET key", "7")
            session.command("SET later 03", IO)
            session.command("SNAP", IO)
            session.command("STATS", "0 2 0 0 1")

        with Session(self.data, self.key) as session:
            session.command("GET key", "0 02")
            session.command("GET later", "3")

    def test_partial_write_failure_is_repaired_on_reopen(self):
        """A torn write is truncated at the next open and reported in the stats."""
        with Session(self.data, self.key, faults=True) as session:
            session.command("SET key 01", OK)
            session.command("FAULT 2", OK)
            session.command("SET key 02", IO)
            session.command("STATS", "0 1 0 0 1")

        with Session(self.data, self.key) as session:
            session.command("GET key", "0 01")
            session.command("STATS", "0 1 0 1 0")

    def test_snapshot_failure_preserves_previous_checkpoint(self):
        """A failed snapshot leaves the old checkpoint in place and no temporary file."""
        self.seed(True)

        previous = (self.data / "snapshot.cvs").read_bytes()

        with Session(self.data, self.key, faults=True) as session:
            session.command("FAULT 1", OK)
            session.command("SNAP", IO)
            session.command("GET tail", "0 7461696c")

            self.assertEqual((self.data / "snapshot.cvs").read_bytes(), previous)
            self.assertEqual(list(self.data.glob(".snapshot-*.tmp")), [])

            session.command("SNAP", OK)

    def test_key_generation_never_overwrites_and_load_is_exact(self):
        """Key generation refuses to overwrite, and a key file must be exactly 32 bytes."""
        original = self.key.read_bytes()
        result = subprocess.run([ARGS.server, "--generate-key", str(self.key)], capture_output=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.key.read_bytes(), original)
        self.assertEqual(len(original), 32)

        for length in (0, 31, 33):
            bad = self.root / f"bad-{length}.key"

            bad.write_bytes(b"x" * length)
            bad.chmod(0o600)

            Session(self.root / f"bad-{length}", bad, expected=CORRUPT)

    @unittest.skipIf(os.name == "nt", "POSIX permission/symlink policy")
    def test_private_permissions_symlinks_and_hardlinks(self):
        """Files are private, and symlinks or hard links in place of them are rejected."""
        self.seed()

        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)

        for name in ("journal.aof", "snapshot.cvs", "writer.lock"):
            if (self.data / name).exists():
                self.assertEqual((self.data / name).stat().st_mode & 0o777, 0o600)

        # A key readable by others is refused.
        self.key.chmod(0o644)

        Session(self.data, self.key, expected=IO)

        self.key.chmod(0o600)

        # The data directory itself must not be reached through a symlink.
        symlink = self.root / "link"

        symlink.symlink_to(self.data, target_is_directory=True)

        Session(symlink, self.key, expected=IO)
        Session(str(symlink) + "/", self.key, expected=IO)

        # Neither may the journal be a symlink or a hard link.
        journal = self.data / "journal.aof"

        journal.rename(self.root / "original.aof")
        journal.symlink_to(self.root / "original.aof")

        Session(self.data, self.key, expected=IO)

        journal.unlink()
        os.link(self.root / "original.aof", journal)

        Session(self.data, self.key, expected=IO)

    def test_server_recovery_before_bind_and_periodic_snapshots(self):
        """The real server recovers before listening, checkpoints periodically, and refuses corrupt data."""
        self.seed(True)

        server = subprocess.Popen([ARGS.server, "--data", str(self.data), "--key-file", str(self.key),
                                   "--port", "0", "--snapshot-interval-ms", "100"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        try:
            ready = server.stdout.readline().strip()

            self.assertTrue(ready.startswith("Listening on 127.0.0.1:"), ready)

            port = int(ready.split()[2].rsplit(":", 1)[1])

            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(b"PING\n")

                self.assertEqual(client.recv(100), b"+PONG\n")

            # Wait until the periodic snapshot covers the recovered sequence.
            deadline = time.monotonic() + 5

            while time.monotonic() < deadline:
                checkpoint = (self.data / "snapshot.cvs").read_bytes()

                if struct.unpack_from("<Q", checkpoint, 24)[0] == 3:
                    break

                time.sleep(0.05)
            else:
                self.fail("periodic snapshot did not advance to the recovered sequence")

            if os.name != "nt":
                server.send_signal(signal.SIGTERM)

                _, error = server.communicate(timeout=10)

                self.assertEqual(server.returncode, 0, error)
            else:
                server.terminate()
                server.communicate(timeout=10)
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()

        with Session(self.data, self.key) as session:
            session.command("STATS", "0 3 3 0 0")

        # Corrupt the journal: the server must refuse to start, before listening.
        journal = self.data / "journal.aof"
        data = bytearray(journal.read_bytes())

        data[-1] ^= 1

        journal.write_bytes(data)

        result = subprocess.run([ARGS.server, "--data", str(self.data), "--key-file", str(self.key),
                                 "--port", "0"], capture_output=True, text=True, timeout=5)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Listening", result.stdout)
        self.assertIn("recovery failed", result.stderr)

    def test_server_rejects_incomplete_persistence_options(self):
        """--data and --key-file must be given together; other combinations are errors."""
        for options in (["--data", str(self.data)], ["--key-file", str(self.key)],
                        ["--snapshot-interval-ms", "100"], ["--generate-key", str(self.key), "--port", "0"]):
            result = subprocess.run([ARGS.server, *options], capture_output=True, timeout=5)

            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--faults", required=True)
    parser.add_argument("--server", required=True)

    ARGS, rest = parser.parse_known_args()

    unittest.main(argv=[__file__, *rest], verbosity=2)
