"""Verify bootstrap recovery without depending on a live download service.

``scripts/bootstrap-posix.py`` downloads pinned archives. These tests replace the
network with scripted failures and check the guarantees that matter:

* transient errors are retried with exponential backoff,
* a file is published only after its SHA-256 digest matches,
* permanent errors and checksum mismatches are never retried,
* a corrupted cache is detected instead of being trusted.
"""

import hashlib
import io
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


BOOTSTRAP = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/bootstrap-posix.py'))
DOWNLOAD = BOOTSTRAP['download']
GLOBALS = DOWNLOAD.__globals__


class Downloads(unittest.TestCase):
    """Behaviour of ``download()`` under simulated network conditions."""

    def setUp(self):
        """Point the downloader at a private cache directory and a known payload."""
        self.temporary = tempfile.TemporaryDirectory(prefix='cvault-bootstrap-')
        self.root = Path(self.temporary.name)
        self.patch = patch.dict(GLOBALS, DEPS=self.root)
        self.patch.start()

        self.payload = b'verified synthetic archive\x00\xff'
        self.spec = {'file': 'archive.bin', 'url': 'https://example.invalid/archive',
                     'sha256': hashlib.sha256(self.payload).hexdigest()}

    def tearDown(self):
        """Undo the patch and remove the private cache."""
        self.patch.stop()
        self.temporary.cleanup()

    def test_dns_retry_publishes_only_verified_complete_download(self):
        """A DNS failure is retried once after 2 s and the result is verified."""
        with patch('urllib.request.urlopen', side_effect=[urllib.error.URLError('DNS unavailable'),
                                                         io.BytesIO(self.payload)]) as request, \
             patch('time.sleep') as sleep:
            archive = DOWNLOAD(self.spec)

            self.assertEqual(archive.read_bytes(), self.payload)
            self.assertEqual(request.call_count, 2)
            sleep.assert_called_once_with(2)
            self.assertFalse(archive.with_name('archive.bin.part').exists())

    def test_retry_exhaustion_leaves_no_cached_partial_file(self):
        """Five interrupted attempts give up with backoff 2/4/8/16 s and leave no file behind."""
        class Interrupted(io.BytesIO):
            def read(self, count=-1):
                if self.tell():
                    raise ConnectionResetError('connection interrupted')

                return super().read(3)

        with patch('urllib.request.urlopen', side_effect=lambda *_, **__: Interrupted(self.payload)), \
             patch('time.sleep') as sleep:
            with self.assertRaises(ConnectionResetError):
                DOWNLOAD(self.spec)

            self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4, 8, 16])

        self.assertEqual(list((self.root / 'downloads').iterdir()), [])

    def test_invalid_checksum_never_publishes_or_retries(self):
        """A digest mismatch is a hard failure: nothing is published and nothing is retried."""
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'altered')) as request, \
             patch('time.sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                DOWNLOAD(self.spec)

            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()

        self.assertEqual(list((self.root / 'downloads').iterdir()), [])

    def test_existing_cache_is_verified_without_network_access(self):
        """A cached archive is checked offline, and a modified cache is rejected."""
        directory = self.root / 'downloads'
        directory.mkdir()

        archive = directory / self.spec['file']
        archive.write_bytes(self.payload)

        with patch('urllib.request.urlopen') as request:
            self.assertEqual(DOWNLOAD(self.spec), archive)
            request.assert_not_called()

            archive.write_bytes(b'changed cache')

            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                DOWNLOAD(self.spec)

            request.assert_not_called()

        self.assertEqual(archive.read_bytes(), b'changed cache')

    def test_permanent_http_errors_are_not_retried(self):
        """An HTTP 404 fails immediately instead of being retried."""
        error = urllib.error.HTTPError(self.spec['url'], 404, 'missing', {}, None)

        with patch('urllib.request.urlopen', side_effect=error) as request, patch('time.sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                DOWNLOAD(self.spec)

            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
