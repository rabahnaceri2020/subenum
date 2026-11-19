#!/usr/bin/env python3
"""Offline checks for the bundled SecLists default and installer selection."""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "resources/wordlists/subdomains.txt.gz"
SECLISTS_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Discovery/DNS/subdomains-top1million-5000.txt"
)
DEEP_URL = (
    "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/"
    "n0kovo_subdomains_huge.txt"
)
EXPECTED_SHA256 = "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19"
WGET_STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
url = args[-1]
output = Path(args[args.index("-O") + 1])
with Path(os.environ["DOWNLOAD_LOG"]).open("a") as log:
    log.write(json.dumps({"url": url, "output": str(output)}) + "\n")
if url == os.environ["SECLISTS_URL"]:
    output.write_bytes(Path(os.environ["DOWNLOAD_PAYLOAD"]).read_bytes())
elif url == os.environ["DEEP_URL"]:
    output.write_text("deep-fixture\n")
else:
    raise SystemExit("Unexpected download URL in offline test: " + url)
'''


class BundledWordlistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packed = ARCHIVE.read_bytes()
        cls.data = gzip.decompress(cls.packed)
        cls.words = cls.data.decode("ascii").splitlines()

    def test_exact_official_snapshot_checksum(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECTED_SHA256)
        self.assertEqual(len(self.data), 30075)

    def test_five_thousand_unique_entries(self):
        self.assertEqual(len(self.words), 5000)
        self.assertEqual(len(set(self.words)), 5000)

    def test_plaintext_format(self):
        self.assertTrue(self.data.endswith(b"\n"))
        self.assertNotIn(b"\r", self.data)
        self.assertTrue(all(word and word == word.strip() for word in self.words))
        self.assertTrue(all(re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", word)
                            for word in self.words))

    def test_common_candidates_and_upstream_order_are_retained(self):
        self.assertEqual(self.words[:5], ["www", "mail", "ns2", "ns1", "ftp"])
        self.assertTrue({"www", "mail", "api", "dev", "staging", "test", "admin",
                         "vpn", "portal", "auth", "cdn"}.issubset(self.words))

    def test_deterministic_gzip_header_and_content(self):
        self.assertEqual(self.packed[:10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff")
        buffer = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=buffer, mode="wb", compresslevel=9, mtime=0) as stream:
            stream.write(self.data)
        self.assertEqual(buffer.getvalue(), self.packed)


@unittest.skipUnless(shutil.which("bash") and shutil.which("gzip"), "bash and gzip required")
class InstallerWordlistTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-wordlist-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        self.lists = self.work / "wordlists"
        self.bin = self.work / "bin"
        self.lists.mkdir(parents=True)
        self.bin.mkdir()
        stub = self.bin / "wget"
        stub.write_text(WGET_STUB)
        stub.chmod(0o755)
        self.default = self.lists / "subdomains.txt"
        self.deep = self.lists / "subdomains_big.txt"
        self.deep.write_text("existing-deep-fixture\n")
        self.payload = self.work / "upstream-fixture.txt"
        self.payload.write_bytes(gzip.decompress(ARCHIVE.read_bytes()))
        self.requests = self.work / "downloads.jsonl"
        resolvers = self.work / "resolvers.txt"
        trusted = self.work / "trusted.txt"
        resolvers.write_text("127.0.0.1\n")
        trusted.write_text("127.0.0.1\n")
        self.env = dict(
            os.environ,
            PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            WORDLISTS_DIR=str(self.lists),
            dir=str(self.work / "tools"),
            resolvers=str(resolvers),
            resolvers_trusted=str(trusted),
            resolvers_url="https://resolvers.example.test/public",
            resolvers_trusted_url="https://resolvers.example.test/trusted",
            DOWNLOAD_LOG=str(self.requests),
            DOWNLOAD_PAYLOAD=str(self.payload),
            SECLISTS_URL=SECLISTS_URL,
            DEEP_URL=DEEP_URL,
            DRY_RUN="false",
            yellow="", reset="", bgreen="",
        )
        source = (ROOT / "install.sh").read_text()
        match = re.search(r"^function download_required_files\(\) \{\n.*?^\}", source, re.M | re.S)
        self.assertIsNotNone(match)
        # Execute only the download function with mocked network access; never run the installer.
        self.function = match.group(0)

    def run_downloads(self, **settings):
        harness = '''
set -euo pipefail
header() { :; }
retry() { shift 2; "$@"; }
q_to() { shift; "$@"; }
msg_err() { printf '%s\\n' "$*" >&2; return 1; }
'''
        result = subprocess.run(
            ["bash", "-c", harness + self.function + "\ndownload_required_files"],
            cwd=self.work, env=dict(self.env, **settings), text=True,
            capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def downloads(self):
        if not self.requests.exists():
            return []
        return [json.loads(line) for line in self.requests.read_text().splitlines()]

    def test_fresh_install_expands_bundled_five_thousand_list(self):
        shutil.copyfile(ARCHIVE, self.lists / "subdomains.txt.gz")
        self.run_downloads()
        self.assertEqual(self.default.read_bytes(), self.payload.read_bytes())
        self.assertEqual(self.downloads(), [])
        self.assertEqual(self.deep.read_text(), "existing-deep-fixture\n")

    def test_missing_archive_fetches_official_seclists_list(self):
        self.run_downloads()
        self.assertEqual(self.default.read_bytes(), self.payload.read_bytes())
        self.assertEqual(self.downloads(), [{"url": SECLISTS_URL, "output": str(self.default)}])

    def test_existing_custom_plaintext_is_preserved(self):
        self.default.write_text("custom-prefix\n")
        shutil.copyfile(ARCHIVE, self.lists / "subdomains.txt.gz")
        self.run_downloads()
        self.assertEqual(self.default.read_text(), "custom-prefix\n")
        self.assertEqual(self.deep.read_text(), "existing-deep-fixture\n")
        self.assertEqual(self.downloads(), [])

    def test_deep_huge_wordlist_source_is_unchanged(self):
        self.default.write_text("custom-prefix\n")
        # An empty existing file follows the installer's missing/empty download path.
        self.deep.write_text("")
        self.run_downloads()
        self.assertEqual(self.default.read_text(), "custom-prefix\n")
        self.assertEqual(self.deep.read_text(), "deep-fixture\n")
        self.assertEqual(self.downloads(), [{"url": DEEP_URL, "output": str(self.deep)}])

    def test_dry_run_does_not_expand_or_download(self):
        shutil.copyfile(ARCHIVE, self.lists / "subdomains.txt.gz")
        self.run_downloads(DRY_RUN="true")
        self.assertFalse(self.default.exists())
        self.assertEqual(self.deep.read_text(), "existing-deep-fixture\n")
        self.assertEqual(self.downloads(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
