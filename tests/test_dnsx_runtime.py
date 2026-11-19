#!/usr/bin/env python3
"""DNSX helper regressions: mocks plus an optional loopback-only DNS server."""

import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
REAL_DNSX = shutil.which("dnsx")
TIMEOUT = shutil.which("timeout")
HARNESS = r'''
set -o pipefail
SCRIPTPATH="$REPO_ROOT"
source "$REPO_ROOT/lib/common.sh"
source "$REPO_ROOT/modules/utils.sh"
sleep() { command sleep 0.01; }
'''
DNSX_STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time
args = sys.argv[1:]
raw = Path(args[args.index("-o") + 1])
resolvers = Path(args[args.index("-r") + 1])
with Path(os.environ["CAPTURE"]).open("a") as capture:
    capture.write(json.dumps({
        "args": args, "raw": str(raw), "resolver_file": str(resolvers),
        "raw_existed": raw.is_file(), "raw_before": raw.read_text() if raw.exists() else None,
        "resolvers": resolvers.read_text(),
    }) + "\n")
with raw.open("a") as output:
    output.write(os.environ["DNSX_FIXTURE"])
time.sleep(float(os.environ.get("DNSX_DELAY", "0")))
sys.exit(int(os.environ.get("DNSX_EXIT", "0")))
'''


class LoopbackDNS:
    """Minimal UDP fixture; every packet is received and answered on loopback."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.endpoint = "127.0.0.1:" + str(self.socket.getsockname()[1])
        self.questions = []
        self.errors = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopped.set()
        self.thread.join(timeout=1)
        self.socket.close()

    def serve(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ident, flags, qdcount, _, _, _ = struct.unpack("!6H", packet[:12])
                if qdcount != 1:
                    raise ValueError("expected exactly one DNS question")
                offset, labels = 12, []
                while packet[offset]:
                    length = packet[offset]
                    if length >= 64:
                        raise ValueError("unexpected compressed DNS question")
                    offset += 1
                    labels.append(packet[offset:offset + length].decode("ascii"))
                    offset += length
                offset += 1
                qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
                offset += 4
                name = ".".join(labels).lower()
                self.questions.append((name, qtype))
                address = None
                rcode = 0
                if name == "good.example.com":
                    if qtype == 1:
                        address = "192.0.2.10"
                elif name == "other.example.org":
                    if qtype == 1:
                        address = "192.0.2.11"
                elif name == "nodata.example.com":
                    pass  # Deliberate NOERROR with no A or AAAA records.
                elif name == "example.net" or name.endswith(".example.net"):
                    if qtype == 1:
                        address = "198.51.100.44"  # Wildcard root and random labels.
                else:
                    rcode = 3  # NXDOMAIN, including nx.example.com.
                answer = b""
                if address is not None:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, qclass, 60, 4) + socket.inet_aton(address)
                header = struct.pack("!6H", ident, 0x8480 | (flags & 0x0100) | rcode,
                                     1, int(address is not None), 0, 0)
                self.socket.sendto(header + packet[12:offset] + answer, peer)
            except Exception as error:
                self.errors.append(repr(error))


@unittest.skipUnless(shutil.which("bash"), "bash required")
class DNSXRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-dnsx-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        self.bin = self.work / "bin"
        self.bin.mkdir(parents=True)
        self.dnsx = self.bin / "dnsx"
        self.dnsx.write_text(DNSX_STUB)
        self.dnsx.chmod(0o755)
        self.input = self.work / "input.txt"
        self.input.write_text("www.example.test\napi.example.test\n")
        self.words = self.work / "words.txt"
        self.words.write_text("www\napi\n")
        self.output = self.work / "results.txt"
        self.resolvers = self.work / "trusted.txt"
        self.resolvers.write_text("# Provider\n127.0.0.1:5300\n\n127.0.0.1:5300\n")
        self.capture = self.work / "capture.jsonl"
        self.env = dict(
            os.environ, REPO_ROOT=str(ROOT), PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            HOME=str(self.work / "home"), XDG_CONFIG_HOME=str(self.work / "home/config"),
            INPUT=str(self.input), WORDLIST=str(self.words), OUTPUT=str(self.output),
            CLEANED=str(self.work / "cleaned.txt"), CAPTURE=str(self.capture),
            resolvers_trusted=str(self.resolvers), DNS_RESOLVER="dnsx", DEEP="false",
            DNSX_THREADS="4", DNSX_RATE_LIMIT="1000", DNSX_RETRIES="2", DNSX_QUERY_TIMEOUT="1s",
            DNS_RESOLVE_TIMEOUT="0", DNS_BRUTE_TIMEOUT="0", TIMEOUT_CMD="",
            LOGFILE=str(self.work / "run.log"), DEBUG_LOG=str(self.work / "debug.log"),
            OUTPUT_VERBOSITY="0", DRY_RUN="false", DNSX_EXIT="0", DNSX_DELAY="0",
            DNSX_FIXTURE="www.example.test\napi.example.test\nwww.example.test\n",
        )

    def run_helper(self, command='_resolve_domains "$INPUT" "$OUTPUT"', **settings):
        return subprocess.run(
            ["bash", "-c", HARNESS + "\n" + command], cwd=self.work,
            env=dict(self.env, **settings), text=True, capture_output=True, timeout=15,
        )

    def records(self):
        return [json.loads(line) for line in self.capture.read_text().splitlines()] if self.capture.exists() else []

    def temporary_files(self):
        return sorted(path.name for path in self.work.glob("results.txt.*"))

    def test_resolver_comments_crlf_blank_lines_duplicates_and_endpoints(self):
        original = (b"# comment\r\n \t# indented\r\n\r\n  127.0.0.1:5300  \r\n"
                    b"127.0.0.1:5300 # duplicate\r\n"
                    b"https://dns.example.test/dns-query#fragment # custom endpoint\r\n"
                    b"tcp:127.0.0.1:5353\r\n[::1]:5353\r\n")
        self.resolvers.write_bytes(original)
        result = self.run_helper('_prepare_dnsx_resolvers "$CLEANED"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "cleaned.txt").read_text(),
                         "127.0.0.1:5300\nhttps://dns.example.test/dns-query#fragment\ntcp:127.0.0.1:5353\n[::1]:5353\n")
        self.assertEqual(self.resolvers.read_bytes(), original)
        self.assertFalse(self.capture.exists())

    def test_comment_only_resolver_list_is_rejected_without_running_tool(self):
        self.resolvers.write_text("# comments only\n \t# more\n\n")
        self.output.write_text("previous.example.test\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("No usable DNSX resolver", result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        self.assertFalse(self.capture.exists())
        self.assertEqual(self.temporary_files(), [])

    def test_success_uses_clean_private_resolvers_fresh_raw_and_safe_flags(self):
        original = self.resolvers.read_bytes()
        self.output.write_text("previous.example.test\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.records()[0]
        self.assertEqual(record["resolvers"], "127.0.0.1:5300\n")
        self.assertTrue(record["raw_existed"])
        self.assertEqual(record["raw_before"], "")
        self.assertNotEqual(record["raw"], str(self.output))
        self.assertNotEqual(record["resolver_file"], str(self.resolvers))
        self.assertEqual(self.resolvers.read_bytes(), original)
        args = record["args"]
        for flag in ("-a", "-auto-wildcard", "-duc", "-nc"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("-rcode") + 1], "noerror")
        self.assertEqual(args[args.index("-ot") + 1], "{{host}}")
        self.assertEqual(args[args.index("-timeout") + 1], "1s")
        self.assertEqual(args[args.index("-retry") + 1], "2")
        self.assertEqual(self.output.read_text(), "api.example.test\nwww.example.test\n")
        self.assertEqual(self.temporary_files(), [])

    def test_repeated_runs_do_not_reuse_appended_output_or_temp_names(self):
        for fixture in ("first.example.test\n", "second.example.test\n"):
            result = self.run_helper(DNSX_FIXTURE=fixture)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.output.read_text(), fixture)
        records = self.records()
        self.assertNotEqual(records[0]["raw"], records[1]["raw"])
        self.assertNotEqual(records[0]["resolver_file"], records[1]["resolver_file"])
        self.assertTrue(all(record["raw_before"] == "" for record in records))
        self.assertEqual(self.temporary_files(), [])

    def test_successful_empty_result_replaces_previous_output(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper(DNSX_FIXTURE="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "")
        self.assertEqual(self.temporary_files(), [])

    def test_failed_tool_preserves_status_previous_output_and_partial_diagnostics(self):
        for code in (7, 124, 137):
            with self.subTest(code=code):
                self.output.write_text("previous.example.test\n")
                result = self.run_helper(DNSX_EXIT=str(code), DNSX_FIXTURE="partial.example.test\n")
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertEqual(self.output.read_text(), "previous.example.test\n")
                record = self.records()[-1]
                self.assertEqual(Path(record["raw"]).read_text(), "partial.example.test\n")
                self.assertFalse(Path(record["resolver_file"]).exists())

    def test_empty_failed_output_is_cleaned(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper(DNSX_EXIT="9", DNSX_FIXTURE="")
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        self.assertEqual(self.temporary_files(), [])

    def test_sort_failure_preserves_prior_output_and_exact_exit_status(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper('sort() { return 42; }; _resolve_domains "$INPUT" "$OUTPUT"')
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        record = self.records()[0]
        self.assertEqual(Path(record["raw"]).read_text(), self.env["DNSX_FIXTURE"])
        self.assertFalse(Path(record["resolver_file"]).exists())

    def test_rename_failure_preserves_prior_output_and_sorted_diagnostics(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper('mv() { return 43; }; _resolve_domains "$INPUT" "$OUTPUT"')
        self.assertEqual(result.returncode, 43, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        record = self.records()[0]
        self.assertEqual(Path(record["raw"]).read_text(), "api.example.test\nwww.example.test\n")
        self.assertFalse(Path(record["resolver_file"]).exists())

    def test_destination_directory_is_rejected_without_moving_output_into_it(self):
        self.output.mkdir()
        saved = self.output / "existing.txt"
        saved.write_text("preserve directory contents\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.output.iterdir()), [saved])
        self.assertEqual(saved.read_text(), "preserve directory contents\n")
        record = self.records()[0]
        self.assertEqual(Path(record["raw"]).read_text(), "api.example.test\nwww.example.test\n")
        self.assertFalse(Path(record["resolver_file"]).exists())

    @unittest.skipUnless(TIMEOUT, "GNU timeout required")
    def test_genuine_timeout_preserves_124_and_previous_output(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper(
            TIMEOUT_CMD=TIMEOUT, DNS_RESOLVE_TIMEOUT="0.1s", DNSX_DELAY="30",
            DNSX_FIXTURE="partial.example.test\n",
        )
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        self.assertFalse(list(self.work.glob("results.txt.resolvers.*")))

    def test_bruteforce_helper_preserves_status_and_does_not_publish_partial_output(self):
        self.output.write_text("previous.example.test\n")
        result = self.run_helper('_bruteforce_domains "$WORDLIST" example.test "$OUTPUT"', DNSX_EXIT="124")
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        args = self.records()[0]["args"]
        self.assertEqual(args[args.index("-d") + 1], "example.test")
        self.assertEqual(args[args.index("-w") + 1], str(self.words))

    def test_dry_run_preserves_files_and_does_not_create_private_copies(self):
        self.output.write_text("previous.example.test\n")
        original = self.resolvers.read_bytes()
        result = self.run_helper(DRY_RUN="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "previous.example.test\n")
        self.assertEqual(self.resolvers.read_bytes(), original)
        self.assertFalse(self.capture.exists())
        self.assertEqual(self.temporary_files(), [])

    def test_temporary_file_failure_does_not_run_dnsx(self):
        result = self.run_helper('mktemp() { return 1; }; _resolve_domains "$INPUT" "$OUTPUT"')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertEqual(self.temporary_files(), [])

    def test_second_temporary_file_failure_removes_private_resolvers(self):
        result = self.run_helper(r'''
mktemp() {
    case "$1" in *.dnsx.raw.*) return 1 ;; *) command mktemp "$@" ;; esac
}
_resolve_domains "$INPUT" "$OUTPUT"
''')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertEqual(self.temporary_files(), [])

    @unittest.skipUnless(REAL_DNSX, "installed DNSX required for loopback integration")
    def test_real_dnsx_filters_nodata_nxdomain_and_wildcards_on_loopback(self):
        try:
            fixture = LoopbackDNS()
        except OSError as error:
            self.skipTest("UDP loopback unavailable: " + str(error))
        self.dnsx.write_text('#!/usr/bin/env bash\nexec "$REAL_DNSX" "$@"\n')
        self.input.write_text("good.example.com\nnodata.example.com\nnx.example.com\n"
                              "wild1.example.net\nwild2.example.net\nother.example.org\n")
        with fixture:
            self.resolvers.write_text("# loopback only\n" + fixture.endpoint + "\n" + fixture.endpoint + "\n")
            result = self.run_helper(
                REAL_DNSX=str(Path(REAL_DNSX).resolve()), DNSX_RETRIES="1", DNSX_QUERY_TIMEOUT="0.2s",
                PDCP_API_KEY="", PDCP_API_SERVER="http://127.0.0.1:9",
                HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                ALL_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost",
            )
        log = (self.work / "debug.log").read_text() if (self.work / "debug.log").exists() else ""
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + log)
        self.assertEqual(fixture.errors, [])
        self.assertEqual(set(self.output.read_text().splitlines()), {"good.example.com", "other.example.org"})
        nx_questions = [qtype for name, qtype in fixture.questions if name == "nx.example.com"]
        self.assertTrue(nx_questions)
        self.assertEqual(set(nx_questions), {1}, "NXDOMAIN must not trigger extra AAAA wildcard work")
        self.assertTrue(any(name.endswith(".example.net") and name not in {"wild1.example.net", "wild2.example.net"}
                            for name, _ in fixture.questions), "wildcard probes should actually run")
        self.assertEqual(self.temporary_files(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
