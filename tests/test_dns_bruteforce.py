#!/usr/bin/env python3
"""Offline regressions for file-based PureDNS bruteforce under piped stdin."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REAL_PUREDNS = shutil.which("puredns")
HARNESS = r'''
set -o pipefail
set +e
SCRIPTPATH="$REPO_ROOT"
source "$SCRIPTPATH/lib/common.sh"
source "$SCRIPTPATH/modules/utils.sh"
sleep() { command sleep 0.01; }
'''
PUREDNS_STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import stat
import sys

args = sys.argv[1:]
assert args[0] == "bruteforce", args
piped = stat.S_ISFIFO(os.fstat(0).st_mode)
# Mirrors PureDNS v2.1.1 parseBruteforceArgs: a pipe takes precedence over args.
if piped:
    domain = args[1]
    words = sys.stdin.read().splitlines()
    source = "stdin"
else:
    domain = args[2]
    source = args[1]
    words = Path(source).read_text().splitlines()
Path(os.environ["CAPTURE"]).write_text(json.dumps({
    "args": args, "piped": piped, "domain": domain, "source": source, "words": words,
}))
code = int(os.environ.get("MOCK_EXIT", "0"))
if code:
    sys.exit(code)
output = Path(args[args.index("-w") + 1])
output.write_text("".join(word + "." + domain + "\n" for word in words))
'''


@unittest.skipUnless(shutil.which("bash"), "bash required")
class PureDNSBruteforceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-brute-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        self.bin = self.work / "bin"
        self.bin.mkdir(parents=True)
        stub = self.bin / "puredns"
        stub.write_text(PUREDNS_STUB)
        stub.chmod(0o755)
        self.words = self.work / "short words.txt"
        self.words.write_text("www\napi\n")
        self.resolvers = self.work / "resolvers.txt"
        self.resolvers.write_text("127.0.0.1\n")
        self.output = self.work / "resolved.txt"
        self.capture = self.work / "capture.json"
        self.env = dict(
            os.environ,
            REPO_ROOT=str(ROOT),
            PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            WORDLIST=str(self.words),
            TARGET_DOMAIN="example.test",
            OUTPUT=str(self.output),
            CAPTURE=str(self.capture),
            DNS_RESOLVER="puredns",
            resolvers=str(self.resolvers),
            resolvers_trusted=str(self.resolvers),
            PUREDNS_PUBLIC_LIMIT="5000",
            PUREDNS_TRUSTED_LIMIT="400",
            PUREDNS_WILDCARDTEST_LIMIT="30",
            PUREDNS_WILDCARDBATCH_LIMIT="1500000",
            DNS_BRUTE_TIMEOUT="0",
            DNS_HEARTBEAT_INTERVAL_SECONDS="20",
            TIMEOUT_CMD="",
            OUTPUT_VERBOSITY="0",
            LOGFILE=str(self.work / "run.log"),
            DEBUG_LOG=str(self.work / "debug.log"),
            DRY_RUN="false",
            MOCK_EXIT="0",
        )

    def run_helper(self, extra="", invocation=None, stdin="", **settings):
        if invocation is None:
            invocation = '_bruteforce_domains "$WORDLIST" "$TARGET_DOMAIN" "$OUTPUT"'
        return subprocess.run(
            ["bash", "-c", HARNESS + "\n" + extra + "\n" + invocation],
            cwd=self.work, env=dict(self.env, **settings), input=stdin,
            text=True, capture_output=True, timeout=10,
        )

    def assert_file_input(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.capture.read_text())
        self.assertFalse(record["piped"])
        self.assertEqual(record["domain"], "example.test")
        self.assertEqual(record["source"], str(self.words))
        self.assertEqual(record["words"], ["www", "api"])
        self.assertEqual(self.output.read_text(), "www.example.test\napi.example.test\n")
        self.assertEqual(record["args"][1:3], [str(self.words), "example.test"])

    def test_file_arguments_are_used_with_empty_parent_stdin(self):
        self.assert_file_input(self.run_helper())

    def test_file_arguments_are_used_with_piped_input(self):
        invocation = 'printf "unrelated\\n" | _bruteforce_domains "$WORDLIST" "$TARGET_DOMAIN" "$OUTPUT"'
        self.assert_file_input(self.run_helper(invocation=invocation))

    def test_file_arguments_are_used_with_explicit_fifo_redirection(self):
        invocation = '_bruteforce_domains "$WORDLIST" "$TARGET_DOMAIN" "$OUTPUT" < <(printf "unrelated\\n")'
        self.assert_file_input(self.run_helper(invocation=invocation))

    def test_job_control_does_not_enable_stdin_mode(self):
        self.assert_file_input(self.run_helper(extra="set -m", stdin="unrelated\n"))

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required")
    def test_timeout_wrapper_preserves_file_input(self):
        invocation = '_bruteforce_domains "$WORDLIST" "$TARGET_DOMAIN" "$OUTPUT" < <(printf "unrelated\\n")'
        result = self.run_helper(
            invocation=invocation, DNS_BRUTE_TIMEOUT="2s", TIMEOUT_CMD=shutil.which("timeout"),
        )
        self.assert_file_input(result)

    @unittest.skipUnless(REAL_PUREDNS, "installed puredns required")
    def test_real_puredns_with_offline_massdns_backend(self):
        # Exercise the installed binary and real argument parser without DNS traffic.
        massdns = self.bin / "massdns-offline"
        massdns.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
if "--help" in sys.argv:
    sys.exit(0)
names = [line.strip() for line in sys.stdin if line.strip()]
Path(os.environ["MASSDNS_CAPTURE"]).write_text("\\n".join(names))
output = Path(sys.argv[sys.argv.index("-w") + 1])
output.write_text("".join(name.rstrip(".") + ". A 192.0.2.1\\n\\n" for name in names))
''')
        massdns.chmod(0o755)
        (self.bin / "puredns").write_text('''#!/usr/bin/env bash
exec "$REAL_PUREDNS" "$@" --bin "$MASSDNS_STUB" --skip-wildcard-filter --skip-validation
''')
        candidates = self.work / "massdns-candidates.txt"
        invocation = 'printf "" | _bruteforce_domains "$WORDLIST" "$TARGET_DOMAIN" "$OUTPUT"'
        result = self.run_helper(
            invocation=invocation, REAL_PUREDNS=str(Path(REAL_PUREDNS).resolve()),
            MASSDNS_STUB=str(massdns), MASSDNS_CAPTURE=str(candidates),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(set(candidates.read_text().splitlines()), {"www.example.test", "api.example.test"})
        self.assertEqual(set(self.output.read_text().splitlines()), {"www.example.test", "api.example.test"})

    def test_tool_failure_propagates(self):
        result = self.run_helper(MOCK_EXIT="3")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_dry_run_does_not_execute_puredns(self):
        result = self.run_helper(DRY_RUN="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
