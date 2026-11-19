#!/usr/bin/env python3
"""Offline regressions for empty and populated NS delegation results.

Run with: python3 -B tests/test_ns_delegation.py
DNS queries and zone transfers are mocked; only temporary fixtures are changed.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
set -o pipefail
set +e
SCRIPTPATH="$REPO_ROOT"
source "$SCRIPTPATH/modules/core.sh"
source "$SCRIPTPATH/modules/subdomains.sh"

ensure_dirs() { mkdir -p -- "$@"; }
getElapsedTime() { :; }
_print_msg() { printf '%s %s\n' "$1" "$2"; }
_print_status() { printf '%s %s\n' "$1" "$2"; }
print_notice() { printf '%s %s %s\n' "$1" "$2" "$3"; }
skip_notification() { printf 'SKIP %s\n' "$1"; }
_run_timed_command() {
    shift
    [[ "${DRY_RUN:-false}" == "true" ]] && return 0
    "$@"
}

dnsx() {
    printf 'dnsx\n' >> "$TEST_EVENTS"
    while IFS= read -r host; do :; done
    printf '%s' "$NS_FIXTURE"
}

dig() {
    printf '%s\n' "$*" >> "$DIG_CALLS"
    printf '%s' "$AXFR_FIXTURE"
}

anew() {
    python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
seen = set(p.read_text().splitlines()) if p.exists() else set()
with p.open("a") as out:
    for line in sys.stdin:
        value = line.rstrip("\n")
        if value not in seen:
            seen.add(value)
            out.write(value + "\n")
            print(value)
' "$@"
}
'''


@unittest.skipUnless(shutil.which("bash"), "bash required")
class NSDelegationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-ns-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        for name in ("subdomains", ".tmp", ".called_fn"):
            (self.work / name).mkdir(parents=True, exist_ok=True)
        self.input = self.work / "subdomains/subdomains.txt"
        self.input.write_text("example.test\nseed.example.test\n")
        self.output = self.work / "subdomains/ns_delegated_zones.txt"
        self.status = self.work / ".called_fn/.status_sub_ns_delegation"
        self.checkpoint = self.work / ".called_fn/.sub_ns_delegation"
        self.events = self.work / "events.txt"
        self.dig_calls = self.work / "dig-calls.txt"
        self.log = self.work / "run.log"
        self.apex_only = "example.test [ns1.provider.test]\nexample.test [ns2.provider.test]\n"
        self.env = dict(
            os.environ,
            REPO_ROOT=str(ROOT),
            TEST_EVENTS=str(self.events),
            DIG_CALLS=str(self.dig_calls),
            LOGFILE=str(self.log),
            domain="example.test",
            DOMAIN_MATCH_REGEX=r"(^|\.)example\.test$",
            called_fn_dir=str(self.work / ".called_fn"),
            resolvers_trusted=str(self.work / "resolvers.txt"),
            DRY_RUN="false",
            DIFF="false",
            DEEP="false",
            NS_DELEGATION="true",
            NS_AXFR_MAX="50",
            INSCOPE="false",
            OUTPUT_VERBOSITY="1",
            ENRICH_MAX_SUBS="3000",
        )

    def run_stage(self, ns=None, axfr="", extra="", **settings):
        env = dict(self.env, NS_FIXTURE=self.apex_only if ns is None else ns,
                   AXFR_FIXTURE=axfr, **settings)
        return subprocess.run(
            ["bash", "-c", HARNESS + "\n" + extra + "\nsub_ns_delegation"],
            cwd=self.work, env=env, text=True, capture_output=True, timeout=10,
        )

    def assert_empty_result(self, result, status):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.output.is_file())
        self.assertEqual(self.output.read_text(), "")
        self.assertEqual(self.status.read_text().strip(), status)
        self.assertFalse(self.dig_calls.exists())
        self.assertEqual(result.stderr, "")
        self.assertNotIn("No such file or directory", self.log.read_text())

    def test_apex_only_records_publish_empty_artifact_and_zero_count(self):
        result = self.run_stage()
        self.assert_empty_result(result, "OK")
        self.assertIn("0 new subs (ns delegation, 0 delegated zones)", self.log.read_text())

    def test_no_ns_records_publish_empty_artifact(self):
        result = self.run_stage(ns="")
        self.assert_empty_result(result, "SKIP")
        self.assertIn("0 new subs (ns delegation - no NS records)", self.log.read_text())

    def test_apex_only_run_clears_stale_delegated_output(self):
        self.output.write_text("old.example.test\nolder.example.test\n")
        result = self.run_stage()
        self.assert_empty_result(result, "OK")
        self.assertIn("0 delegated zones", self.log.read_text())

    def test_empty_ns_run_clears_stale_delegated_output(self):
        self.output.write_text("old.example.test\n")
        result = self.run_stage(ns="")
        self.assert_empty_result(result, "SKIP")

    def test_no_input_clears_stale_delegated_output_without_queries(self):
        self.input.write_text("")
        self.output.write_text("old.example.test\n")
        result = self.run_stage()
        self.assert_empty_result(result, "SKIP")
        self.assertFalse(self.events.exists())

    def test_delegated_zones_are_deduplicated_and_axfr_hosts_added(self):
        self.output.write_text("old.example.test\n")
        ns = self.apex_only + (
            "child.example.test [ns1.provider.test]\n"
            "child.example.test [ns2.provider.test]\n"
        )
        axfr = "www.child.example.test.\n192.0.2.1\noutside.test.\n"
        result = self.run_stage(ns=ns, axfr=axfr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.output.read_text(), "child.example.test\n")
        self.assertEqual(self.status.read_text().strip(), "OK")
        self.assertEqual(self.dig_calls.read_text().splitlines(), [
            "+time=3 +tries=1 axfr child.example.test @ns1.provider.test +short",
            "+time=3 +tries=1 axfr child.example.test @ns2.provider.test +short",
        ])
        hosts = self.input.read_text().splitlines()
        self.assertIn("www.child.example.test", hosts)
        self.assertNotIn("outside.test", hosts)
        self.assertNotIn("192.0.2.1", hosts)
        self.assertIn("1 new subs (ns delegation, 1 delegated zones)", self.log.read_text())

    def test_output_reset_failure_reports_fail_before_queries(self):
        self.output.mkdir()
        result = self.run_stage()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status.read_text().strip(), "FAIL")
        self.assertFalse(self.checkpoint.exists())
        self.assertFalse(self.events.exists())
        self.assertFalse(self.dig_calls.exists())
        self.assertIn("Failed to reset NS delegated-zone output", self.log.read_text())
        self.assertNotIn("OK sub_ns_delegation", result.stdout)

    def test_sort_write_failure_reports_fail(self):
        self.checkpoint.touch()
        result = self.run_stage(
            ns="child.example.test [ns1.provider.test]\n",
            extra="sort() { return 1; }",
            DIFF="true",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status.read_text().strip(), "FAIL")
        self.assertFalse(self.checkpoint.exists())
        self.assertIn("Failed to write NS delegated-zone output", self.log.read_text())
        self.assertNotIn("OK sub_ns_delegation", result.stdout)

    def test_dry_run_preserves_existing_output(self):
        self.output.write_text("old.example.test\n")
        result = self.run_stage(DRY_RUN="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "old.example.test\n")
        self.assertFalse(self.events.exists())
        self.assertFalse(self.dig_calls.exists())
        self.assertFalse(self.checkpoint.exists())

    def test_disabled_stage_preserves_existing_output(self):
        self.output.write_text("old.example.test\n")
        result = self.run_stage(NS_DELEGATION="false")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "old.example.test\n")
        self.assertFalse(self.events.exists())
        self.assertFalse(self.dig_calls.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
