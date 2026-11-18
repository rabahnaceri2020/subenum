#!/usr/bin/env python3
"""Offline regression tests for DNS output publication and stage checkpoints.

Run with: python3 tests/test_sub_dns.py
Only temporary fixtures are modified; DNS and resolution commands are mocked.
"""

import json
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
source "$SCRIPTPATH/modules/utils.sh"
source "$SCRIPTPATH/modules/subdomains.sh"

ensure_dirs() { mkdir -p -- "$@"; }
_method_selected() { return 0; }
_print_msg() { printf '%s %s\n' "$1" "$2"; }
_print_status() { printf '%s %s\n' "$1" "$2"; }
print_notice() { printf '%s %s %s\n' "$1" "$2" "$3"; }
skip_notification() { printf 'SKIP %s\n' "$1"; }
ui_dryrun_track() { printf 'dry-run\n' >> "$TEST_EVENTS"; }

# Emulate dnsx's append behavior, including partial writes and failure codes.
dnsx() {
    local output=""
    printf 'dnsx\n' >> "$TEST_EVENTS"
    while (($#)); do
        case "$1" in
            -o) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [[ -n "$output" && -f "$output" && ! -s "$output" ]] || return 90
    while IFS= read -r host; do :; done
    printf '%s' "$DNS_FIXTURE" >> "$output"
    return "$DNS_EXIT"
}

_resolve_domains() {
    printf 'resolve\n' >> "$TEST_EVENTS"
    cp -- "$1" "$2"
}

# A local replacement for anew keeps the test independent of installed tools.
anew() {
    python3 -c '
import pathlib, sys
quiet = sys.argv[1] == "-q"
p = pathlib.Path(sys.argv[2] if quiet else sys.argv[1])
seen = set(p.read_text().splitlines()) if p.exists() else set()
with p.open("a") as out:
    for line in sys.stdin:
        value = line.rstrip("\n")
        if value not in seen:
            seen.add(value)
            out.write(value + "\n")
            if not quiet:
                print(value)
' "$@"
}
'''


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "bash and jq required")
class DNSOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-dns-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        for directory in ("subdomains", ".tmp", ".called_fn"):
            (self.work / directory).mkdir(parents=True, exist_ok=True)
        self.input = self.work / "subdomains/subdomains.txt"
        self.input.write_text("seed.example.test\n")
        self.output = self.work / "subdomains/subdomains_dnsregs.json"
        self.old_data = json.dumps({"host": "old.example.test", "a": ["192.0.2.1"]}) + "\n"
        self.new_data = json.dumps({
            "host": "new.example.test",
            "a": ["192.0.2.2"],
            "cname": ["target.example.test"],
        }) + "\n"
        self.output.write_text(self.old_data)
        self.checkpoint = self.work / ".called_fn/.sub_dns"
        self.status = self.work / ".called_fn/.status_sub_dns"
        self.events = self.work / "events.txt"
        self.env = dict(
            os.environ,
            REPO_ROOT=str(ROOT),
            TEST_EVENTS=str(self.events),
            LOGFILE=str(self.work / "run.log"),
            DEBUG_LOG="",
            domain="example.test",
            DOMAIN_MATCH_REGEX=r"(^|\.)example\.test$",
            called_fn_dir=str(self.work / ".called_fn"),
            resolvers_trusted=str(self.work / "resolvers.txt"),
            DRY_RUN="false",
            DIFF="false",
            DEEP="false",
            INSCOPE="false",
            OUTPUT_VERBOSITY="1",
            ENRICH_MAX_SUBS="3000",
            DNS_RECON_TIMEOUT="5m",
            TIMEOUT_CMD="",
            yellow="",
            reset="",
        )

    def run_stage(self, fixture=None, exit_code=0, extra="", **settings):
        env = dict(self.env, DNS_FIXTURE=self.new_data if fixture is None else fixture,
                   DNS_EXIT=str(exit_code), **settings)
        return subprocess.run(
            ["bash", "-c", HARNESS + "\n" + extra + "\nsub_dns"],
            cwd=self.work, env=env, text=True, capture_output=True, timeout=10,
        )

    def partial_files(self):
        return list(self.output.parent.glob(self.output.name + ".tmp.*"))

    def assert_failure(self, result, exit_code):
        self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.old_data)
        self.assertFalse(self.checkpoint.exists())
        self.assertEqual(self.status.read_text().strip(), "FAIL")
        self.assertIn("FAIL sub_dns", result.stdout)
        self.assertNotIn("OK sub_dns", result.stdout)
        self.assertNotIn("parse error", result.stdout + result.stderr)
        if self.events.exists():
            self.assertNotIn("resolve", self.events.read_text().splitlines())

    def test_success_replaces_instead_of_appending(self):
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.new_data)
        self.assertEqual(self.partial_files(), [])
        self.assertTrue(self.checkpoint.exists())
        self.assertEqual(self.status.read_text().strip(), "OK")
        self.assertIn("new.example.test", self.input.read_text().splitlines())
        self.assertIn("target.example.test", self.input.read_text().splitlines())

    def test_success_replaces_a_previously_corrupted_file(self):
        self.output.write_text('{"host":"unfinished')
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.new_data)

    def test_repeated_success_does_not_accumulate_records(self):
        self.assertEqual(self.run_stage().returncode, 0)
        result = self.run_stage(DIFF="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.new_data)
        self.assertEqual(self.partial_files(), [])

    def test_timeout_preserves_previous_output_and_partial_file(self):
        partial = '{"host":"unfinished'
        result = self.run_stage(fixture=partial, exit_code=124)
        self.assert_failure(result, 124)
        self.assertIn("timed out after 5m", result.stdout)
        self.assertEqual(len(self.partial_files()), 1)
        self.assertEqual(self.partial_files()[0].read_text(), partial)

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required")
    def test_actual_timeout_retains_previous_output(self):
        # timeout launches an executable, so supply a local non-networking dnsx.
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        mock = bin_dir / "dnsx"
        mock.write_text('''#!/usr/bin/env bash
while (($#)); do
    case "$1" in
        -o) output="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s' '{"host":"unfinished' >> "$output"
exec sleep 10
''')
        mock.chmod(0o755)
        result = self.run_stage(
            TIMEOUT_CMD=shutil.which("timeout"),
            DNS_RECON_TIMEOUT="0.2s",
            PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
        )
        self.assert_failure(result, 124)
        self.assertIn("timed out after 0.2s", result.stdout)
        self.assertEqual(self.partial_files()[0].read_text(), '{"host":"unfinished')

    def test_nonzero_exit_rejects_even_valid_partial_output(self):
        result = self.run_stage(exit_code=2)
        self.assert_failure(result, 2)
        self.assertEqual(self.partial_files()[0].read_text(), self.new_data)

    def test_malformed_json_is_not_published(self):
        result = self.run_stage(fixture=self.new_data + '{"host":')
        self.assert_failure(result, 1)
        self.assertIn("Invalid DNS JSON", result.stdout)
        self.assertEqual(len(self.partial_files()), 1)

    def test_nonobject_json_is_not_published(self):
        result = self.run_stage(fixture='42\n' + self.new_data)
        self.assert_failure(result, 1)

    def test_failed_rerun_removes_old_success_checkpoint(self):
        self.checkpoint.touch()
        result = self.run_stage(exit_code=124, DIFF="true")
        self.assert_failure(result, 124)
        retry = self.run_stage()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertTrue(self.checkpoint.exists())

    def test_empty_success_does_not_reprocess_stale_candidates(self):
        for name in ("subdomains_dns.txt", "subdomains_dns_resolved.txt"):
            (self.work / ".tmp" / name).write_text("stale.example.test\n")
        result = self.run_stage(fixture="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertNotIn("resolve", self.events.read_text().splitlines())
        for name in ("subdomains_dns.txt", "subdomains_dns_resolved.txt"):
            self.assertEqual((self.work / ".tmp" / name).read_text(), "")

    def test_no_input_does_not_reprocess_saved_output(self):
        self.input.write_text("")
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.old_data)
        self.assertFalse(self.events.exists())
        self.assertEqual(self.status.read_text().strip(), "SKIP")
        self.assertEqual(self.partial_files(), [])
        self.assertFalse(self.checkpoint.exists())
        self.input.write_text("seed.example.test\n")
        self.assertEqual(self.run_stage().returncode, 0)
        self.assertEqual(self.output.read_text(), self.new_data)

    def test_dry_run_preserves_output_and_does_not_collect(self):
        result = self.run_stage(DRY_RUN="true", extra="_enrich_input() { return 7; }")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), self.old_data)
        self.assertEqual(self.partial_files(), [])
        self.assertEqual(self.events.read_text().splitlines(), ["dry-run"])
        self.assertFalse(self.checkpoint.exists())

    def test_no_input_rerun_invalidates_prior_checkpoint(self):
        self.checkpoint.touch()
        self.input.write_text("")
        result = self.run_stage(DIFF="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.checkpoint.exists())
        self.assertEqual(self.output.read_text(), self.old_data)
        self.input.write_text("seed.example.test\n")
        self.assertEqual(self.run_stage().returncode, 0)
        self.assertEqual(self.output.read_text(), self.new_data)

    def test_dry_run_rerun_preserves_prior_checkpoint(self):
        self.checkpoint.write_text("previous checkpoint\n")
        result = self.run_stage(DIFF="true", DRY_RUN="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.checkpoint.read_text(), "previous checkpoint\n")
        self.assertEqual(self.output.read_text(), self.old_data)
        self.assertEqual(self.partial_files(), [])

    def test_candidate_reset_failure_is_reported(self):
        (self.work / ".tmp/subdomains_dns.txt").mkdir()
        result = self.run_stage()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status.read_text().strip(), "FAIL")
        self.assertFalse(self.checkpoint.exists())
        # Collection was complete and valid before downstream file creation failed.
        self.assertEqual(self.output.read_text(), self.new_data)
        self.assertNotIn("resolve", self.events.read_text().splitlines())

    def test_temp_creation_failure_leaves_old_output(self):
        result = self.run_stage(extra="mktemp() { return 1; }")
        self.assert_failure(result, 1)
        self.assertEqual(self.partial_files(), [])

    def test_publish_failure_retains_valid_temporary_output(self):
        result = self.run_stage(extra="mv() { return 1; }")
        self.assert_failure(result, 1)
        self.assertEqual(self.partial_files()[0].read_text(), self.new_data)

    def test_input_failure_is_not_hidden_by_successful_dnsx(self):
        result = self.run_stage(extra="_enrich_input() { return 7; }")
        self.assert_failure(result, 7)

    def test_directory_creation_failure_is_reported(self):
        result = self.run_stage(extra="ensure_dirs() { return 1; }")
        self.assert_failure(result, 1)
        self.assertEqual(self.partial_files(), [])

    def test_destination_directory_is_not_treated_as_success(self):
        saved = self.output.with_suffix(".original")
        self.output.rename(saved)
        self.output.mkdir()
        result = self.run_stage()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(saved.read_text(), self.old_data)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.partial_files()[0].read_text(), self.new_data)
        self.assertEqual(self.status.read_text().strip(), "FAIL")
        self.assertFalse(self.checkpoint.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
