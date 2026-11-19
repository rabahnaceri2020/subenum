#!/usr/bin/env python3
"""Offline tests for deep-only stages and single-pass DNS bruteforce results."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEEP_STAGES = {
    "sub_permut": "SUBPERMUTE",
    "sub_regex_permut": "SUBREGEXPERMUTE",
    "sub_ia_permut": "SUBIAPERMUTE",
    "sub_ns_delegation": "NS_DELEGATION",
}
HARNESS = r'''
set -o pipefail
set +e
SCRIPTPATH="$REPO_ROOT"
source "$SCRIPTPATH/lib/common.sh"
source "$SCRIPTPATH/modules/core.sh"
source "$SCRIPTPATH/modules/utils.sh"
source "$SCRIPTPATH/modules/subdomains.sh"

_method_selected() {
    [[ -z "${ONLY_METHODS:-}" ]] || [[ ",${ONLY_METHODS}," == *",$1,"* ]]
}
_print_msg() { printf '%s %s\n' "$1" "$2"; }
_print_status() { printf '%s %s\n' "$1" "$2"; }
print_notice() { printf '%s %s %s\n' "$1" "$2" "$3"; }
print_warnf() { printf '%s\n' "$*"; }
getElapsedTime() { :; }

_bruteforce_domains() {
    printf 'brute\n' >> "$TEST_EVENTS"
    printf '%s\n' "$1" > "$WORDLIST_USED"
    if [[ "${BRUTE_NO_WRITE:-false}" != "true" ]]; then
        printf '%s' "$BRUTE_FIXTURE" > "$3"
    fi
    return "${BRUTE_EXIT:-0}"
}
_resolve_domains() {
    printf 'resolve\n' >> "$TEST_EVENTS"
    if [[ "${RESOLVE_NO_WRITE:-false}" != "true" ]]; then
        if [[ "${RESOLVE_USE_FIXTURE:-false}" == "true" ]]; then
            printf '%s' "$RESOLVE_FIXTURE" > "$2"
        else
            cp -- "$1" "$2"
        fi
    fi
    return "${RESOLVE_EXIT:-0}"
}
_generate_permutation_candidates() {
    printf 'generate\n' >> "$TEST_EVENTS"
    printf '%s\n' 'permut.example.test' > "$2"
}
subwiz() {
    printf 'subwiz\n' >> "$TEST_EVENTS"
    local output=""
    while (($#)); do
        if [[ "$1" == "-o" ]]; then output="$2"; shift 2; else shift; fi
    done
    printf '%s\n' 'ai.example.test' > "$output"
}
run_command() {
    if [[ "$1" == "$tools/regulator/venv/bin/python3" ]]; then
        printf 'regulator\n' >> "$TEST_EVENTS"
        local output=""
        while (($#)); do
            if [[ "$1" == "-o" ]]; then output="$2"; shift 2; else shift; fi
        done
        printf '%s\n' 'regex.example.test' > "$output"
    elif [[ "$1" == "subwiz" || "$1" == "dnsx" ]]; then
        "$@"
    else
        printf 'Unexpected external command: %s\n' "$1" >&2
        return 99
    fi
}
_run_timed_command() { shift; "$@"; }
dnsx() {
    printf 'dnsx\n' >> "$TEST_EVENTS"
    while IFS= read -r host; do :; done
    printf '%s' "$DNSX_FIXTURE"
}
tlsx() {
    printf 'tlsx\n' >> "$TEST_EVENTS"
    while IFS= read -r host; do :; done
    local output=""
    while (($#)); do
        if [[ "$1" == "-o" ]]; then output="$2"; shift 2; else shift; fi
    done
    if [[ "${TLS_NO_WRITE:-false}" != "true" ]]; then
        if [[ -n "$output" ]]; then
            printf '%s' "$TLS_FIXTURE" > "$output"
        else
            printf '%s' "$TLS_FIXTURE"
        fi
    fi
    return "${TLS_EXIT:-0}"
}
dig() { printf 'Unexpected dig call\n' >&2; return 99; }
check_inscope() {
    printf 'inscope\n' >> "$TEST_EVENTS"
    [[ "${SCOPE_EXIT:-0}" == "0" ]] || return "$SCOPE_EXIT"
    printf '%s' "$SCOPE_FIXTURE" > "$1"
}
anew() {
    python3 -c '
from pathlib import Path
import sys
quiet = sys.argv[1] == "-q"
p = Path(sys.argv[2] if quiet else sys.argv[1])
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


@unittest.skipUnless(shutil.which("bash"), "bash required")
class FastStageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-fast-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        for name in (".tmp", "subdomains", ".called_fn", "tools/regulator/venv/bin"):
            (self.work / name).mkdir(parents=True, exist_ok=True)
        regulator = self.work / "tools/regulator"
        (regulator / "main.py").write_text("# Fixture only; never executed.\n")
        (regulator / "venv/bin/python3").write_text("#!/bin/sh\nexit 99\n")
        (regulator / "venv/bin/python3").chmod(0o755)
        self.input = self.work / "subdomains/subdomains.txt"
        self.input.write_text("seed.example.test\n")
        self.words = self.work / "words.txt"
        self.words.write_text("www\napi\n")
        self.big_words = self.work / "words-big.txt"
        self.big_words.write_text("www\napi\ndev\n")
        self.events = self.work / "events.txt"
        self.wordlist_used = self.work / "wordlist-used.txt"
        self.raw = self.work / ".tmp/subs_brute.txt"
        self.valid = self.work / ".tmp/subs_brute_valid.txt"
        self.env = dict(
            os.environ,
            REPO_ROOT=str(ROOT),
            TEST_EVENTS=str(self.events),
            WORDLIST_USED=str(self.wordlist_used),
            LOGFILE=str(self.work / "run.log"),
            called_fn_dir=str(self.work / ".called_fn"),
            dir=str(self.work),
            tools=str(self.work / "tools"),
            domain="example.test",
            DOMAIN_MATCH_REGEX=r"(^|\.)example\.test$",
            resolvers_trusted=str(self.work / "resolvers.txt"),
            subs_wordlist=str(self.words),
            subs_wordlist_big=str(self.big_words),
            outOfScope_file="",
            ONLY_METHODS="",
            DEEP="false",
            DIFF="false",
            DRY_RUN="false",
            INSCOPE="false",
            SUBBRUTE="true",
            SUBPERMUTE="true",
            SUBREGEXPERMUTE="true",
            SUBIAPERMUTE="true",
            NS_DELEGATION="true",
            NS_AXFR_MAX="50",
            OUTPUT_VERBOSITY="1",
            DEEP_LIMIT="500",
            DEEP_LIMIT2="1500",
            BRUTE_EXIT="0",
            BRUTE_NO_WRITE="false",
            BRUTE_FIXTURE="www.example.test\napi.example.test\noutside.test\n",
            RESOLVE_EXIT="0",
            RESOLVE_NO_WRITE="false",
            RESOLVE_USE_FIXTURE="false",
            RESOLVE_FIXTURE="partial.example.test\n",
            DNSX_FIXTURE="example.test [ns1.provider.test]\n",
            RESOLVER_IQ="false",
            TLSX_THREADS="10",
            TLS_PORTS="443",
            TLS_FIXTURE="tls.example.test\n",
            TLS_EXIT="0",
            TLS_NO_WRITE="false",
            SCOPE_EXIT="0",
            SCOPE_FIXTURE="api.example.test\n",
        )

    def run_stage(self, method, extra="", **settings):
        return subprocess.run(
            ["bash", "-c", HARNESS + "\n" + extra + "\n" + method],
            cwd=self.work, env=dict(self.env, **settings), text=True,
            capture_output=True, timeout=10,
        )

    def checkpoint(self, method):
        return self.work / ".called_fn" / ("." + method)

    def status(self, method):
        return (self.work / ".called_fn" / (".status_" + method)).read_text().strip()

    def event_lines(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def assert_mode_skip(self, method, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SKIP " + method, result.stdout)
        self.assertEqual(self.event_lines(), [])
        self.assertFalse(self.checkpoint(method).exists())
        reason = self.work / ".called_fn" / (".status_reason_" + method)
        self.assertEqual(reason.read_text().strip(), "mode")

    def test_all_expensive_stages_skip_normal_mode(self):
        for method in DEEP_STAGES:
            with self.subTest(method=method):
                self.assert_mode_skip(method, self.run_stage(method))
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertFalse((self.work / "subdomains/ns_delegated_zones.txt").exists())

    def test_unset_deep_defaults_to_skipping(self):
        for method in DEEP_STAGES:
            with self.subTest(method=method):
                self.assert_mode_skip(method, self.run_stage(method, extra="unset DEEP"))

    def test_forced_normal_mode_still_skips(self):
        for method in DEEP_STAGES:
            with self.subTest(method=method):
                self.assert_mode_skip(method, self.run_stage(method, DIFF="true"))

    def test_deep_mode_respects_explicit_method_selection(self):
        for method in DEEP_STAGES:
            with self.subTest(method=method):
                self.assert_mode_skip(method, self.run_stage(method, DEEP="true", ONLY_METHODS="sub_brute"))

    def test_deep_mode_respects_existing_enable_flags(self):
        for method, flag in DEEP_STAGES.items():
            with self.subTest(method=method):
                result = self.run_stage(method, DEEP="true", **{flag: "false"})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.event_lines(), [])
                self.assertFalse(self.checkpoint(method).exists())
                reason = self.work / ".called_fn" / (".status_reason_" + method)
                self.assertEqual(reason.read_text().strip(), "config")

    def test_default_skips_do_not_block_later_deep_execution(self):
        for method in DEEP_STAGES:
            with self.subTest(method=method):
                before = len(self.event_lines())
                skipped = self.run_stage(method)
                self.assertEqual(skipped.returncode, 0, skipped.stdout + skipped.stderr)
                self.assertFalse(self.checkpoint(method).exists())
                result = self.run_stage(method, DEEP="true")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertGreater(len(self.event_lines()), before)
                self.assertTrue(self.checkpoint(method).exists())
                self.assertEqual(self.status(method), "OK")

    def test_brute_uses_validated_results_without_another_dns_pass(self):
        result = self.run_stage("sub_brute")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.event_lines(), ["brute"])
        self.assertEqual(self.wordlist_used.read_text().strip(), str(self.words))
        self.assertEqual(self.valid.read_text(), self.raw.read_text())
        self.assertEqual(set(self.input.read_text().splitlines()), {
            "seed.example.test", "www.example.test", "api.example.test",
        })
        self.assertEqual(self.status("sub_brute"), "OK")

    def test_deep_brute_retains_big_wordlist_choice(self):
        result = self.run_stage("sub_brute", DEEP="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.wordlist_used.read_text().strip(), str(self.big_words))
        self.assertEqual(self.event_lines(), ["brute"])

    def test_empty_brute_result_clears_stale_candidates(self):
        self.raw.write_text("stale-raw.example.test\n")
        self.valid.write_text("stale-valid.example.test\n")
        result = self.run_stage("sub_brute", BRUTE_FIXTURE="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.raw.read_text(), "")
        self.assertEqual(self.valid.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["brute"])

    def test_tool_success_without_output_does_not_reuse_old_results(self):
        self.raw.write_text("stale-raw.example.test\n")
        self.valid.write_text("stale-valid.example.test\n")
        result = self.run_stage("sub_brute", BRUTE_NO_WRITE="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.valid.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["brute"])

    def test_failed_brute_discards_partial_candidates_and_remains_retryable(self):
        self.raw.write_text("stale-raw.example.test\n")
        self.valid.write_text("stale-valid.example.test\n")
        self.checkpoint("sub_brute").touch()
        result = self.run_stage("sub_brute", BRUTE_EXIT="124", DIFF="true")
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(self.valid.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["brute"])
        self.assertEqual(self.status("sub_brute"), "FAIL")
        self.assertFalse(self.checkpoint("sub_brute").exists())
        retry = self.run_stage("sub_brute")
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertTrue(self.checkpoint("sub_brute").exists())

    def test_missing_wordlist_is_retryable_and_clears_stale_candidates(self):
        self.words.write_text("")
        self.raw.write_text("stale-raw.example.test\n")
        self.valid.write_text("stale-valid.example.test\n")
        result = self.run_stage("sub_brute")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.raw.read_text(), "")
        self.assertEqual(self.valid.read_text(), "")
        self.assertFalse(self.checkpoint("sub_brute").exists())
        self.assertEqual(self.status("sub_brute"), "SKIP")
        self.assertEqual(self.event_lines(), [])

    def test_scratch_reset_failure_reports_failure_before_running_tool(self):
        self.valid.mkdir()
        result = self.run_stage("sub_brute")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status("sub_brute"), "FAIL")
        self.assertFalse(self.checkpoint("sub_brute").exists())
        self.assertEqual(self.event_lines(), [])

    def test_copy_failure_does_not_publish_results(self):
        result = self.run_stage("sub_brute", extra="cp() { return 1; }")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.status("sub_brute"), "FAIL")
        self.assertFalse(self.checkpoint("sub_brute").exists())

    def test_scope_filter_still_applies_without_extra_resolution(self):
        result = self.run_stage("sub_brute", INSCOPE="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.event_lines(), ["brute", "inscope"])
        self.assertEqual(set(self.input.read_text().splitlines()), {"seed.example.test", "api.example.test"})

    def test_scope_failure_is_retryable(self):
        result = self.run_stage("sub_brute", INSCOPE="true", SCOPE_EXIT="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.status("sub_brute"), "FAIL")
        self.assertFalse(self.checkpoint("sub_brute").exists())

    def test_active_resolution_timeout_does_not_publish_stale_or_partial_results(self):
        (self.work / ".tmp/passive_subs.txt").write_text("fresh.example.test\n")
        scratch = self.work / ".tmp/subdomains_tmp.txt"
        scratch.write_text("stale.example.test\n")
        self.checkpoint("sub_active").touch()
        result = self.run_stage("sub_active", DIFF="true", RESOLVE_EXIT="124", RESOLVE_USE_FIXTURE="true")
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(scratch.read_text(), "partial.example.test\n")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["resolve"])
        self.assertEqual(self.status("sub_active"), "FAIL")
        self.assertFalse(self.checkpoint("sub_active").exists())
        retry = self.run_stage("sub_active", DNSX_FIXTURE="")
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(set(self.input.read_text().splitlines()), {"seed.example.test", "fresh.example.test"})
        self.assertTrue(self.checkpoint("sub_active").exists())

    def test_active_empty_resolution_cannot_reuse_old_output(self):
        (self.work / ".tmp/passive_subs.txt").write_text("fresh.example.test\n")
        scratch = self.work / ".tmp/subdomains_tmp.txt"
        scratch.write_text("stale.example.test\n")
        result = self.run_stage("sub_active", RESOLVE_NO_WRITE="true", DNSX_FIXTURE="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(scratch.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")

    def test_active_output_reset_failure_is_retryable(self):
        (self.work / ".tmp/subdomains_tmp.txt").mkdir()
        result = self.run_stage("sub_active")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status("sub_active"), "FAIL")
        self.assertFalse(self.checkpoint("sub_active").exists())
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), [])

    def test_tls_resolution_timeout_does_not_publish_stale_or_partial_results(self):
        scratch = self.work / ".tmp/subdomains_tlsx_resolved.txt"
        scratch.write_text("stale.example.test\n")
        self.checkpoint("sub_tls").touch()
        result = self.run_stage("sub_tls", DIFF="true", RESOLVE_EXIT="124", RESOLVE_USE_FIXTURE="true")
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(scratch.read_text(), "partial.example.test\n")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["tlsx", "resolve"])
        self.assertEqual(self.status("sub_tls"), "FAIL")
        self.assertFalse(self.checkpoint("sub_tls").exists())
        retry = self.run_stage("sub_tls")
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(set(self.input.read_text().splitlines()), {"seed.example.test", "tls.example.test"})
        self.assertTrue(self.checkpoint("sub_tls").exists())

    def test_tls_collection_timeout_is_retryable_without_resolving_partial_output(self):
        result = self.run_stage("sub_tls", TLS_EXIT="124")
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["tlsx"])
        self.assertEqual(self.status("sub_tls"), "FAIL")
        self.assertFalse(self.checkpoint("sub_tls").exists())

    def test_tls_empty_collection_clears_all_stale_stage_files(self):
        files = [self.work / (".tmp/subdomains_tlsx" + suffix + ".txt") for suffix in ("", "_clean", "_resolved")]
        for path in files:
            path.write_text("stale.example.test\n")
        result = self.run_stage("sub_tls", DEEP="true", TLS_NO_WRITE="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in files:
            self.assertEqual(path.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), ["tlsx"])

    def test_tls_empty_resolution_cannot_reuse_old_output(self):
        scratch = self.work / ".tmp/subdomains_tlsx_resolved.txt"
        scratch.write_text("stale.example.test\n")
        result = self.run_stage("sub_tls", RESOLVE_NO_WRITE="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(scratch.read_text(), "")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")

    def test_tls_output_reset_failure_is_retryable(self):
        (self.work / ".tmp/subdomains_tlsx_resolved.txt").mkdir()
        result = self.run_stage("sub_tls")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.status("sub_tls"), "FAIL")
        self.assertFalse(self.checkpoint("sub_tls").exists())
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), [])

    def test_active_and_tls_dry_run_preserve_saved_output(self):
        for method, basename in (("sub_active", "subdomains_tmp"), ("sub_tls", "subdomains_tlsx_resolved")):
            with self.subTest(method=method):
                scratch = self.work / (".tmp/" + basename + ".txt")
                scratch.write_text("stale.example.test\n")
                result = self.run_stage(method, DRY_RUN="true")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(scratch.read_text(), "stale.example.test\n")
                self.assertEqual(self.input.read_text(), "seed.example.test\n")
                self.assertEqual(self.event_lines(), [])
                self.assertFalse(self.checkpoint(method).exists())

    def test_dry_run_does_not_reuse_or_replace_saved_candidates(self):
        self.raw.write_text("stale-raw.example.test\n")
        self.valid.write_text("stale-valid.example.test\n")
        result = self.run_stage("sub_brute", DRY_RUN="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.raw.read_text(), "stale-raw.example.test\n")
        self.assertEqual(self.valid.read_text(), "stale-valid.example.test\n")
        self.assertEqual(self.input.read_text(), "seed.example.test\n")
        self.assertEqual(self.event_lines(), [])
        self.assertFalse(self.checkpoint("sub_brute").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
