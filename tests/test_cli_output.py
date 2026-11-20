#!/usr/bin/env python3
"""Offline tests for concise terminal output without losing scan bookkeeping."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
SCRIPTPATH="$REPO_ROOT"
source "$SCRIPTPATH/lib/common.sh"
source "$SCRIPTPATH/lib/ui.sh"
source "$SCRIPTPATH/modules/utils.sh"
source "$SCRIPTPATH/modules/core.sh"
start_sub=$(date +%s)
'''


@unittest.skipUnless(shutil.which("bash"), "Bash required")
class CliOutputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="subenum-cli-output-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.markers = self.work / "markers"
        self.markers.mkdir()
        self.log = self.work / "run.log"
        self.env = dict(
            os.environ, REPO_ROOT=str(ROOT), HOME=str(self.work),
            called_fn_dir=str(self.markers), LOGFILE=str(self.log),
            OUTPUT_VERBOSITY="1", SHOW_CACHE="false", DRY_RUN="false",
            COLUMNS="160", TERM="dumb", NO_COLOR="1",
        )
        for name in ("BASH_ENV", "ENV", "CDPATH"):
            self.env.pop(name, None)

    def shell(self, commands, **settings):
        result = subprocess.run(
            ["bash", "-c", HARNESS + "\n" + commands], cwd=self.work,
            env=dict(self.env, **settings), text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def marker(self, name):
        return self.markers / name

    def test_direct_skip_rows_are_silent_without_disturbing_tty_progress(self):
        for verbosity in ("0", "1", "2"):
            with self.subTest(verbosity=verbosity):
                result = self.shell(r'''
_UI_IS_TTY=true
_UI_LIVE_ACTIVE=true
for state in SKIP SKIP_CONFIG SKIP_NOINPUT; do
    print_task "$state" unused_stage 0 reason
    _print_status "$state" unused_stage 0s
done
[[ "$_UI_LIVE_ACTIVE" == true ]]
''', OUTPUT_VERBOSITY=verbosity, SHOW_CACHE="true")
                self.assertEqual(result.stdout + result.stderr, "")

    def test_skip_notifications_keep_markers_and_reasons_but_print_nothing(self):
        reasons = {"disabled": "config", "mode": "mode", "noinput": "noinput",
                   "processed": "cache", "processed-visible": "cache"}
        for reason, code in reasons.items():
            name = "stage_" + reason.replace("-", "_")
            with self.subTest(reason=reason):
                result = self.shell(f'{name}() {{ skip_notification "{reason}"; }}; {name}',
                                    OUTPUT_VERBOSITY="2")
                self.assertEqual(result.stdout + result.stderr, "")
                self.assertEqual(self.marker(".status_reason_" + name).read_text().strip(), code)
                kind = ".cache_" if code == "cache" else ".skip_"
                self.assertTrue(self.marker(kind + name).exists())
                self.assertFalse(self.marker("." + name).exists())

    def test_end_skip_statuses_keep_logs_and_checkpoint_semantics(self):
        for status, badge, reason, checkpoint in (
            ("SKIP", "SKIP", None, True),
            ("SKIP_CONFIG", "SKIP", "config", True),
            ("SKIP_NOINPUT", "SKIP", "noinput", False),
            ("CACHE_HIT", "CACHE", "cache", True),
        ):
            name = "stage_" + status.lower()
            with self.subTest(status=status):
                self.marker("." + name).touch()
                result = self.shell(f'end_subfunc "{name} finished" "{name}" "{status}"',
                                    OUTPUT_VERBOSITY="2")
                self.assertEqual(result.stdout + result.stderr, "")
                self.assertEqual(self.marker(".status_" + name).read_text().strip(), badge)
                if reason:
                    self.assertEqual(self.marker(".status_reason_" + name).read_text().strip(), reason)
                self.assertEqual(self.marker("." + name).exists(), checkpoint)
                self.assertIn(name + " finished", self.log.read_text())

    def test_legacy_skip_messages_still_record_skip_markers(self):
        result = self.shell('legacy_stage() { _print_msg WARN "stage skipped by configuration"; }; legacy_stage')
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertTrue(self.marker(".skip_legacy_stage").exists())

    def test_cache_output_requires_explicit_opt_in(self):
        hidden = self.shell('print_task CACHE cached_stage 0; _print_status CACHE cached_stage 0s')
        self.assertEqual(hidden.stdout, "")
        visible = self.shell('cached_stage() { skip_notification processed; }; cached_stage', SHOW_CACHE="true")
        self.assertRegex(visible.stdout, r"CACHE\s+cached_stage")
        self.assertIn("reason: cache", visible.stdout)
        skipped = self.shell('cached_stage() { skip_notification processed-visible; }; cached_stage',
                             SHOW_CACHE="true", OUTPUT_VERBOSITY="2")
        self.assertEqual(skipped.stdout, "")

    def test_running_success_warning_failure_and_artifacts_remain_visible(self):
        result = self.shell(r'''
print_task RUN running_stage 0
end_subfunc "done" completed_stage OK
_print_msg WARN "fixture warning"
end_subfunc "failed" failed_stage FAIL
print_artifacts "1 found"
''')
        self.assertRegex(result.stdout, r"RUN\s+running_stage")
        self.assertRegex(result.stdout, r"OK\s+completed_stage")
        self.assertIn("fixture warning", result.stdout)
        self.assertRegex(result.stdout, r"FAIL\s+failed_stage")
        self.assertIn("Artifacts: 1 found", result.stdout)
        self.assertFalse(self.marker(".failed_stage").exists())
        self.assertEqual(self.marker(".status_failed_stage").read_text().strip(), "FAIL")

    def test_quiet_mode_does_not_hide_explicit_errors(self):
        result = self.shell('print_task OK quiet_stage 0; _print_error "fixture error"; print_notice FAIL failing_stage "fixture failure"',
                            OUTPUT_VERBOSITY="0")
        self.assertNotIn("quiet_stage", result.stdout)
        self.assertIn("fixture error", result.stderr)
        self.assertRegex(result.stdout, r"FAIL\s+failing_stage")

    def test_header_retains_context_without_branding_or_decorative_rules(self):
        result = self.shell(r'''
domain=example.test
dir=/tmp/output
subenum_version=1.0.0
DNS_RESOLVER_SELECTED=dnsx
RECON_BEHIND_NAT=no
ui_header
''')
        for text in ("Mode: SUBDOMAINS", "Target: example.test", "Output: /tmp/output", "DNS: dnsx", "Started:"):
            self.assertIn(text, result.stdout)
        self.assertNotIn("Authorized testing only", result.stdout)
        self.assertNotIn("subenum 1.0.0", result.stdout)
        self.assertNotIn("─", result.stdout)

    def run_cli(self, *flags):
        config = self.work / "offline.cfg"
        config.write_text(r'''
check_critical_dependencies() { :; }
tools_installed() { :; }
init_dns_resolver() { RECON_BEHIND_NAT=no; DNS_RESOLVER_SELECTED=dnsx; }
subdomains_full() {
    disabled_fixture() { skip_notification disabled; }
    disabled_fixture
    start_subfunc completed_fixture
    end_subfunc "done" completed_fixture OK
    start_subfunc empty_fixture
    end_subfunc "no input" empty_fixture SKIP_NOINPUT
    _print_msg WARN "fixture warning"
    end_subfunc "failed" failed_fixture FAIL
    printf 'www.example.test\n' >subdomains/subdomains.txt
    print_artifacts "1 found"
}
''')
        result = subprocess.run(
            ["bash", str(ROOT / "subenum.sh"), "-d", "example.test", "-f", str(config),
             "-o", str(self.work / "output"), "--no-color", *flags],
            cwd=self.work, env=self.env, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_real_cli_is_concise_by_default_and_in_verbose_mode(self):
        for flags in ((), ("--verbose",), ("--no-banner",)):
            with self.subTest(flags=flags):
                result = self.run_cli(*flags)
                self.assertNotIn("powered by reconFTW methods", result.stdout)
                self.assertNotIn("Authorized testing only", result.stdout)
                self.assertNotIn("SKIP", result.stdout)
                self.assertNotIn("reason:", result.stdout)
                self.assertNotIn("disabled_fixture", result.stdout)
                self.assertRegex(result.stdout, r"OK\s+completed_fixture")
                self.assertRegex(result.stdout, r"FAIL\s+failed_fixture")
                self.assertIn("fixture warning", result.stdout)
                self.assertIn("RESULTS  example.test", result.stdout)
                self.assertIn("Subdomains: 1", result.stdout)
                markers = self.work / "output/example.test/.called_fn"
                self.assertEqual((markers / ".status_reason_disabled_fixture").read_text().strip(), "config")
                self.assertEqual((markers / ".status_empty_fixture").read_text().strip(), "SKIP")
                self.assertFalse((markers / ".empty_fixture").exists())

    def test_existing_banner_opt_in_and_quiet_override_remain_supported(self):
        enabled = self.run_cli("--banner")
        self.assertIn("powered by reconFTW methods", enabled.stdout)
        disabled = self.run_cli("--banner", "--no-banner")
        self.assertNotIn("powered by reconFTW methods", disabled.stdout)
        quiet = self.run_cli("--banner", "--quiet")
        self.assertNotIn("powered by reconFTW methods", quiet.stdout)
        self.assertNotIn("SKIP", quiet.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
