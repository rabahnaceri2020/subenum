#!/usr/bin/env python3
"""Offline checks for heartbeat status, exit codes, and live-progress cleanup."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = shutil.which("timeout")
HARNESS = r'''
set -o pipefail
SCRIPTPATH="$REPO_ROOT"
source "$REPO_ROOT/lib/common.sh"
source "$REPO_ROOT/lib/ui.sh"
source "$REPO_ROOT/modules/utils.sh"
_UI_IS_TTY="$TEST_TTY"
_UI_CACHED_WIDTH=120
# Speed up only the heartbeat polling, not the fixture or GNU timeout.
sleep() { command sleep 0.01; }
trap 'printf "%s\n" "$_UI_LIVE_ACTIVE" >"$UI_STATE"' EXIT
if [[ "$TEST_ERREXIT" == "true" ]]; then set -e; fi
run_with_heartbeat "$TEST_LABEL" 0 "$@"
'''
FIXTURE = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import time
Path(os.environ["FIXTURE_MARKER"]).write_text("executed\n")
print("fixture stdout", flush=True)
print("fixture stderr", file=sys.stderr, flush=True)
time.sleep(float(os.environ["FIXTURE_DELAY"]))
sys.exit(int(os.environ["FIXTURE_EXIT"]))
'''


@unittest.skipUnless(shutil.which("bash"), "bash required")
class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-heartbeat-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "run with spaces"
        self.work.mkdir()
        self.fixture = self.work / "fixture.py"
        self.fixture.write_text(FIXTURE)
        self.fixture.chmod(0o755)
        self.marker = self.work / "executed.txt"
        self.log = self.work / "heartbeat.log"
        self.ui_state = self.work / "ui-state.txt"
        self.env = dict(
            os.environ, REPO_ROOT=str(ROOT), LOGFILE=str(self.log), DEBUG_LOG="",
            TEST_LABEL="DNS probe", TEST_TTY="false", TEST_ERREXIT="false",
            UI_STATE=str(self.ui_state), OUTPUT_VERBOSITY="1", DRY_RUN="false",
            FIXTURE_MARKER=str(self.marker), FIXTURE_DELAY="0.03", FIXTURE_EXIT="0",
        )

    def run_heartbeat(self, command=None, **settings):
        if command is None:
            command = [str(self.fixture)]
        result = subprocess.run(
            ["bash", "-c", HARNESS, "heartbeat-test", *command],
            cwd=self.work, env=dict(self.env, **settings), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=10,
        )
        # Keep carriage returns intact so the TTY cleanup sequence is testable.
        result.stdout = result.stdout.decode()
        result.stderr = result.stderr.decode()
        return result

    def assert_failure(self, result, code, text):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertIn(text + ": DNS probe (", result.stdout)
        self.assertIn("exit " + str(code), result.stdout)
        self.assertNotIn("Completed:", result.stdout)
        self.assertEqual(result.stderr, "")

    def assert_tty_cleanup(self, result, text=None):
        self.assertEqual(self.ui_state.read_text(), "false\n")
        self.assertIn("Running: DNS probe", result.stdout)
        self.assertIn("\r\x1b[K", result.stdout)
        if text:
            self.assertLess(result.stdout.rfind("\r\x1b[K"), result.stdout.index(text + ":"))

    def test_non_tty_success_reports_completed_and_logs_tool_output(self):
        result = self.run_heartbeat()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Started: DNS probe\n", result.stdout)
        self.assertIn("Completed: DNS probe (", result.stdout)
        self.assertNotIn("Failed:", result.stdout)
        self.assertNotIn("Timed out:", result.stdout)
        self.assertNotIn("fixture stdout", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.marker.read_text(), "executed\n")
        self.assertIn("fixture stdout\n", self.log.read_text())
        self.assertIn("fixture stderr\n", self.log.read_text())

    def test_non_tty_failures_preserve_exact_status(self):
        for code in (1, 7, 37, 127, 137):
            with self.subTest(code=code):
                result = self.run_heartbeat(FIXTURE_EXIT=str(code))
                self.assert_failure(result, code, "Failed")
                self.assertIn("Started: DNS probe\n", result.stdout)

    def test_failure_is_reported_before_errexit_exits(self):
        result = self.run_heartbeat(FIXTURE_EXIT="37", TEST_ERREXIT="true")
        self.assert_failure(result, 37, "Failed")

    @unittest.skipUnless(TIMEOUT, "GNU timeout required")
    def test_real_timeout_reports_timeout_and_preserves_124(self):
        result = self.run_heartbeat(
            command=[TIMEOUT, "-k", "0.1s", "0.08s", str(self.fixture)],
            FIXTURE_DELAY="30", TEST_ERREXIT="true",
        )
        self.assert_failure(result, 124, "Timed out")
        self.assertNotIn("Failed:", result.stdout)

    def test_quiet_success_and_failure_do_not_print_heartbeat_status(self):
        for code in (0, 7, 124):
            for tty in ("false", "true"):
                with self.subTest(code=code, tty=tty):
                    result = self.run_heartbeat(
                        FIXTURE_EXIT=str(code), OUTPUT_VERBOSITY="0", TEST_TTY=tty,
                    )
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(self.ui_state.read_text(), "false\n")

    def test_tty_success_cleans_up_without_extra_summary_line(self):
        result = self.run_heartbeat(TEST_TTY="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_tty_cleanup(result)
        self.assertNotIn("Started:", result.stdout)
        self.assertNotIn("Completed:", result.stdout)
        self.assertNotIn("Failed:", result.stdout)

    def test_tty_failure_is_visible_after_cleanup_with_errexit(self):
        result = self.run_heartbeat(TEST_TTY="true", TEST_ERREXIT="true", FIXTURE_EXIT="9")
        self.assert_failure(result, 9, "Failed")
        self.assert_tty_cleanup(result, "Failed")

    @unittest.skipUnless(TIMEOUT, "GNU timeout required")
    def test_real_tty_timeout_cleans_up_before_reporting_failure(self):
        result = self.run_heartbeat(
            command=[TIMEOUT, "-k", "0.1s", "0.08s", str(self.fixture)],
            TEST_TTY="true", TEST_ERREXIT="true", FIXTURE_DELAY="30",
        )
        self.assert_failure(result, 124, "Timed out")
        self.assert_tty_cleanup(result, "Timed out")

    def test_dry_run_does_not_execute_tool_or_start_heartbeat(self):
        for verbosity in ("0", "1", "2"):
            for tty in ("false", "true"):
                with self.subTest(verbosity=verbosity, tty=tty):
                    result = self.run_heartbeat(
                        DRY_RUN="true", OUTPUT_VERBOSITY=verbosity, TEST_TTY=tty,
                        FIXTURE_EXIT="37", TEST_ERREXIT="true",
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(self.marker.exists())
                    self.assertFalse(self.log.exists())
                    self.assertEqual(self.ui_state.read_text(), "false\n")
                    self.assertNotIn("Started:", result.stdout)
                    self.assertNotIn("Completed:", result.stdout)
                    self.assertNotIn("Running:", result.stdout)
                    if verbosity == "2":
                        self.assertIn("[DRY-RUN]", result.stdout)
                    else:
                        self.assertEqual(result.stdout, "")

    def test_missing_command_fails_without_starting_progress(self):
        result = self.run_heartbeat(command=[])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.ui_state.read_text(), "false\n")
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
