"""Offline installer regressions. All installations are shell mocks in temp dirs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "install.sh"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tools = self.root / "tools"
        self.dest = self.root / "installed-massdns"
        self.calls = self.root / "calls"
        self.script = self.root / "install.sh"
        # Redirect the absolute installation target and OS detection in fixture only.
        text = SOURCE.read_text().replace("/usr/local/bin/massdns", str(self.dest))
        text = text.replace("/etc/debian_version", str(self.root / "debian"))
        self.script.write_text(text)
        (self.root / "debian").touch()
        (self.root / "subenum.cfg").write_text(
            f'tools="{self.tools}"\nupgrade_tools=true\ninstall_golang=false\n'
        )
        self.env = dict(os.environ, HOME=str(self.root), LOGFILE=str(self.root / "install.log"),
                        CALLS=str(self.calls), FAIL="", VERBOSE="false", DRY_RUN="false",
                        TOOLS_ONLY="false", TEMPLATES_ONLY="false", REPAIR_DEPS="false")
        self.mock = self.root / "mocks.sh"
        self.mock.write_text(r'''
record() { printf '%s\n' "$*" >> "$CALLS"; }
id() { printf '0\n'; }
timeout() { shift; "$@"; }
apt-get() { record "apt-get $*"; if [[ $FAIL == "apt-$1" ]]; then echo "APT diagnostic $1" >&2; return 100; fi; }
uv() {
    record "uv $*"
    case "$1 $2" in
        'venv --python')
            [[ $FAIL != venv ]] || { echo 'venv diagnostic' >&2; return 23; }
            mkdir -p venv/bin
            cat > venv/bin/python3 <<'PYTHON_MOCK'
#!/bin/bash
printf 'python %s\n' "$*" >> "$CALLS"
[[ $FAIL != imports ]]
PYTHON_MOCK
            chmod +x venv/bin/python3 ;;
        'pip install') [[ $FAIL != pip ]] || { echo 'pip diagnostic' >&2; return 24; } ;;
        'pip check') [[ $FAIL != check ]] || return 25 ;;
        *) echo "FORBIDDEN uv $*" >&2; return 97 ;;
    esac
}
make() {
    record make
    [[ $FAIL != make ]] || { echo 'make diagnostic' >&2; return 21; }
    [[ $FAIL != missing-binary ]] || return 0
    mkdir -p bin
    printf '#!/bin/bash\n[[ $FAIL != executable ]]\n' > bin/massdns
    chmod +x bin/massdns
}
cp() {
    record "cp $*"
    [[ $FAIL != copy ]] || { echo 'copy diagnostic' >&2; return 22; }
    [[ $FAIL != missing-copy ]] || return 0
    [[ $2 == "$HOME/installed-massdns" ]] || return 97
    /bin/cp "$@"
}
for forbidden in go git curl wget crontab notify subfinder yum pacman brew sudo; do
    eval "$forbidden() { record 'FORBIDDEN $forbidden'; return 97; }"
done
''')
        self.env["BASH_ENV"] = str(self.mock)
        for repo in ("massdns", "regulator"):
            (self.tools / repo / ".git").mkdir(parents=True)
        (self.tools / "regulator" / "requirements.txt").write_text("datrie\neditdistance\n")
        (self.tools / "regulator" / "main.py").write_text("# fixture\n")

    def run_shell(self, command, fail=""):
        env = dict(self.env, FAIL=fail)
        return subprocess.run(["bash", "-c", f'source "{self.script}"; {command}'],
                              cwd=self.root, env=env, text=True, capture_output=True, timeout=10)

    def cli(self, *args, fail=""):
        return subprocess.run(["bash", str(self.script), *args], cwd=self.root,
                              env=dict(self.env, FAIL=fail), text=True, capture_output=True, timeout=10)

    def call_text(self):
        return self.calls.read_text() if self.calls.exists() else ""

    def test_apt_update_failure_stops_before_install_and_uv(self):
        p = self.run_shell("install_system_packages", "apt-update")
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        self.assertIn("APT diagnostic update", p.stderr)
        self.assertNotIn("apt-get install", self.call_text())
        self.assertNotIn("uv ", self.call_text())

    def test_apt_install_failure_not_masked_by_uv(self):
        p = self.run_shell("install_system_packages", "apt-install")
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        self.assertIn("APT diagnostic install", p.stderr)
        self.assertNotIn("uv ", self.call_text())
        self.assertIn("python3-dev", self.call_text())
        self.assertIn("pkg-config", self.call_text())
        self.assertIn("--no-remove", self.call_text())

    def test_build_failures_have_honest_counts_and_no_ready(self):
        for failure, repo in (("make", "massdns"), ("copy", "massdns"),
                              ("missing-binary", "massdns"), ("missing-copy", "massdns"),
                              ("executable", "massdns"), ("venv", "regulator"),
                              ("pip", "regulator"), ("check", "regulator"),
                              ("imports", "regulator")):
            with self.subTest(failure=failure):
                # Reuse fixture safely, remove only generated test artifacts.
                if self.dest.exists():
                    self.dest.unlink()
                binary = self.tools / "massdns/bin/massdns"
                if binary.exists():
                    binary.unlink()
                python = self.tools / "regulator/venv/bin/python3"
                if python.exists():
                    python.unlink()
                p = self.run_shell("REPAIR_DEPS=true; install_repositories", failure)
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn("1 OK, 0 skipped, 1 failed (of 2)", p.stdout)
                self.assertNotIn(f"{repo} ready", p.stdout)
                self.assertIn(f"{repo} build/validation failed", p.stdout)

    def test_repair_success_existing_empty_venv_and_isolation(self):
        (self.tools / "regulator/venv").mkdir()
        sentinel = self.tools / "massdns/user-content"
        sentinel.write_text("keep me")
        p = self.cli("--repair-deps")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("2 OK, 0 skipped, 0 failed (of 2)", p.stdout)
        self.assertIn("Dependency repair complete", p.stdout)
        self.assertEqual(sentinel.read_text(), "keep me")
        self.assertNotIn("FORBIDDEN", self.call_text())
        self.assertNotIn("update-shell", self.call_text())
        self.assertFalse((self.root / ".config").exists())
        self.assertFalse((self.root / ".profile").exists())
        self.assertIn("uv venv\n--python", self.call_text())
        self.assertNotIn("--upgrade", self.call_text())
        self.assertIn("from dank.DankEncoder import DankEncoder", self.call_text())
        self.assertIn("from dank.DankGenerator import DankGenerator", self.call_text())

    def test_repair_missing_clone_preserves_content(self):
        (self.tools / "massdns/.git").rmdir()
        sentinel = self.tools / "massdns/custom"
        sentinel.write_text("preserve")
        p = self.cli("--repair-deps")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("repair requires existing clone", p.stdout)
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertNotIn("FORBIDDEN", self.call_text())

    def test_cli_failures_never_finish(self):
        for args, failure in (((), "apt-update"), ((), "apt-install"),
                              (("--repair-deps",), "make"), (("--repair-deps",), "pip")):
            with self.subTest(args=args, failure=failure):
                p = self.cli(*args, fail=failure)
                self.assertNotEqual(p.returncode, 0)
                self.assertNotIn("Finished", p.stdout)
                self.assertNotIn("Dependency repair complete", p.stdout)
                self.assertNotIn("FORBIDDEN", self.call_text())

    def test_normal_setup_stops_on_go_or_tools_failure(self):
        for stage in ("install_golang_version", "install_tools"):
            with self.subTest(stage=stage):
                p = self.run_shell('''
install_system_packages() { return 0; }
check_network() { return 0; }
install_golang_version() { return 0; }
install_tools() { return 0; }
q() { return 0; }
download_required_files() { echo FORBIDDEN; return 97; }
setup_nuclei_templates() { echo FORBIDDEN; return 97; }
''' + stage + '() { return 42; }; initial_setup')
                self.assertEqual(p.returncode, 42, p.stdout + p.stderr)
                self.assertNotIn("Finished", p.stdout)
                self.assertNotIn("FORBIDDEN", p.stdout)

    def test_uv_setup_failure_stops_normal_install(self):
        p = self.run_shell('''
install_uv() { echo 'uv failed'; return 31; }
install_golang_version() { echo FORBIDDEN; return 97; }
initial_setup
''')
        self.assertEqual(p.returncode, 31, p.stdout + p.stderr)
        self.assertNotIn("FORBIDDEN", p.stdout)
        self.assertNotIn("Finished", p.stdout)

    def test_failed_go_upgrade_counts_as_failure_even_with_existing_binary(self):
        p = self.run_shell('''
gotools=([go]=fixture); pipxtools=(); repos=()
install_tools
''')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("0 OK, 0 skipped, 1 failed (of 1)", p.stdout)
        self.assertIn("existing binary kept", p.stdout)

    def test_normal_repo_count_is_build_success_not_clone_count(self):
        p = self.run_shell("git() { return 0; }; install_repositories")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("2 OK, 0 skipped, 0 failed (of 2)", p.stdout)

    def test_normal_tool_summary_propagates_repo_failure(self):
        p = self.run_shell('''
gotools=(); pipxtools=(); REPAIR_DEPS=true
install_tools
''', "make")
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("1 OK, 0 skipped, 1 failed (of 2)", p.stdout)

    def test_clone_refuses_existing_content(self):
        p = self.run_shell('clone_repo ignored "$dir/massdns"')
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue((self.tools / "massdns/.git").exists())
        self.assertNotIn("FORBIDDEN", self.call_text())

    def test_argument_validation_and_help_do_not_touch_logs(self):
        log = self.root / "install.log"
        log.write_text("original evidence\n")
        for args in (("--help",), ("--log",), ("--repair-deps", "--tools"), ("--unknown",)):
            with self.subTest(args=args):
                p = self.cli(*args)
                self.assertEqual(p.returncode == 0, args == ("--help",))
                self.assertEqual(log.read_text(), "original evidence\n")
                self.assertEqual(self.call_text(), "")

    def test_selected_log_is_append_only(self):
        default = self.root / "install.log"
        default.write_text("old default\n")
        selected = self.root / "selected.log"
        selected.write_text("old selected\n")
        p = self.cli("--repair-deps", "--log", str(selected))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(default.read_text(), "old default\n")
        self.assertTrue(selected.read_text().startswith("old selected\n"))
        self.assertIn("Dependency repair complete", selected.read_text())

    def test_dry_repair_does_not_execute_commands_or_log(self):
        p = self.cli("--repair-deps", "--dry-run")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.call_text(), "")
        self.assertFalse((self.root / "install.log").exists())
        self.assertIn("0 OK, 2 skipped, 0 failed", p.stdout)


if __name__ == "__main__":
    unittest.main()
