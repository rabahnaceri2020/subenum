"""Offline installer regressions. All installations are shell mocks in temp dirs."""
import os
from pathlib import Path
import shlex
import shutil
import signal
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
        # Defense in depth: NEVER inherit a host command search path. If a shell
        # mock is skipped, executable stubs fail closed instead of running apt,
        # Git, compilers, Python installers, scanners, or network utilities.
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("bash", "uname", "awk", "cut", "mktemp", "cat", "rm",
                     "mkdir", "chmod", "tee", "touch", "sleep", "date", "cmp"):
            target = shutil.which(name, path="/usr/bin:/bin")
            self.assertIsNotNone(target, f"Required fixture utility: {name}")
            (self.bin / name).symlink_to(target)
        self.denied = ("apt", "apt-get", "apt-cache", "dpkg", "yum", "dnf",
                       "pacman", "brew", "sudo", "git", "curl", "wget", "go",
                       "uv", "pip", "pip3", "python", "python3", "make", "cmake",
                       "gcc", "g++", "cc", "strip", "cp", "mv", "tar", "sh",
                       "env", "crontab", "flock", "notify", "subfinder", "massdns",
                       "dnsx", "puredns", "nuclei", "httpx", "katana", "dig",
                       "nslookup", "getent", "timeout", "gtimeout")
        for name in self.denied:
            stub = self.bin / name
            stub.write_text('#!/bin/bash\nprintf "DENIED %s\\n" "${0##*/}" >> "$CALLS"\n'
                            'printf "DENIED %s\\n" "${0##*/}" >&2\nexit 97\n')
            stub.chmod(0o755)
        # Root detection must also be deterministic without using host sudo.
        (self.bin / "id").write_text("#!/bin/bash\nprintf '0\\n'\n")
        (self.bin / "id").chmod(0o755)
        # Redirect absolute installation targets and OS detection in fixture only.
        text = SOURCE.read_text().replace("/usr/local/bin/massdns", str(self.dest))
        text = text.replace("/usr/local/go", str(self.root / "unused-go"))
        text = text.replace("/etc/debian_version", str(self.root / "debian"))
        # CLI script execution loads mocks explicitly, independent of Bash's
        # SSH-specific startup rules. An unset variable tests the deny fallback.
        text = text.replace("#!/bin/bash\n", '#!/bin/bash\n'
                            'if [[ -n ${INSTALLER_TEST_MOCKS:-} ]]; then\n'
                            '    source "$INSTALLER_TEST_MOCKS" || exit $?\nfi\n', 1)
        self.script.write_text(text)
        (self.root / "debian").touch()
        (self.root / "subenum.cfg").write_text(
            f'tools="{self.tools}"\nupgrade_tools=true\ninstall_golang=false\n'
        )
        # Do not inherit exported Bash functions, startup files, SSH variables,
        # credentials, Python/Go paths, or installer flags from the test runner.
        self.env = dict(PATH=str(self.bin), HOME=str(self.root), TMPDIR=str(self.root),
                        LANG="C", LC_ALL="C", LOGFILE=str(self.root / "install.log"),
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
        self.env["INSTALLER_TEST_MOCKS"] = str(self.mock)
        for repo in ("massdns", "regulator"):
            (self.tools / repo / ".git").mkdir(parents=True)
        (self.tools / "regulator" / "requirements.txt").write_text("datrie\neditdistance\n")
        (self.tools / "regulator" / "main.py").write_text("# fixture\n")

    def run_process(self, args, env=None, timeout=10):
        env = dict(self.env if env is None else env)
        for name in tuple(env):
            if name.startswith("SSH_") or name in ("BASH_EXECUTION_STRING", "ENV"):
                del env[name]
        proc = subprocess.Popen(args, cwd=self.root, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # Kill the whole isolated session's process group, not just Bash:
            # children may hold captured pipes open after their parent exits.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                stdout = stderr = ""
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # communicate reaps our child and closes all captured pipes.
                remaining_out, remaining_err = proc.communicate()
            exc.output = stdout or remaining_out
            exc.stderr = stderr or remaining_err
            raise
        return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)

    def run_shell(self, command, fail=""):
        env = dict(self.env, FAIL=fail)
        return self.run_process([str(self.bin / "bash"), "--noprofile", "--norc", "-c",
                                 f'source {shlex.quote(str(self.mock))} || exit $?; '
                                 f'source {shlex.quote(str(self.script))} || exit $?; {command}'], env)

    def cli(self, *args, fail=""):
        return self.run_process([str(self.bin / "bash"), "--noprofile", "--norc",
                                 str(self.script), *args], dict(self.env, FAIL=fail))

    def call_text(self):
        return self.calls.read_text() if self.calls.exists() else ""

    def test_inherited_ssh_variables_do_not_disable_mocks(self):
        self.env.update(SSH_CLIENT="192.0.2.1 12345 22",
                        SSH_CONNECTION="192.0.2.1 12345 192.0.2.2 22",
                        SSH_TTY="/dev/pts/999")
        p = self.run_shell('[[ -z ${SSH_CLIENT+x} && -z ${SSH_CONNECTION+x} '
                           '&& -z ${SSH_TTY+x} ]] || exit 98; install_system_packages',
                           "apt-install")
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        self.assertIn("APT diagnostic install", p.stderr)
        p = self.cli("--repair-deps")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("DENIED", self.call_text())

    def test_missing_bash_env_still_loads_explicit_mocks(self):
        self.env.pop("BASH_ENV")
        p = self.run_shell("install_system_packages", "apt-update")
        self.assertEqual(p.returncode, 100, p.stdout + p.stderr)
        p = self.cli("--repair-deps")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("DENIED", self.call_text())

    def test_missing_all_mocks_fails_closed_without_host_commands(self):
        self.env.pop("BASH_ENV")
        self.env.pop("INSTALLER_TEST_MOCKS")
        p = self.cli("--repair-deps")
        self.assertEqual(p.returncode, 97, p.stdout + p.stderr)
        self.assertIn("DENIED apt-get", p.stdout + p.stderr)
        self.assertNotIn("Dependency repair complete", p.stdout)
        # Sourced function calls are equally safe even with no startup hook.
        p = self.run_process([str(self.bin / "bash"), "--noprofile", "--norc", "-c",
                              f'source {shlex.quote(str(self.script))}; install_system_packages'])
        self.assertEqual(p.returncode, 97, p.stdout + p.stderr)
        self.assertIn("DENIED apt-get", p.stderr)
        # Exercise every executable deny fallback directly, never the host PATH.
        for name in self.denied:
            with self.subTest(command=name):
                p = self.run_process([name, "--fixture-safety-check"])
                self.assertEqual(p.returncode, 97, p.stdout + p.stderr)
                self.assertIn(f"DENIED {name}", p.stderr)

    def test_timeout_terminates_process_group_and_reaps_children(self):
        pids = self.root / "timeout-pids"
        command = ("sleep 30 & child=$!; "
                   "trap 'wait \"$child\"; exit 143' TERM; "
                   f'printf "%s %s\\n" "$$" "$child" > {shlex.quote(str(pids))}; '
                   'wait "$child"')
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_process([str(self.bin / "bash"), "--noprofile", "--norc", "-c", command],
                             timeout=0.5)
        self.assertTrue(pids.exists(), "Timeout fixture failed to start")
        for pid in map(int, pids.read_text().split()):
            with self.assertRaises(ProcessLookupError, msg=f"Unreaped process {pid}"):
                os.kill(pid, 0)

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
