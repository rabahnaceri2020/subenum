#!/usr/bin/env python3
"""Offline checks for fast defaults, deep overrides, and DNS backend selection."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
set -o pipefail
SCRIPTPATH="$REPO_ROOT"
source "$SCRIPTPATH/subenum.cfg"
source "$SCRIPTPATH/lib/common.sh"
source "$SCRIPTPATH/modules/utils.sh"
_get_local_ip() { printf '203.0.113.7\n'; }
_can_use_puredns() { [[ "$TEST_NAT" == "no" ]]; }
_is_behind_nat() { [[ "$TEST_NAT" == "yes" ]]; }
'''
FIELDS = ["deep", "resolver", "brute", "resolve", "tls", "passive", "wildcards", "rate"]
CAPTURE = r'''
printf '%s\n' "${DEEP:-false}" "$(_select_dns_resolver)" "$DNS_BRUTE_TIMEOUT" \
    "$DNS_RESOLVE_TIMEOUT" "$TLS_ENUM_TIMEOUT" "$SUBFINDER_ENUM_TIMEOUT" \
    "$PUREDNS_WILDCARDTEST_LIMIT" "$DNSX_RATE_LIMIT" >"$PROFILE_CAPTURE"
'''


@unittest.skipUnless(shutil.which("bash"), "bash required")
class ScanProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="subenum-profile-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.capture = self.work / "profile.txt"
        self.args = self.work / "args.bin"
        self.trusted = self.work / "trusted.txt"
        self.trusted.write_text("127.0.0.1\n")
        self.env = dict(
            os.environ, REPO_ROOT=str(ROOT), HOME=str(self.work),
            GOPATH=str(self.work / "go"), GOROOT=str(self.work / "goroot"),
            PROFILE_CAPTURE=str(self.capture), ARG_CAPTURE=str(self.args),
            LOGFILE=str(self.work / "run.log"), TEST_NAT="no",
            TRUSTED=str(self.trusted), DRY_RUN="false",
            DNS_RESOLVER_SELECTED="", RECON_BEHIND_NAT="",
        )

    def run_shell(self, script, **env):
        result = subprocess.run(
            ["bash", "-c", HARNESS + "\n" + script], cwd=self.work,
            env=dict(self.env, **env), text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def profile(self, settings="", **env):
        self.run_shell(settings + "\napply_scan_profile\ninit_dns_resolver\n" + CAPTURE, **env)
        return dict(zip(FIELDS, self.capture.read_text().splitlines()))

    def test_normal_vps_uses_fast_dnsx_and_budgets(self):
        self.assertEqual(self.profile(), dict(
            deep="false", resolver="dnsx", brute="90s", resolve="60s", tls="30s",
            passive="2", wildcards="5", rate="500",
        ))

    def test_normal_nat_uses_dnsx(self):
        self.assertEqual(self.profile(TEST_NAT="yes")["resolver"], "dnsx")

    def test_deep_vps_restores_thorough_budgets_and_puredns(self):
        self.assertEqual(self.profile("DEEP=true"), dict(
            deep="true", resolver="puredns", brute="6h", resolve="4h", tls="5m",
            passive="180", wildcards="30", rate="500",
        ))

    def test_deep_nat_still_uses_dnsx(self):
        self.assertEqual(self.profile("DEEP=true", TEST_NAT="yes")["resolver"], "dnsx")

    def test_explicit_puredns_is_respected_in_normal_mode(self):
        self.assertEqual(self.profile("DNS_RESOLVER=puredns")["resolver"], "puredns")

    def test_explicit_dnsx_is_respected_in_deep_mode(self):
        self.assertEqual(self.profile("DEEP=true; DNS_RESOLVER=dnsx")["resolver"], "dnsx")

    def test_auto_selection_without_init_obeys_profile(self):
        for deep, nat, expected in [("false", "no", "dnsx"), ("true", "no", "puredns"), ("true", "yes", "dnsx")]:
            with self.subTest(deep=deep, nat=nat):
                self.run_shell('DEEP=' + deep + '\n' + CAPTURE, TEST_NAT=nat)
                self.assertEqual(self.capture.read_text().splitlines()[1], expected)

    def test_normal_mode_does_not_reuse_stale_puredns_cache(self):
        self.run_shell('DNS_RESOLVER_SELECTED=puredns\n' + CAPTURE)
        self.assertEqual(self.capture.read_text().splitlines()[1], "dnsx")

    def test_custom_normal_budgets_are_not_overwritten(self):
        actual = self.profile('DNS_BRUTE_TIMEOUT=17s; DNS_RESOLVE_TIMEOUT=9s; TLS_ENUM_TIMEOUT=11s; SUBFINDER_ENUM_TIMEOUT=1')
        self.assertEqual([actual[k] for k in ["brute", "resolve", "tls", "passive"]], ["17s", "9s", "11s", "1"])

    def test_custom_deep_budgets_are_applied(self):
        actual = self.profile('DEEP=true; DEEP_DNS_BRUTE_TIMEOUT=7m; DEEP_DNS_RESOLVE_TIMEOUT=3m; DEEP_PUREDNS_WILDCARDTEST_LIMIT=12')
        self.assertEqual([actual[k] for k in ["brute", "resolve", "wildcards"]], ["7m", "3m", "12"])

    def test_profile_does_not_enable_disabled_methods(self):
        self.run_shell('DEEP=true; SUBPERMUTE=false; NS_DELEGATION=false; apply_scan_profile; '
                       '[[ "$SUBPERMUTE" == false && "$NS_DELEGATION" == false ]]')

    def test_dnsx_commands_use_wildcard_filter_and_fast_budgets(self):
        stubs = r'''
resolvers_trusted="$TRUSTED"
_run_dns_with_heartbeat() {
    printf '%s\0' "$@" >"$ARG_CAPTURE"
    shift 2
    "$@"
}
dnsx() {
    local out=""
    while (($#)); do
        if [[ "$1" == "-o" ]]; then out="$2"; shift 2; else shift; fi
    done
    printf 'www.example.test\n' >"$out"
}
puredns() { return 97; }
printf 'www.example.test\n' >input.txt
printf 'www\n' >words.txt
'''
        for command, budget in [('_resolve_domains input.txt output.txt', '60s'),
                                ('_bruteforce_domains words.txt example.test output.txt', '90s')]:
            with self.subTest(command=command):
                self.run_shell(stubs + '\n' + command)
                args = self.args.read_bytes().decode().rstrip('\0').split('\0')
                self.assertEqual(args[1:3], [budget, 'dnsx'])
                self.assertIn('-auto-wildcard', args)
                self.assertIn('-duc', args)
                self.assertEqual((self.work / 'output.txt').read_text(), 'www.example.test\n')

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required")
    def test_dns_budget_stops_a_slow_tool(self):
        binary = self.work / "bin"
        binary.mkdir()
        dnsx = binary / "dnsx"
        dnsx.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n')
        dnsx.chmod(0o755)
        self.run_shell(r'''
resolvers_trusted="$TRUSTED"
TIMEOUT_CMD="$TEST_TIMEOUT_CMD"
DNS_RESOLVE_TIMEOUT=0.05s
printf 'www.example.test\n' >input.txt
printf 'previous.example.test\n' >output.txt
_resolve_domains input.txt output.txt
status=$?
[[ "$status" == 1 ]] || exit 91
''', PATH=str(binary) + os.pathsep + os.environ.get('PATH', ''),
                       TEST_TIMEOUT_CMD=shutil.which('timeout'))
        self.assertEqual((self.work / 'output.txt').read_text(), 'previous.example.test\n')

    def test_cli_applies_profile_after_config_and_cli_overrides(self):
        config = self.work / "offline.cfg"
        config.write_text(r'''
source "$REPO_ROOT/subenum.cfg"
check_critical_dependencies() { :; }
tools_installed() { :; }
_get_local_ip() { printf '203.0.113.7\n'; }
_can_use_puredns() { return 0; }
notification() { :; }
subdomains_full() {
''' + CAPTURE + '\n}\n')
        for flags, expected in [([], ('false', 'dnsx', '90s')), (['--deep'], ('true', 'puredns', '6h'))]:
            with self.subTest(flags=flags):
                result = subprocess.run(
                    ['bash', str(ROOT / 'subenum.sh'), '-d', 'example.test', '-f', str(config),
                     '-o', str(self.work / 'output'), '--dry-run', '--no-banner', '--quiet', '-q', '77', *flags],
                    cwd=self.work, env=self.env, text=True, capture_output=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                actual = dict(zip(FIELDS, self.capture.read_text().splitlines()))
                self.assertEqual(tuple(actual[k] for k in ['deep', 'resolver', 'brute']), expected)
                self.assertEqual(actual['rate'], '77')


if __name__ == '__main__':
    unittest.main(verbosity=2)
