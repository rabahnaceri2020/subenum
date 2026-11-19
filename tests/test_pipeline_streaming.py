#!/usr/bin/env python3
"""Offline wrapper integration tests, including output-before-exit pipe gates."""

import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE_NAMES = ("bash", "cat", "cut", "date", "dirname", "mkdir", "rm", "sort", "tee", "wc", "awk")
CORE = {name: shutil.which(name) for name in CORE_NAMES}
DOMAIN = "example.test"
SUBDOMAINS = [f"{name}.{DOMAIN}" for name in ("a", "b", "c", "d")]
HTTPX_ROWS = [
    "https://a.example.test [200] [Welcome page] [42]",
    "https://b.example.test\t[200] [Welcome page] [42]",
    "https://c.example.test [200] [Welcome page] [43]",
    "https://d.example.test [403] [Forbidden] [12]",
    "https://a.example.test [200] [Welcome page] [42]",
]
HTTPX_UNIQUE = [HTTPX_ROWS[index] for index in (0, 2, 3)]
HTTP_URLS = [row.split()[0] for row in HTTPX_UNIQUE]
KATANA_ROWS = [
    "https://d.example.test/z.js", "https://a.example.test/a.js",
    "https://d.example.test/z.js", "https://c.example.test/m.js",
    "https://a.example.test/a.js",
]
KATANA_UNIQUE = list(dict.fromkeys(KATANA_ROWS))
CREDENTIALS = [
    "[credentials-disclosure] [http] [high] https://c.example.test/m.js [fixture-token]",
    "[credentials-disclosure] [http] [high] https://a.example.test/a.js [fixture-key]",
]
FINDINGS = [
    "[fixture-template] [http] [medium] https://a.example.test",
    "[fixture-template] [http] [medium] https://d.example.test",
]
SUBENUM_LINE = "MOCK_SUBENUM_FOUND a.example.test"
PHASES = ("subenum", "httpx", "katana", "credentials", "full")

# All scanner programs, notifications, and Git are replaced by this dispatcher.
# No subprocess or networking modules are used here. Only fixture files and the
# explicitly inherited gate descriptors are available to these fake scanners.
STUB = r'''
import json
import os
from pathlib import Path
import select
import sys
import time

root = Path(os.environ["MOCK_ROOT"])
config = json.loads((root / "fixture.json").read_text())
events = root / "events"
args = sys.argv[1:]
role = Path(sys.argv[0]).name
if args[:1] == ["--subenum"]:
    role, args = "subenum", args[1:]

def record(**fields):
    with (events / "calls.jsonl").open("a") as stream:
        stream.write(json.dumps(dict(tool=role, args=args, **fields)) + "\n")

def produce(phase, lines):
    (events / (phase + ".started")).write_text(str(os.getpid()))
    try:
        for line in lines:
            print(line, flush=True)
        gates = json.loads(os.environ.get("MOCK_GATES", "{}"))
        if phase in gates:
            fd = gates[phase]
            ready, _, _ = select.select([fd], [], [], 10)
            if not ready or os.read(fd, 1) != b"G":
                raise RuntimeError("reader did not release " + phase)
    finally:
        (events / (phase + ".exited")).write_text("exited\n")

try:
    if role == "sleep":
        time.sleep(0.01)
    elif role == "subenum":
        domain = args[args.index("-d") + 1]
        destination = root / "Recon" / domain / "subdomains" / "subdomains.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("\n".join(config["subdomains"]) + "\n")
        record(domain=domain)
        produce("subenum", [config["subenum_line"]])
    elif role == "anew":
        incoming = sys.stdin.read().splitlines()
        destination = Path(args[0])
        existing = destination.read_text().splitlines() if destination.exists() else []
        seen = set(existing)
        fresh = []
        for line in incoming:
            if line not in seen:
                fresh.append(line)
                seen.add(line)
        with destination.open("a") as stream:
            for line in fresh:
                stream.write(line + "\n")
                print(line)
        record(input=incoming, previous=existing, fresh=fresh)
    elif role in ("httpx", "katana"):
        record(input=sys.stdin.read().splitlines())
        produce(role, config[role])
    elif role == "nuclei":
        if "-id" in args:
            assert args[args.index("-id") + 1] == "credentials-disclosure"
            filename = Path(args[args.index("-l") + 1])
            record(phase="credentials", input=filename.read_text().splitlines(), list_file=str(filename))
            produce("credentials", config["credentials"])
        else:
            assert Path(args[args.index("-t") + 1]).is_dir()
            record(phase="full", input=sys.stdin.read().splitlines())
            produce("full", config["full"])
    elif role == "notify":
        filename = Path(args[args.index("-data") + 1])
        record(channel=args[args.index("-id") + 1], data=filename.read_text().splitlines())
    elif role == "git":
        record()
        assert args[:2] == ["-C", str(root)]
        if args[2:] == ["rev-parse", "--is-inside-work-tree"]:
            print("true")
        elif args[2:] == ["pull"]:
            print("MOCK_GIT_PULL", flush=True)
        else:
            raise RuntimeError("unexpected fake Git invocation")
    else:
        raise RuntimeError("unexpected mock command: " + role)
except BaseException as error:
    with (events / "errors.jsonl").open("a") as stream:
        stream.write(json.dumps(dict(tool=role, error=repr(error))) + "\n")
    raise
'''


class RunningPipeline:
    """Read wrapper stdout continuously; release each producer only on demand."""

    def __init__(self, work, env, gated):
        self.work, self.env, self.gated = work, env, gated
        self.process = None
        self.reader = None
        self.lines = []
        self.queue = queue.Queue()
        self.writers = {}
        self.readers = []

    def start(self):
        gates = {}
        if self.gated:
            for phase in PHASES:
                read_fd, write_fd = os.pipe()
                gates[phase] = read_fd
                self.readers.append(read_fd)
                self.writers[phase] = write_fd
        env = dict(self.env, MOCK_GATES=json.dumps(gates))
        try:
            self.process = subprocess.Popen(
                [CORE["bash"], str(self.work / "script.sh")], cwd=self.work,
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                start_new_session=True, pass_fds=tuple(self.readers),
            )
        finally:
            for fd in self.readers:
                os.close(fd)
            self.readers.clear()
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()

    def read_output(self):
        try:
            for line in self.process.stdout:
                line = line.rstrip("\n")
                self.lines.append(line)
                self.queue.put(line)
        finally:
            self.queue.put(None)

    def await_line(self, expected):
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"No live output {expected!r}; output so far: {self.lines!r}")
            try:
                line = self.queue.get(timeout=remaining)
            except queue.Empty:
                raise AssertionError(f"No live output {expected!r}; output so far: {self.lines!r}") from None
            if line is None:
                raise AssertionError(f"Wrapper ended before {expected!r}; output: {self.lines!r}")
            if line == expected:
                return

    def release(self, phase):
        fd = self.writers.pop(phase)
        try:
            os.write(fd, b"G")
        finally:
            os.close(fd)

    def finish(self):
        code = self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        if self.reader.is_alive():
            raise AssertionError("Wrapper exited but its output pipe is still held open")
        return code

    def close(self):
        # Kill the whole session's process group, not just Bash, on any failure.
        # Always reap the direct child and close descriptors, including gates for
        # stages never reached when an assertion fails.
        if self.process is not None:
            if self.process.poll() is None or (self.reader and self.reader.is_alive()):
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.process.wait(timeout=3)
        for fd in self.readers + list(self.writers.values()):
            os.close(fd)
        self.readers.clear()
        self.writers.clear()
        if self.reader:
            self.reader.join(timeout=2)
        if self.process and self.process.stdout:
            self.process.stdout.close()


@unittest.skipUnless(os.name == "posix" and all(CORE.values()), "Bash and POSIX core utilities required")
class PipelineStreamingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="subenum streaming test ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.bin = self.work / "bin"
        self.events = self.work / "events"
        self.templates = self.work / "templates"
        self.data = self.work / "data"
        for directory in (self.bin, self.events, self.templates, self.data, self.work / "logs"):
            directory.mkdir()
        for name, command in CORE.items():
            (self.bin / name).symlink_to(command)
        dispatcher = self.bin / "mock-scanner.py"
        dispatcher.write_text(f"#!{sys.executable} -I\n" + STUB)
        dispatcher.chmod(0o755)
        for name in ("anew", "httpx", "katana", "nuclei", "notify", "git", "sleep"):
            (self.bin / name).symlink_to(dispatcher)
        (self.work / "subenum.sh").write_text(
            '#!/usr/bin/env bash\nexec "$MOCK_PYTHON" -I "$MOCK_DISPATCH" --subenum "$@"\n'
        )
        (self.work / "domains.txt").write_text(DOMAIN + "\n")
        words = self.work / "resources" / "wordlists"
        words.mkdir(parents=True)
        (words / "subdomains.txt").write_text("www\n")
        source = (ROOT / "script.sh").read_text()
        replacements = {
            'LOG_FILE="/var/log/recon.log"': 'LOG_FILE=' + json.dumps(str(self.work / "logs" / "recon.log")),
            'NUCLEI_TEMPLATES="/opt/nuclei-templates/"': 'NUCLEI_TEMPLATES=' + json.dumps(str(self.templates)),
        }
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 1, "fixture path replacement must be exact")
            source = source.replace(old, new)
        (self.work / "script.sh").write_text(source)
        self.config = dict(subdomains=SUBDOMAINS, subenum_line=SUBENUM_LINE,
                           httpx=HTTPX_ROWS, katana=KATANA_ROWS,
                           credentials=CREDENTIALS, full=FINDINGS)
        self.env = dict(os.environ, PATH=str(self.bin), HOME=str(self.work), LC_ALL="C",
                        HEARTBEAT_INTERVAL="3600", MOCK_ROOT=str(self.work),
                        MOCK_PYTHON=sys.executable, MOCK_DISPATCH=str(dispatcher))
        for variable in ("BASH_ENV", "ENV", "CDPATH", "PYTHONPATH", "PYTHONHOME"):
            self.env.pop(variable, None)

    def start(self, gated=False):
        (self.work / "fixture.json").write_text(json.dumps(self.config))
        runner = RunningPipeline(self.work, self.env, gated)
        self.addCleanup(runner.close)
        runner.start()
        return runner

    def records(self):
        return [json.loads(line) for line in (self.events / "calls.jsonl").read_text().splitlines()]

    def saved(self, suffix):
        return (self.data / (DOMAIN + suffix)).read_text().splitlines()

    def assert_finished(self, runner):
        self.assertEqual(runner.finish(), 0, "\n".join(runner.lines))
        errors = self.events / "errors.jsonl"
        self.assertFalse(errors.exists(), errors.read_text() if errors.exists() else "")
        self.assertIn("MOCK_GIT_PULL", runner.lines)
        self.assertEqual([record["args"][-1] for record in self.records() if record["tool"] == "git"],
                         ["--is-inside-work-tree", "pull"])

    def test_every_scanner_streams_before_exit_and_preserves_handoffs(self):
        runner = self.start(gated=True)
        expected = {
            "subenum": [SUBENUM_LINE], "httpx": HTTPX_UNIQUE,
            "katana": KATANA_UNIQUE, "credentials": CREDENTIALS, "full": FINDINGS,
        }
        for phase in PHASES:
            for line in expected[phase]:
                runner.await_line(line)
            # Visibility is proven while the producer still cannot exit:
            # its gate has not been released, it is alive, and no exit
            # marker exists. Assertions only after wrapper exit would miss
            # both AWK buffering and a blocking sort in the live pipeline.
            # Fail immediately rather than continuing to other blocked stages;
            # addCleanup then kills/reaps the whole process group promptly.
            pid = int((self.events / (phase + ".started")).read_text())
            os.kill(pid, 0)
            self.assertFalse((self.events / (phase + ".exited")).exists(), phase)
            self.assertIn(phase, runner.writers)
            runner.release(phase)
        self.assert_finished(runner)
        for phase in PHASES:
            self.assertTrue((self.events / (phase + ".exited")).exists())
        self.assertEqual(self.saved(".httpx"), HTTPX_UNIQUE)
        self.assertEqual(self.saved(".jsurls"), sorted(KATANA_UNIQUE))
        self.assertEqual(self.saved(".tokens"), CREDENTIALS)
        self.assertEqual(self.saved(".nuclei"), FINDINGS)
        self.assertEqual(self.saved(".txt.new"), SUBDOMAINS)
        self.assertEqual(self.saved(".txt.all"), SUBDOMAINS)
        for line in HTTPX_UNIQUE + KATANA_UNIQUE + CREDENTIALS + FINDINGS:
            self.assertEqual(runner.lines.count(line), 1, line)
        self.assertNotIn(HTTPX_ROWS[1], runner.lines)
        records = self.records()
        calls = {record["tool"]: record for record in records if record["tool"] in ("subenum", "anew", "httpx", "katana")}
        self.assertEqual(calls["subenum"]["args"], ["-d", DOMAIN])
        self.assertEqual(calls["anew"]["input"], SUBDOMAINS)
        self.assertEqual(calls["httpx"]["input"], SUBDOMAINS)
        self.assertEqual(calls["katana"]["input"], HTTP_URLS)
        nuclei = {record["phase"]: record for record in records if record["tool"] == "nuclei"}
        self.assertEqual(nuclei["credentials"]["input"], sorted(KATANA_UNIQUE))
        self.assertEqual(nuclei["full"]["input"], HTTP_URLS)
        notifications = {record["channel"]: record["data"] for record in records if record["tool"] == "notify"}
        self.assertEqual(notifications, dict(httpx=HTTPX_UNIQUE, tokens=CREDENTIALS, bugs=FINDINGS))

    def test_no_new_subdomains_skips_all_downstream_scanners_and_notifications(self):
        (self.data / (DOMAIN + ".txt.all")).write_text("\n".join(SUBDOMAINS) + "\n")
        runner = self.start()
        self.assert_finished(runner)
        self.assertTrue(any("No new subdomains found" in line for line in runner.lines))
        self.assertEqual(self.saved(".txt.new"), [])
        self.assertEqual(self.saved(".txt.all"), SUBDOMAINS)
        self.assertEqual([record["tool"] for record in self.records()], ["subenum", "anew", "git", "git"])
        for suffix in (".httpx", ".jsurls", ".tokens", ".nuclei"):
            self.assertFalse((self.data / (DOMAIN + suffix)).exists())

    def test_empty_httpx_skips_katana_and_both_nuclei_scans(self):
        self.config["httpx"] = []
        runner = self.start()
        self.assert_finished(runner)
        self.assertEqual(self.saved(".httpx"), [])
        self.assertEqual([record["tool"] for record in self.records()], ["subenum", "anew", "httpx", "git", "git"])
        self.assertTrue(any("Skipping katana" in line for line in runner.lines))
        self.assertTrue(any("Skipping credentials scan" in line for line in runner.lines))
        self.assertTrue(any("Skipping full nuclei scan" in line for line in runner.lines))

    def test_empty_katana_skips_credentials_but_keeps_full_nuclei(self):
        self.config["katana"] = []
        runner = self.start()
        self.assert_finished(runner)
        self.assertEqual(self.saved(".jsurls"), [])
        self.assertFalse((self.data / (DOMAIN + ".tokens")).exists())
        self.assertEqual(self.saved(".nuclei"), FINDINGS)
        nuclei = [record for record in self.records() if record["tool"] == "nuclei"]
        self.assertEqual([record["phase"] for record in nuclei], ["full"])
        self.assertEqual(nuclei[0]["input"], HTTP_URLS)
        self.assertTrue(any("Skipping credentials scan" in line for line in runner.lines))


if __name__ == "__main__":
    unittest.main(verbosity=2)
