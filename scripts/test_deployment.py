"""Exercise deployment entry points in disposable directories with fake commands.

No package installation, network listener or real database is used by these tests.
Run: python -m unittest scripts.test_deployment -v
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
RECORDER = '''import json, os, sys
from pathlib import Path
record = {
    "kind": __name__ if KIND == "manage" else KIND,
    "args": sys.argv[1:], "app_env": os.getenv("APP_ENV"),
    "migration_role": os.getenv("DATABASE_URL") == "migration-test-only",
    "runtime_role": os.getenv("DATABASE_URL") == "runtime-test-only",
    "has_migration_secret": bool(os.getenv("MIGRATION_DATABASE_URL")),
    "python": sys.executable,
}
record["kind"] = KIND
with Path(os.environ["DEPLOY_TEST_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(record) + "\\n")
if KIND == "manage" and len(sys.argv) > 1 and sys.argv[1] == os.getenv("DEPLOY_TEST_FAIL"):
    sys.exit(17)
'''


class DeploymentEntryPointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="plit99-deploy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.app = self.directory / "app with spaces"
        self.app.mkdir()
        (self.app / "scripts").mkdir()
        for name in ("build.ps1", "start.ps1", "manage.ps1", "build.sh", "start.sh",
                     "scripts/deploy-common.ps1", "scripts/deploy-common.sh"):
            shutil.copyfile(ROOT / name, self.app / name)
        for name, kind in (("manage.py", "manage"), ("pip.py", "pip"),
                           ("waitress.py", "waitress")):
            (self.app / name).write_text(f"KIND = {kind!r}\n" + RECORDER, encoding="utf-8")
        (self.app / ".env").write_text(
            f'PYTHON_EXECUTABLE="{Path(sys.executable).as_posix()}"\n'
            "DATABASE_URL=runtime-test-only\n", encoding="utf-8")
        self.log = self.directory / "calls.jsonl"
        self.environment = {key: value for key, value in os.environ.items()
                            if key not in {"APP_ENV", "PYTHON_EXECUTABLE", "DATABASE_URL",
                                           "WAITRESS_TRUSTED_PROXY", "MIGRATION_DATABASE_URL",
                                           "WAITRESS_HOST", "WAITRESS_PORT", "WAITRESS_THREADS", "PORT"}}
        self.environment["DEPLOY_TEST_LOG"] = str(self.log)
        self.environment["MIGRATION_DATABASE_URL"] = "migration-test-only"

    def runners(self):
        if os.name == "nt":
            yield "powershell", [str(Path(os.environ["SYSTEMROOT"]) / "System32" /
                "WindowsPowerShell/v1.0/powershell.exe"), "-NoProfile", "-NonInteractive", "-File"]
        bash = shutil.which("bash")
        if os.name == "nt":
            candidate = Path("C:/Program Files/Git/bin/bash.exe")
            bash = str(candidate) if candidate.exists() else None
        if bash:
            yield "bash", [bash]

    def run_script(self, runner, command, *, extra=None, arguments=()):
        self.log.unlink(missing_ok=True)
        extension = "ps1" if runner[0] == "powershell" else "sh"
        environment = dict(self.environment, **(extra or {}))
        result = subprocess.run(runner[1] + [str(self.app / f"{command}.{extension}")] + list(arguments),
                                cwd=self.directory, env=environment, capture_output=True,
                                text=True, timeout=45)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_build_uses_production_and_separate_migration_credentials(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "build")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([c["kind"] for c in calls], ["pip", "manage", "manage", "manage"])
                self.assertTrue(all(c["app_env"] == "production" for c in calls))
                self.assertTrue(all(Path(c["python"]) == Path(sys.executable) for c in calls))
                self.assertTrue(all(c["runtime_role"] for c in calls[:-1]))
                self.assertTrue(calls[-1]["migration_role"])
                self.assertEqual(calls[-1]["args"], ["migrate", "--noinput"])
                self.assertEqual(calls[2]["args"], ["collectstatic", "--noinput"])

    def test_start_checks_schema_without_migration_role_and_limits_http(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "start")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 3)
                self.assertEqual(calls[1]["args"], ["migrate", "--check"])
                self.assertTrue(all(c["runtime_role"] for c in calls))
                self.assertTrue(all(not c["has_migration_secret"] for c in calls))
                self.assertEqual(calls[-1]["kind"], "waitress")
                for flag in ("--listen=127.0.0.1:8000", "--max-request-body-size=12582912",
                             "--max-request-header-size=32768", "--connection-limit=100"):
                    self.assertIn(flag, calls[-1]["args"])

    def test_unapplied_migrations_prevent_listening(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "start", extra={"DEPLOY_TEST_FAIL": "migrate"})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([c["kind"] for c in calls], ["manage", "manage"])

    def test_failed_collection_prevents_migration(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "build", extra={"DEPLOY_TEST_FAIL": "collectstatic"})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c["args"][0] == "migrate" for c in calls))

    def test_wildcard_proxy_prevents_listening(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "start", extra={"WAITRESS_TRUSTED_PROXY": "*"})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c["kind"] == "waitress" for c in calls))

    def test_exact_proxy_is_passed_to_selected_interpreter(self):
        for runner in self.runners():
            with self.subTest(runner=runner[0]):
                result, calls = self.run_script(runner, "start", extra={"WAITRESS_TRUSTED_PROXY": "127.0.0.1"})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--trusted-proxy=127.0.0.1", calls[-1]["args"])
                self.assertIn("--trusted-proxy-headers=x-forwarded-for x-forwarded-proto", calls[-1]["args"])

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper")
    def test_management_wrapper_uses_service_environment(self):
        runner = next(self.runners())
        result, calls = self.run_script(runner, "manage", arguments=("check", "--deploy"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0]["app_env"], "production")
        self.assertEqual(calls[0]["args"], ["check", "--deploy"])


if __name__ == "__main__":
    unittest.main()
