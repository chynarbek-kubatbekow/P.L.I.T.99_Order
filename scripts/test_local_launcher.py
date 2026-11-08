"""Run the real local launchers in disposable folders with a fake Django command."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class LocalLauncherTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='plit-local-profile-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name) / 'app with spaces'
        self.root.mkdir()
        (self.root / 'scripts').mkdir()
        for name in ('scripts/local.py', 'scripts/deploy-common.ps1', 'scripts/deploy-common.sh', 'run-local.ps1', 'run-local.sh'):
            shutil.copyfile(ROOT / name, self.root / name)
        package = self.root / 'django' / 'core'
        package.mkdir(parents=True)
        (package.parent / '__init__.py').write_text('')
        (package / '__init__.py').write_text('')
        (package / 'management.py').write_text('''import os, json
from pathlib import Path
def execute_from_command_line(argv):
    names = ('APP_ENV', 'LOCAL_PREVIEW', 'DEBUG', 'SECURE_SSL_REDIRECT',
             'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE', 'ALLOWED_HOSTS',
             'CSRF_TRUSTED_ORIGINS', 'APP_DATA_DIR')
    data = {name: os.getenv(name) for name in names}
    data['args'] = argv[1:]
    data['migration_credentials_present'] = bool(os.getenv('MIGRATION_DATABASE_URL'))
    Path(os.environ['LOCAL_TEST_RECORD']).write_text(json.dumps(data))
''', encoding='utf-8')
        self.config = self.root / '.env'
        self.config.write_text(
            f'PYTHON_EXECUTABLE="{Path(sys.executable).as_posix()}"\n'
            'APP_ENV=production\nSECURE_SSL_REDIRECT=True\nSESSION_COOKIE_SECURE=True\n'
            'CSRF_COOKIE_SECURE=True\nAPP_DATA_DIR=existing-data\n', encoding='utf-8')
        self.digest = hashlib.sha256(self.config.read_bytes()).digest()
        self.record = self.root / 'result.json'
        self.env = {key: value for key, value in os.environ.items()
                    if key.upper() in {'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'COMSPEC'}}
        self.env['LOCAL_TEST_RECORD'] = str(self.record)
        self.env['MIGRATION_DATABASE_URL'] = 'test-only-migration-value'

    def run_local(self, launcher, arguments=()):
        self.record.unlink(missing_ok=True)
        result = subprocess.run(launcher + list(arguments), cwd=self.root.parent,
                                env=self.env, capture_output=True, text=True, timeout=30)
        return result

    def assert_local_profile(self, expected_command):
        data = json.loads(self.record.read_text())
        self.assertEqual(data['args'], expected_command)
        self.assertEqual(data['APP_ENV'], 'local')
        self.assertEqual(data['LOCAL_PREVIEW'], 'True')
        for key in ('DEBUG', 'SECURE_SSL_REDIRECT', 'SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE'):
            self.assertEqual(data[key], 'False')
        self.assertFalse(data['migration_credentials_present'])
        self.assertEqual(data['APP_DATA_DIR'], 'existing-data')
        self.assertEqual(hashlib.sha256(self.config.read_bytes()).digest(), self.digest)

    def test_direct_python_defaults_to_loopback_with_production_config_unchanged(self):
        result = self.run_local([sys.executable, str(self.root / 'scripts/local.py')])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_local_profile(['runserver', '127.0.0.1:8001'])

    def test_local_management_commands_use_same_existing_data(self):
        for command in ('migrate', 'createsuperuser', 'check'):
            result = self.run_local([sys.executable, str(self.root / 'scripts/local.py')], (command,))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_local_profile([command])

    def test_optional_local_env_does_not_replace_production_env(self):
        (self.root / '.env.local').write_text('APP_DATA_DIR=local-only-data\n', encoding='utf-8')
        result = self.run_local([sys.executable, str(self.root / 'scripts/local.py')], ('check',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.record.read_text())['APP_DATA_DIR'], 'local-only-data')
        self.assertEqual(hashlib.sha256(self.config.read_bytes()).digest(), self.digest)

    def test_local_launcher_rejects_public_bind(self):
        result = self.run_local([sys.executable, str(self.root / 'scripts/local.py')], ('runserver', '0.0.0.0:8001'))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())

    def test_powershell_and_bash_wrappers_keep_local_and_production_separate(self):
        launchers = []
        if os.name == 'nt':
            launchers.append([str(Path(os.environ['SYSTEMROOT']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
                              '-NoProfile', '-NonInteractive', '-File', str(self.root / 'run-local.ps1')])
        bash = shutil.which('bash')
        if os.name == 'nt':
            candidate = Path('C:/Program Files/Git/bin/bash.exe')
            bash = str(candidate) if candidate.exists() else None
        if bash:
            launchers.append([bash, str(self.root / 'run-local.sh')])
        for launcher in launchers:
            result = self.run_local(launcher)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_local_profile(['runserver', '127.0.0.1:8001'])


if __name__ == '__main__':
    unittest.main()
