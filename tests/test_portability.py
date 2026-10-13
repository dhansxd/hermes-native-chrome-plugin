"""Run every runtime fixture in a child with no personal Hermes home."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PortabilityTests(unittest.TestCase):
    def test_full_suite_works_with_fresh_home(self):
        with tempfile.TemporaryDirectory(prefix='nc-home-') as directory:
            home = Path(directory) / 'unrelated-user'
            home.mkdir()
            env = dict(os.environ)
            for key in tuple(env):
                if key.startswith(('BH_', 'BU_', 'HERMES_')):
                    env.pop(key)
            env.update(HOME=str(home), HERMES_HOME=str(home / '.hermes'))
            # Exclude only this outer gate, not any runtime/safety fixture.
            code = '''
import unittest
suite = unittest.defaultTestLoader.discover('tests')
def cases(node):
    for item in node:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        elif type(item).__module__ != 'test_portability':
            yield item
selected = unittest.TestSuite(cases(suite))
assert selected.countTestCases() >= 101, selected.countTestCases()
result = unittest.TextTestRunner(verbosity=2).run(selected)
raise SystemExit(not result.wasSuccessful())
'''
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                                    env=env, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((home / '.hermes').exists(), 'fixtures wrote a personal Hermes home')


if __name__ == '__main__':
    unittest.main()
