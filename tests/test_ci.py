"""Publication CI contract: pinned host, isolated runtime, no live browser."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class CITests(unittest.TestCase):
    def test_ci_runs_fixtures_and_official_gates_on_pinned_macos_host(self):
        path = ROOT / '.github/workflows/ci.yml'
        self.assertTrue(path.is_file(), 'portable macOS CI workflow missing')
        workflow = yaml.safe_load(path.read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'tests', 'plugin-checks'})
        for job in jobs.values():
            self.assertEqual(job['runs-on'], 'macos-15')
            self.assertLessEqual(job['timeout-minutes'], 30)
        fixture = '\n'.join(step.get('run', '') for step in jobs['tests']['steps'])
        self.assertIn('requirements-test.txt', fixture)
        self.assertIn('-W error -m unittest discover -s tests -v', fixture)
        official = jobs['plugin-checks']['steps']
        upstream = next(step for step in official if step.get('with', {}).get('repository') == 'NousResearch/hermes-agent')
        self.assertEqual(upstream['with']['ref'], 'd02f211858ab202d6d4d34ea59774591a5f14cbd')
        script = '\n'.join(step.get('run', '') for step in official)
        for contract in ('HERMES_HOME', 'HERMES_RUNTIME_DIR', 'HERMES_REAL_HOME',
                         '--without agent-browser', '--without cua-driver',
                         'plugins doctor', '--ci', 'plugins validate', '--json'):
            self.assertIn(contract, script)
        self.assertIn('mv "$GITHUB_WORKSPACE/.ci-hermes" "$RUNNER_TEMP/official-hermes"', script,
                      'validator must not recursively scan the upstream host as plugin payload')
        self.assertNotIn('plugins enable', script)
        self.assertNotIn('--install-deps', script)


if __name__ == '__main__':
    unittest.main()
