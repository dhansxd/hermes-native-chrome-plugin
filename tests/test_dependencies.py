"""Platform markers must constrain this macOS-only payload."""
import unittest
from pathlib import Path
import yaml
from packaging.requirements import Requirement

class DependencyTests(unittest.TestCase):
    def test_yaml_import_has_declared_dependency(self):
        manifest = yaml.safe_load((Path(__file__).resolve().parents[1] / 'plugin.yaml').read_text())
        names = {Requirement(text).name.lower() for text in manifest['python_dependencies']}
        self.assertIn('pyyaml', names, 'fresh Hermes generation does not guarantee yaml module')

    def test_runtime_dependencies_apply_to_darwin_only(self):
        manifest = yaml.safe_load((Path(__file__).resolve().parents[1] / 'plugin.yaml').read_text())
        for text in manifest['python_dependencies']:
            requirement = Requirement(text)
            with self.subTest(dependency=requirement.name):
                self.assertIsNotNone(requirement.marker, 'macOS dependency must not constrain other platforms')
                for platform in ['darwin', 'linux', 'win32', 'android']:
                    self.assertEqual(requirement.marker.evaluate({'sys_platform': platform}), platform == 'darwin')
