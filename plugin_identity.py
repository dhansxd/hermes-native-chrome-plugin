"""Passive identity from this bundle's adjacent manifest; no global override."""
import hashlib
import json
from pathlib import Path


def plugin_id() -> str:
    """Return the identity declared by this installed or relocated bundle."""
    import yaml  # Dependency is Darwin-only; unsupported discovery stays passive.
    try:
        manifest = yaml.safe_load(Path(__file__).with_name('plugin.yaml').read_text())
        name = manifest.get('name') if isinstance(manifest, dict) else None
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError('unsupported_plugin_identity') from error
    if name not in ('dyra-native-chrome', 'dyra-native-chrome-candidate', 'dyra-native-chrome-verification'):
        raise ValueError('unsupported_plugin_identity')
    return name


def harness_prefix() -> str:
    """Safe bounded IPC prefix; retain the production spelling, not old hashes."""
    identity = plugin_id()
    if identity == 'dyra-native-chrome':
        return 'dyra-'
    return hashlib.sha256(identity.encode('ascii')).hexdigest()[:5] + '-'


def daemon_name(namespace: str) -> str:
    """One exact name for middleware and broker registration, never path-scoped.

    Names use at most six ASCII prefix bytes plus twenty hexadecimal bytes.
    The caller passes its compact JSON identity/task/session namespace unchanged.
    Identity is also hashed here so even identical caller namespaces cannot
    collide between production and candidate bundles. This is not a credential.
    """
    binding = json.dumps([plugin_id(), namespace], separators=(',', ':'), ensure_ascii=True)
    return harness_prefix() + hashlib.sha256(binding.encode('ascii')).hexdigest()[:20]
