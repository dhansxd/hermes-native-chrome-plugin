"""Private, ephemeral fixture space; never use the user's Hermes directory."""
import atexit
import os
from pathlib import Path
import tempfile

# Resolve macOS /var -> /private/var before creating children: journals reject
# symlink ancestors, and path identity assertions must compare canonical paths.
_SPACE = tempfile.TemporaryDirectory(prefix='n-', dir=Path(tempfile.gettempdir()).resolve())
atexit.register(_SPACE.cleanup)
SCRATCH = Path(_SPACE.name)
# Configure before importing browser_harness: its IPC paths are import-time values.
os.environ['BH_RUNTIME_DIR'] = str(SCRATCH)
os.environ['BH_TMP_DIR'] = str(SCRATCH)
