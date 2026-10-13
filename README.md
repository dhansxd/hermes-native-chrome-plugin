# Dyra Native Chrome — macOS preview

A standalone Hermes Python plugin that brackets native `browser_exec` and vault calls with capability-scoped admission to the user's original, headed Google Chrome. It registers only public `tool_execution` middleware: no replacement tools, provider overrides, Hermes core patches, self-updater, or copied browser profile.

**macOS release candidate 0.2.0a1.** The manifest-scoped verification build passed native browser/lifecycle/restart tests; replacement of the original production installation still requires an external maintenance window and post-install native readback. Not published or catalog-admitted. No license has been chosen yet.

## Requirements and consent

- macOS only. Registration is passive on other platforms, and controller/server launch refuses with `unsupported_platform` before spawning or creating state.
- A compatible Hermes runtime with general plugin middleware and `ctx.on_unload`. The actual minimum supported Hermes release remains to be established by isolated validation; no speculative `requires_hermes` floor is declared.
- Installed original Google Chrome, the agreed `Default` Chrome profile, and user-enabled remote debugging. Shared-profile cookies are shared across tasks; admission is not an account sandbox.
- Accessibility permission for the actual helper launch path. The backend contains exact Chrome/installed-Chrome-app consent-sheet automation and a bounded window-raise recovery path. This may press the remote-debugging Allow button or briefly change focus. **Explicit user authorization is required.** It is not authorization to bypass Hermes tool approvals. Whether automatic Chrome consent is compatible with catalog approval rules requires a maintainer ruling.
- Dependencies `aiohttp==3.14.3`, `psutil==7.2.2` and `PyYAML==6.0.3` are declared with Darwin-only PEP 508 markers in `plugin.yaml`. Use Hermes's package manager; do not install a second Python/virtualenv or point this plugin at an external runtime. PyYAML is explicit: a clean Hermes environment does not guarantee the `yaml` import.

## Explicit lifecycle

Installation/enablement and attachment are separate. Import, discovery and registration do not launch Chrome, create tokens, listen on ports, or change configuration. The middleware reads both profile plugin selection and strict committed lifecycle intent on **every call**. Missing/detached intent or disabled selection delegates the original argument object to the native handler exactly once, without admission or rewriting.

The commands below are operator procedures, **not actions already performed**:

```sh
# Once a public owner repository exists, use the normal installer (no repository is published yet):
hermes plugins install OWNER/REPOSITORY --no-enable
hermes plugins enable dyra-native-chrome

# Run the installed helper with the effective Hermes Python, not system Python.
# Set PLUGIN_DIR to the installed plugin directory and HERMES_HOME to the intended profile.
python "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" status
python "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" --exclusive-config attach
python "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" --exclusive-config detach

# Remove only after detach completed successfully, not while it reports draining:
hermes plugins remove dyra-native-chrome
```

`--exclusive-config` confirms that no other config writers will run during the operation: Hermes does not expose a compare-and-swap config API. The helper uses official `hermes config set/unset` and `hermes plugins enable/disable`, verifies their effects, and preserves a baseline only when it can establish it. It does not assume existing loopback browser settings or old ownership state are trustworthy. Restoration changes only settings still equal to this helper's installed values; intervening user changes survive. Disable alone is not detach and need not hot-reload an existing process.

Data belongs to the effective profile:

```text
$HERMES_HOME/plugin-data/dyra-native-chrome/
  lifecycle.json     strict desired_enabled + committed phase + restoration metadata
  lifecycle.lock    lifecycle operation lock
  control-token     local broker bearer credential (owner-only regular file, 0600)
  ownership.json    strict ownership/uncertainty journal
```

No state is written beside the source tree. Registration captures the context's profile home, otherwise the Hermes home API; standalone callers pass `--home` or use `HERMES_HOME`. Port defaults to 19347; attach can select another port with `--port`. Another profile on the same port is an explicit `profile_conflict`, not a service to stop or reuse.

### Reversible candidate activation (operator-only, pending native acceptance)

The public production ID remains **`dyra-native-chrome`**. Reversible test forks may use **`dyra-native-chrome-candidate`** or **`dyra-native-chrome-verification`**, each with isolated state and daemon names. `plugin_identity.plugin_id()` reads the adjacent `plugin.yaml` name and rejects unknown/malformed identities; there is no environment/global identity override. Changing that one manifest field cascades through selection, lifecycle `PLUGIN`, profile data, authenticated service identity and named-harness registration. Source relocation does not change service identity or daemon names. The path-specific private loader namespace is only Python import isolation, not runtime service identity.

`harness_prefix()` preserves `dyra-` for production and uses `8b000-` for this candidate. `daemon_name(namespace)` is the single shared middleware/broker naming API: the namespace is compact JSON `[plugin_id, task_id, session]`, and the SHA-256 input additionally binds the plugin ID. Names contain at most six safe ASCII prefix characters plus twenty hex characters; production hashes intentionally change from the legacy namespace. The installed named IPC formatter yields 102-byte production and 103-byte candidate socket paths under the current long home, below macOS's 104-byte AF_UNIX capacity. Longer runtime directories still require a path-length preflight; bounded names cannot guarantee arbitrary-home compatibility.

**Do not copy an in-progress parallel staging tree.** Only after the parent accepts all sibling merge handoffs, reruns full staging discovery/packaging gates and freezes the input may it execute this recipe. It has not been executed here. The destination is outside staging and the active checkout; refuse an existing destination rather than overwrite it:

```sh
export STAGE="$HOME/.local/share/dyra-ai/native-chrome/packaging-stage"
export CANDIDATE_DIR="$HOME/.local/share/dyra-ai/native-chrome/candidate-stage/dyra-native-chrome-candidate"
# PYTHON must be the effective Hermes interpreter.
"$PYTHON" - <<'PY'
import os
from pathlib import Path
import shutil
source = Path(os.environ['STAGE']).resolve()
destination = Path(os.environ['CANDIDATE_DIR']).resolve()
if destination.exists():
    raise SystemExit('candidate destination already exists')
destination.mkdir(parents=True)
for path in sorted(source.glob('*.py')):
    shutil.copy2(path, destination / path.name)
for name in ('plugin.yaml', 'README.md'):
    shutil.copy2(source / name, destination / name)
manifest = destination / 'plugin.yaml'
text = manifest.read_text()
if text.count('name: dyra-native-chrome\n') != 1:
    raise SystemExit('unexpected production manifest')
manifest.write_text(text.replace('name: dyra-native-chrome\n',
                                'name: dyra-native-chrome-candidate\n', 1))
# Assert all copied bytes except the one permitted manifest change match.
for path in destination.iterdir():
    if path.name != 'plugin.yaml':
        assert path.read_bytes() == (source / path.name).read_bytes()
PY
# Review and commit the deterministic production-code copy; no runtime data,
# tokens, journals, logs, evidence, virtualenvs, browser profiles or .git copy.
git -C "$CANDIDATE_DIR" init
git -C "$CANDIDATE_DIR" add -- '*.py' plugin.yaml README.md
git -C "$CANDIDATE_DIR" commit -m 'Build manifest-only native Chrome candidate'
git -C "$CANDIDATE_DIR" rev-parse HEAD
```

Record the staged input hashes and full candidate commit SHA. Use the supported committed local `file://` Git source with `--ref FULL_SHA --no-enable` (and dependency flags only after checking the official installed CLI). Install the candidate **alongside**, not over, the active production package. Never replace its checkout/symlink, bypass the live-gateway remove guard, patch Hermes core, or restart the runtime hosting the operation. Keep the candidate disabled until its explicitly authorized activation window. Candidate shares the intended profile home and original Chrome account, but requires distinct ID/data and an explicitly chosen separate unused loopback port, for example `--port 19348`; the default 19347 is not automatically reassigned by manifest identity.

Before attach, preserve the exact raw browser settings and enabled/disabled plugin selection. Existing older production middleware may lack per-call selection gating/unload, so bare disable does **not** prove it stopped routing. Official candidate enable can nudge forced rediscovery: the parent must independently verify the loaded candidate generation and retirement of old routing **before any `browser_exec`**, otherwise stop the gate without making a browser call. Two selected overlapping middlewares are not a supported simultaneous activation. This source change alone does not establish safe hot switching from the older active installation.

After authorized testing, use the candidate's own lifecycle detach, require quiet named-daemon/broker cleanup and restoration readback, then restore the original plugin selection through official commands. Lifecycle detach disables the candidate but does not restore a separately changed production selection; that restoration is the parent's responsibility. If work/transfer uncertainty blocks detach, retain the disabled/pending state and ownership data for reconciliation instead of forcing cleanup. A bare disable is selection-only, not a substitute for drain/detach. Leave the candidate disabled pending guarded removal when the live runtime still prevents remove; do not bypass the guard. Preserve the working production installation throughout.

Native acceptance under the candidate fork proves only that fork's tested operations and cleanup. It is **not production-ID rollout proof**, compatibility approval or catalog admission. Production rollout still requires its own authorization, loaded-generation verification and native continuity/lifecycle gates. No installation, activation, account operation or production replacement is authorized by the recipe itself.

### Drain and unload semantics

`Controller(home=..., port=..., token_file=...).detach(timeout=5)` does not call `ensure()` or start anything. It verifies authenticated service/profile identity first. A refused listener returns `absent`; a responding unknown, old-protocol, inaccessible or different-profile listener fails closed. Authenticated `/control/detach` stops new admissions immediately and waits at most ten seconds for leases, operations and transfer guards, plus a 250 ms downstream socket-close budget. Results are `detached` with no blockers or `blocked` with `active_calls`, `pending_operations`, `transfers` and/or `clients`. The lifecycle helper remains `draining` until a later retry succeeds.

Drain never kills active operations, forcibly clears transfer uncertainty, sends `Browser.close`, closes manual windows, or erases preserved ownership. It revokes runtime capabilities only once quiet and stops idle sweeping while drained. A successful drain publishes a runtime-only `drain_id`; another drain invalidates that proof. Busy/mutation-pending recovery guards, scope locks and journal commits also block a quiet result.

For the standalone child, `lifecycle.default_drain` then calls `Controller.stop(drained)`. `/control/stop` requires the profile bearer token, exact resolved home, an explicit valid `desired_enabled: false` detaching/detached intent for the listener port, the current quiet-drain proof and a fresh blocker check. Absent/corrupt intent is not permission. Only the owning stoppable runner accepts termination. It flushes `stopping` before signaling its own async stop event, closes the listener, closes downstream capability sockets and upstream WebSocket/HTTP transports, and exits without PID signals or process guessing. The lifecycle helper observes listener refusal before restoration/disable. A blocked drain never requests termination; a later absence is idempotent.

The soft cleanup path does not invoke generic `SessionBroker.shutdown`, sweep targets, send CDP destruction commands, or clear retained ownership, unknown-create reservations or uncertainty journals. Existing disconnect methods close transports only; loopback WebSocket QA verifies zero upstream CDP messages and preserved records. Registered named driver generations are now retired through authenticated IPC after downstream disconnection, with bounded exit observation. A private metadata-only `harness-inventory.json` survives broker crashes and binds exact PID creation time, UID and socket identity to the profile/plugin and trusted ownership namespace; endpoints, capabilities and flattened sessions are not persisted. Unknown admission tombstones, changed generations, corrupt records or unresolved activity/transfer guards block cleanup. A separate profile/identity service lock fences the broker lifetime against offline cleanup, including inherited-descriptor startup. Native verification has exercised first-call Chrome-only cold, broker crash and combined cold recovery, followed by daemon exit and unchanged Chrome windows at detach; this bounded coverage is not indefinite reliability. An embedded `make_app` without an owning stop event is drain-only (`stop_required: false`) and cannot terminate its host; its drain success is not complete daemon uninstall evidence. A subsequent committed attach can start a new authenticated child; transfer reconciliation and preserved-resource disposition remain explicit safety gates.

`ctx.on_unload` retires only this middleware/controller generation and local endpoint cache. In-flight calls keep their own lease until their normal `finally` release. It never invokes profile-global drain, restores config, kills browser processes, or revokes another process's leases.

## Architecture and disclosures

- On the first admitted call, the effective Hermes Python starts a long-running loopback aiohttp broker. Marker health is not proof of Chrome ownership or first-call driver readiness.
- The broker reads Chrome runtime endpoint files, process/listener metadata, executable/signature provenance, Chrome Local State, installed Chrome-app bundles and registrar routing metadata outside its own plugin data. These reads and browser-profile access require explicit disclosure in a catalog submission.
- Native startup/consent, process identity and installed-app launch use bounded subprocesses, including macOS tools and `/usr/bin/open`. It never launches a separate managed/cloud browser as a fallback.
- Browser and vault operations remain native Hermes tools. Middleware prepends a trusted execution preamble restoring exact selection and installing app-routing helper wrappers. It does not replay model code or navigate merely to recover binding.
- **Private API dependency:** named browser-harness `_ipc`, daemon startup helpers and Hermes browser supervisor/CDP override internals are used for exact target binding. Context home capture prefers `ctx.home`, falls back to private `ctx._manager.home_path`, then uses `get_hermes_home()`; that private manager seam must be validated against the installed host. App helpers wrap functions in the browser execution namespace. These are not a stable public extension contract and can break after upgrades.
- Flat bundled modules are loaded under path-specific private module names, without replacing generic `controller`, `native`, or other host modules and without adding the checkout to host `sys.path`. The loader uses dynamic local-code execution and `sys.modules` entries only for its own namespace, including dataclass support. Scanner/reviewer findings must be reviewed, not hidden or bypassed.
- Control credentials and runtime capabilities are sensitive. The token is retained locally; URLs, page contents, credential values, flattened-session IDs and live capabilities are not ownership-journal fields. Same-user access is not a hostile-user sandbox.
- There is no telemetry/self-update mechanism added by this package. Browser third-party traffic follows the user's native actions.

## Status and failures

Lifecycle CLI exits 0 on completion, 3 while draining and 2 on error. A passive `status` reports lifecycle intent, not broker readiness, Chrome consent, account authentication or native-tool acceptance. Named failures include `unsupported_platform`, `ambiguous_baseline`, `config_conflict`, invalid lifecycle/config data, official-command/verification failure, `profile_conflict`, `detached`, startup/consent/AX failures, journal failures, lease conflicts, stale driver, resource limits and uncertain upstream outcomes. Safety refusals do not permit mutation replay or deletion of state to make status green.

## Verification and catalog eligibility

Packaging/lifecycle tests run against fake controllers and isolated temporary homes. Shutdown QA uses real server children and loopback HTTP to verify unauthorized/wrong-home refusal, pending/busy refusal, stop acknowledgment, listener absence, child exit and idempotent absence; WebSocket fixtures verify transport-only closure without Chrome. All new QA homes are temporary scratch directories, not named profiles:

```sh
python -m unittest discover -s tests -v
```

No live install, doctor, catalog validation, Chrome/account operation, or runtime restart is authorized by these tests. The parent must validate the merged bundle in an isolated profile and run native acceptance separately.

Current official admission rules: <https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission>. Before submission, an owner must choose a license, publish a loadable public repository and exact full SHA, establish truthful compatibility metadata, then run `hermes plugins doctor` and `hermes plugins validate /path/to/plugin --install-deps` through the effective Hermes environment. Review every caution; dangerous findings must be fixed. Public middleware alone does not establish eligibility: private IPC/supervisor access, execution-namespace wrappers, dynamic loader namespace, browser-profile reads and automated Chrome consent need explicit reviewer acceptance or a supported public hook replacement. This preview makes **no catalog-eligibility promise** and must not bypass the scanner. No catalog PR, GitHub publication or pin exists yet.
