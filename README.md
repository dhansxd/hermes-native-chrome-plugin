# Hermes Native Chrome Plugin

A macOS-only Hermes Agent plugin for native `browser_exec` against your original, headed Google Chrome profile. Installed Chrome web apps are preferred over ordinary tabs when their profile, manifest scope and display mode can be verified.

**Preview 0.2.0a1 · MIT · not yet admitted to the Hermes Community catalog.** Repository name: `hermes-native-chrome-plugin`; installed plugin ID: `dyra-native-chrome`.

## What it does

- Registers public `tool_execution` middleware; keeps the native browser/vault tools and schemas rather than adding MCP tools or replacing handlers.
- Starts a private loopback broker on demand, binds task sessions to verified targets, and never silently falls back to headless/cloud Chromium or copied cookies.
- Refreshes installed-app routing metadata and keeps app selection across native calls.
- Supports explicit attach, detach/config restoration, quiet daemon shutdown and metadata-only crash recovery.
- Preserves user-created/borrowed browser resources. Uncertain mutations and incomplete transfers block unsafe cleanup; they are not erased to make shutdown look successful.

## Tested compatibility

- macOS arm64; local native acceptance on macOS 27.0.1 and Google Chrome 155.0.8059.39.
- Hermes `v0.21.5+8817.gd02f211` at full commit `d02f211858ab202d6d4d34ea59774591a5f14cbd`.
- Python 3.14.7 and `browser-harness==0.1.13` supplied by the tested Hermes installation.
- Darwin requirements: `aiohttp==3.14.3`, `psutil==7.2.2`, `PyYAML==6.0.3`.

This is a tested revision, **not a proven minimum version or support promise for every newer Hermes release**. No speculative minimum `requires_hermes` is declared. Linux/Windows/WSL are unsupported; platform metadata is supplemented by runtime guards. Private harness/supervisor seams require upgrade revalidation.

## Browser access and consent

Use the original Chrome **Default** profile and enable its remote-debugging option. The plugin reads process/listener metadata, Chrome endpoint files, Local State, installed app bundles and registrar metadata to prove profile/app identity. It does not export your Chrome profile or store cookies/passwords in its journals.

The macOS helper needs Accessibility permission on its actual launch path. During a bounded pending debugging connection it can press the exact English/Indonesian Chrome remote-debugging consent button, including verified Chrome web-app sheets, and may briefly raise a Chrome window. **Authorize that behavior before attaching.** This is separate from Hermes tool approvals. Other locales and arbitrary applications are not covered. Shared-profile accounts/cookies are shared across tasks; target admission is not an account sandbox.

## Install and attach

```sh
hermes plugins install dhansxd/hermes-native-chrome-plugin --no-enable
```

For a reproducible installation add `--ref FULL_40_CHARACTER_REVIEWED_SHA`. Do not reinstall/update/remove installed files while their gateway is active if the official manager refuses it; schedule an external maintenance window instead of bypassing the guard.

Use the Python interpreter selected by **your Hermes package manager**, not an unrelated system Python. Set `EFFECTIVE_PYTHON` to that interpreter, and select the intended profile home:

```sh
export HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
export PLUGIN_DIR="$HERMES_HOME/plugins/dyra-native-chrome"
"$EFFECTIVE_PYTHON" "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" status
"$EFFECTIVE_PYTHON" "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" --port 19347 --exclusive-config attach
```

Attach performs official plugin enable/dependency admission and takes over only the required browser keys. Registration alone is passive: no Chrome launch, token or listener. Pick a free port or use `--port` to avoid another profile/service. `--exclusive-config` acknowledges that unrelated config writers must stay inactive during the transaction; public config CLI is not compare-and-swap.

A preexisting identical endpoint without this package's lifecycle ownership is `ambiguous_baseline`, not something to overwrite. Preserve any old integration's routing privately and decide its migration baseline explicitly. Do not reuse old tokens or journals under a new identity.

Once attached, the agent uses ordinary native `browser_exec` helpers. App routing is automatic; it does not need app-specific bootstrap code.

## Detach, disable and remove

```sh
"$EFFECTIVE_PYTHON" "$PLUGIN_DIR/lifecycle.py" --home "$HERMES_HOME" --exclusive-config detach
# After successful detach, and with the gateway offline when required:
hermes plugins remove dyra-native-chrome
```

**Bare `hermes plugins disable` is not full detach.** In the tested Hermes version it changes selection for subsequent loading, not a complete synchronous cleanup/config restoration. The package helper revokes admission, drains quiet work, retires verified registered daemons and stops its own broker before restoring config values still owned by the package. User-changed values survive. A busy/uncertain result stays `draining`; retry or reconcile explicitly, never clear journals or force-kill Chrome.

`ctx.on_unload` releases only the local controller generation; reload is not uninstall intent. Manual/borrowed Chrome windows and profile data are not deleted. Persistent plugin data is retained by default; purge is separate. Removing a developer symlink can be rejected by a manager containment check before its link-only branch—verify the actual manager behavior before migration and never delete the resolved target as a workaround.

## State and recovery

Profile-scoped data lives in `$HERMES_HOME/plugin-data/dyra-native-chrome/`:

- `lifecycle.json` / `lifecycle.lock`: durable config transaction and desired state.
- `control-token`: private mode-0600 broker control credential.
- `ownership.json`: metadata-only browser ownership/uncertainty journal.
- `harness-inventory.json`: exact named-daemon process/socket generations and unknown-admission tombstones, without endpoint capabilities or flattened sessions.

A separate identity/profile-bound `.dyra-service-locks` registry beside the profile home fences the broker lifetime against offline cleanup; its stable owner-only lock inode must not be unlinked during normal use. Shared runtime strings/capabilities remain in memory. These files are not included in the repository.

Recovered inventory is revalidated against trusted ownership and live IPC. Corrupt records, replaced generations, unknown admission outcomes, active operations and unresolved transfers refuse cleanup. The code does not infer ownership from a `dyra-*` name scan. Historical daemons without prior registration are outside its cleanup authority.

## Verification

The initial release runtime passed 101 local tests and real Telegram-native gates: ordinary-page readback/continuity, installed-app preference/continuity, first calls after Chrome-only cold, owned-broker crash and combined cold, plus detach/re-attach, exact registered daemon exit and Chrome/window preservation. Production installation SHA/checksums and three post-maintenance native calls were independently verified. Publication changes to tests/docs do not modify those runtime bytes.

CI runs isolated unit and real loopback/harness fixtures **without Chrome/account access**. CI does not prove native Accessibility/consent behavior on a user's computer, authentication, indefinite uptime, sleep/wake or every website. Test counts and results for each revision come from the actual workflow output.

```sh
python -W error -m unittest discover -s tests -v
hermes plugins doctor /path/to/plugin --ci
hermes plugins validate /path/to/plugin --json
```

`validate --install-deps` can mutate a dependency environment: use an isolated one and inspect stderr, not just exit0 or scanner JSON. No general lint/typecheck gate is claimed.

## Architecture and limits

- Local aiohttp broker, capability-scoped targets, write-ahead metadata and exact process/profile identity checks.
- Installed app selection uses verified registrar scope/display-mode evidence and deterministic unreserved target selection; not every Chrome build exposes identical PWA/CDP capabilities.
- Middleware prepends a trusted helper installer restoring exact target/session binding without replaying model code. It wraps opening helpers, not arbitrary script text.
- **Private APIs:** browser-harness `_ipc` and daemon startup helpers, Hermes browser supervisor/CDP resolution, and fallback context-home capture through `ctx._manager.home_path`. These can break on upgrades; public middleware does not make all internals stable.
- Bundled modules load in a private path-specific Python namespace, without replacing generic host module names. Dynamic local-code loading, browser-profile reads, subprocesses, background service and automated consent are disclosed for scanner/maintainer review.
- No Hermes core patches, self-updater or additional telemetry. Same-user local access is not a hostile-user security sandbox.

## Community catalog

Public GitHub availability is not catalog acceptance. Submission requires a reviewed full SHA, truthful platform/capability metadata and maintainer review of the private seams and automated consent. No catalog PR or acceptance is claimed here.

[Official plugin guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins) · [Catalog submission](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission)

## License

MIT; see [LICENSE](LICENSE). Chrome, Hermes and browser-harness remain separate dependencies with their own licenses.
