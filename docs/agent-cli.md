# npm projects and agent usage

Run Rivet from the project directory. `package.json` supplies the project name,
dependencies, development dependencies, and scripts. `rivet.lock` pins the
verified graphs for all four supported targets. Rivet leaves `package-lock.json`
untouched; it does not import npm's lock or claim that its resolution is identical.

```sh
rivet install
rivet install -D prettier@3.5.3
rivet ci
rivet run --allow-write ./dist build
rivet exec prettier -- --check src
rivet remove prettier
rivet update
```

`install <package...>` saves the supplied ranges and installs the resulting graph.
An omitted range is saved as `latest`. `-D` saves to `devDependencies`. Existing
development dependencies stay in that section when updated. `add <package>`
remains a manifest-only operation for compatibility with earlier Rivet releases.
`remove` also removes entries from development dependencies. `update` refreshes
all dependencies within their declared ranges; targeted updates are not supported.

`ci` uses the existing Rivet lockfile and fails if it is missing or stale. It
rechecks signed release status and installed content. It never updates the
manifest or lock, and keeps the old installation until a replacement is ready.
Existing node_modules created by another manager are refused; move them aside
explicitly before migrating. Repeating install still performs verification and
materialization; this release does not promise a no-work warm install.

An optional `rivet.toml` alongside package.json may contain only `[policy]`:

```toml
[policy]
min_release_age_hours = 72
allow_scripts = ["esbuild"]
allow_network = ["dev"]
```

`rivet init` in an npm project creates a policy file without changing package.json.
Legacy projects with only rivet.toml continue to work. A project with both an npm
manifest and a full legacy Rivet manifest is refused until dependencies and
scripts are consolidated into package.json. There are never two dependency sources.

Supported root fields include dependencies, devDependencies, scripts, name and
version. Unknown descriptive/tool fields are preserved when editing package.json,
although formatting is normalized. Root workspaces, overrides, optionalDependencies,
peerDependencies and bundledDependencies are currently refused when nonempty.
Transitive optional dependencies, aliases, and contextual peers retain their
existing support. Git, URL, local file, and workspace dependency specs are refused.
This is a single-package compatibility increment, not complete npm parity.

## Project scripts

`rivet run <name>` selects a project script first, then falls back to the existing
installed binary behavior. `rivet exec <name>` always selects an installed binary
and never downloads a missing command implicitly. Generated .bin shims use exec,
so a same-named project script cannot redirect them.

Before a project script runs, Rivet verifies the entire installed dependency tree
and builds temporary binary wrappers from the verified receipt. Shell operators
in the project-authored script work, while extra CLI arguments are quoted as data.
The script runs under the same OS sandbox as package commands. Network, credential
environment variables, and project writes require explicit grants. Place Rivet
flags before the script/command name and use `--` before child arguments.

```sh
rivet run --allow-write ./dist --json build -- --mode production
```

Create write-grant directories first. Package manifests, lockfiles, node_modules,
and .rivet controls remain protected inside broader write grants. Declared script
permissions do not grant access. Root install lifecycle hooks and automatic
pre/post script hooks are not run. npm's injected environment-variable set and
nested `npm run` are not emulated. Even dependency-free scripts need an initial
`rivet install` to establish the verified empty installation.

## Machine output

`--json` emits one JSON result on stdout. Object results include
`schema_version: 1` and `ok`. Failure results contain an `error` object with `code`,
`message`, `retryable`, and `suggestion`. `--events` instead emits newline-delimited
JSON, with `schema_version: 1` and `event` in each record. The flags are mutually
exclusive. Diagnostics and child stdout/stderr go to stderr in machine mode.
Successful human-mode runs retain ordinary child stdout.

Install events are flushed at the start of installation, before resolution,
after resolution, before materialization, and upon completion. A plan emits
`plan.created`, not `install.completed`. A failed command ends with
`command.failed`. Run events bracket actual execution. Progress does not currently
include byte counts, individual audit jobs, or per-package download completion.

Common codes:

| Code | Agent response |
| --- | --- |
| PROJECT_BUSY | Retry with backoff after the other project operation finishes |
| PROJECT_CHANGED | Review concurrent manifest/policy/lock edits before retrying |
| LOCKFILE_STALE | Regenerate and review rivet.lock before running ci |
| INVALID_ARGUMENTS / INVALID_MANIFEST | Fix the input |
| UNSUPPORTED_PROJECT / UNSUPPORTED_DEPENDENCY | Report the unsupported feature |
| AUTH_REQUIRED | Configure the required registry credentials |
| AUDIT_PENDING | Wait for the registry audit to finish, then retry with backoff |
| POLICY_REFUSED / INTEGRITY_FAILED | Inspect the evidence; do not automatically weaken policy |
| REGISTRY_UNAVAILABLE / REGISTRY_BUSY | Retry with backoff when retryable is true |
| PROCESS_FAILED | Inspect stderr; process exit status is preserved |
| OPERATION_FAILED | Inspect the message; this covers errors without a narrower typed classification |

Argument errors exit 2, ordinary Rivet failures exit 1, and child failures preserve
their exit status. New optional fields and event names may be added within schema
version 1; consumers should tolerate them. Human-readable messages are not stable
identifiers. The JSON contract is documented by `cli-result.schema.json` and
`event.schema.json`.

## Plans, concurrency, and local reuse

`rivet install <package> --plan --json` reports the dependency map before and after,
selected packages, and install-script requests. It does not edit the manifest,
lockfile, or installed tree. Planning can contact the registry, trigger imports
and audits, pin its key, and create local coordination files. Applying a later
command re-resolves/revalidates; plans are not authorization tokens or immutable
transactions.

Project mutations and executions take a nonblocking advisory lock under .rivet.
Another Rivet process receives PROJECT_BUSY. External editors are not locked out;
installation checks manifest, policy and lock bytes again before committing.
Downloaded packages have per-artifact process locks in the shared local store,
so concurrent projects can reuse one verified download. Existing cached content
is still rehashed. Agent observations cannot change registry trust decisions.

Installs build in a temporary directory before activating node_modules. Failed
resolution, downloads and scripts leave the manifest and installation unchanged.
If activation fails, Rivet attempts to restore the manifest and lock as well as
the previous tree. Writes are atomic per file, not a crash-atomic transaction
across all files; after a machine crash during activation, run install to recover.
Keep `.rivet/` and `node_modules/` out of version control.

The live compatibility gate exercises machine output, script isolation, argument
quoting, command-name collisions, failed edits, frozen cache reuse, and two
simultaneous projects downloading a shared artifact once. Its registry uses static
audits. The separate gVisor gate remains the evidence for trusted dynamic auditing.
