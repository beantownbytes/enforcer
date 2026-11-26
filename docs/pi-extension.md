# Wiring enforcer into Pi (standalone pi extension)

`packages/pi` (`@enforcer/pi-enforcer`) is a standalone pi extension that applies enforcer's
deterministic hard-deny floor to every agent tool call. It registers a single `tool_call`
handler: a call that matches the floor (the built-in redirects plus any additive user rules)
is blocked with the rule's reason text -- the same one-line redirect a claude hook emits --
and every other call passes through untouched. No LLM judge, no approval prompts, no
terminating-agent behavior, no UI.

## Behavior

- Rules load through `loadRules()`: the built-in floor plus additive user rules from
  `$ENFORCER_RULES` (default `~/.config/enforcer/rules.jsonc`; see the README's "User
  rules"). Additive only; built-ins can be added to, never removed. Load warnings are
  reported (a UI notification in an interactive session, `console.warn` headless) -- they
  never prompt.
- The check runs `matchesHardDeny` with the core's default fail-closed context. The optional
  tracked-file exemption is not available through this adapter: a write/edit to a tracked
  destination is denied exactly as the CLI denies it without `editTargetTracked`. An
  input-supplied tracked flag would be untrusted, so the adapter does not read one.
- Tool names and inputs are preserved unchanged; only a match produces a block, and the
  reason is passed through exactly, including redirect reasons.
- Prose fields of listed tools (`Agent` prompt and description, the `grill_*` tools, and
  the Plane MCP `description`/`comment`/`content` bodies) are inert: they are dropped from
  the scan target before any rule runs, so every rule -- built-in and user-supplied
  (`$ENFORCER_RULES`) alike -- passes over prose that describes a command or names a
  secrets file, while every path, id, and title field on the same call is still scanned.
  An MCP tool is matched by its full harness name, configured server alias included, so
  the same server registered under another alias is scanned in full.

## Install from a checkout

The package installs from a local checkout, not from npm:

```
git clone https://github.com/beantownbytes/enforcer ~/code/enforcer
cd ~/code/enforcer
make bootstrap                 # bun install --frozen-lockfile
pi install ~/code/enforcer/packages/pi
```

`pi install` on a local path registers the path in pi's settings without copying it, so the
checkout must stay where it is and stay bootstrapped (the extension imports `@enforcer/core`
from the workspace `node_modules`). Updates come from a `git pull` in the checkout, not
`pi update`. The checkout root is a bun workspace, not a pi package: installing the repo
root (`pi install git:.../enforcer` or `pi install ~/code/enforcer`) finds no extension, and
`@enforcer/pi-enforcer` is not published to npm, so `pi install npm:@enforcer/pi-enforcer`
does not work.

## Selecting it from a pi-subagents agent

A pi-subagents agent definition selects this extension through its `extensions:` entry,
which pi-subagents matches against each extension's package short name (the unscoped
`@enforcer/pi-enforcer` becomes `pi-enforcer`) and the name of the directory that
contains its `index.ts`. Installed from `packages/pi`, the extension therefore answers
to two names: `pi-enforcer` (unique to it) and `pi` (shared by every extension
installed from a `packages/pi` directory).
`extensions: [pi-enforcer]` loads the enforcer alone; `extensions: [pi]` matches that
shared path name and so loads those extensions alongside the enforcer.
`extensions: false` loads no extension at all and so drops the secrets-file protection.
On a machine where the enforcer is not installed, the name does not silently no-op:
pi-subagents reports an extension-error warning.

## Verifying without installing

Run the adapter for one session before registering it: `pi -e` loads the extension
alongside the configured extensions, so use
`pi --no-extensions -e ~/code/enforcer/packages/pi` (optionally with a disposable
`PI_CODING_AGENT_DIR`), which runs it with no other extensions loaded. Confirm only
enforcer is loaded before swapping it in for another `tool_call` handler: removing an
extension's manifest line does not uninstall it, so a stale installed package keeps
loading from pi's settings until it is explicitly removed.

## Limits

- **Deterministic rules only.** The floor denies patterns it knows; evasion that does not
  match a rule passes through. There is no LLM judge layer on top.
- **Not a sandbox.** A call the floor allows runs with the agent's full system access; the
  floor is a deny list, not a boundary.
- **Not comprehensive deletion protection.** `rm -rf /`-class calls are denied, but the
  floor is not an exhaustive guard against destructive commands.
- **No tracked-file exemption.** The adapter uses the fail-closed default context, so a
  write/edit to a committed path is denied even when the same call would pass the CLI with
  `editTargetTracked`.
- **Command text only.** The floor reads the call's own text, so a function or alias
  defined outside it (`source`, `export -f`, `BASH_ENV`) can rebind a trusted pipe sink
  unseen; see the Limits section of the top-level README.
- **Not a permission system.** It blocks floor violations only; it does not approve,
  prompt, or restrict anything else.
