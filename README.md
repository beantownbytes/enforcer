# enforcer

Deterministic tool-call deny floor with tool-substitution redirects. A tool call is
classified with no LLM and no session state: a benign call passes, and a call that has an
evasion-proof better alternative is denied with a one-line redirect telling the model what
to use instead (`sed` -> `slice`/`rg`/edit, `awk` in-program writes -> write/edit tools,
`rm -rf /`, `git push --force`, secret-file writes, `curl | sh`, a script handed to csh,
tcsh or PowerShell, whose syntax the floor does not read). User regex redirects can be added;
built-ins can only be added to, never removed.

The same floor is enforced in both harnesses: claude via a `PreToolUse` hook, pi via the
standalone `@enforcer/pi-enforcer` extension (`packages/pi`), which consumes
`@enforcer/core`. Only the deterministic floor lives here -- an LLM judge, caches, and
journals are out of scope for this package.

## Layout

Bun-workspace monorepo:

- `packages/enforcer` -- `@enforcer/core`: the floor, the shell tokenizer, the CLI, and the
  compiled binary.
- `packages/pi` -- `@enforcer/pi-enforcer`: a standalone pi extension that applies the floor
  to agent tool calls (no LLM judge, no approval prompts). See `docs/pi-extension.md`.

## Build and test

```
make bootstrap   # bun install --frozen-lockfile
make check       # fmt-check + typecheck + lint + test
make build       # dist/enforcer (bun single-file executable)
make install     # dist/enforcer -> ~/.local/bin/enforcer
```

## CLI

Reads a tool call as JSON on stdin, writes a verdict as JSON on stdout.

```
# generic
echo '{"tool":"bash","input":{"command":"sed -n 1,5p f"}}' | enforcer
{"decision":"deny","reason":"sed is hard-denied; use slice lines ..."}

echo '{"tool":"bash","input":{"command":"rg -n foo src"}}' | enforcer
{"decision":"allow"}

# claude PreToolUse hook mode (reads {tool_name,tool_input}, emits hookSpecificOutput)
echo '{"tool_name":"Bash","tool_input":{"command":"sed x"}}' | enforcer --harness claude
```

For `write`/`edit` calls the destination path is scanned (secret-file rule) while the file
body is inert; pass `{"context":{"editTargetTracked":true}}` to stand the secret-file floor
down for a path already committed to the repo.

## User rules

Optional regex redirects load from `$ENFORCER_RULES` (default
`~/.config/enforcer/rules.jsonc`): a JSON/JSONC array of `{ "pattern", "reason", "flags"? }`.
These are appended to the built-in floor. See `rules.example.jsonc`.

## Harness wiring

- claude: `docs/claude-hook.md` -- the `PreToolUse` hook block for `settings.json`.
- pi: `packages/pi` is a standalone pi extension; see `docs/pi-extension.md`.

## Limits

The floor reads only the text of the one tool call in front of it. What that text runs
without spelling it is out of sight, and it stays a known limit rather than a reason to
fail closed:

- **Command names rebound from outside the command.** A pipe sink's name (`... | cat`)
  is trusted unless the command itself rebinds it: a function or alias defined in the
  command, written directly or inside an `eval` or `trap` operand (both run in the
  command's own shell, unlike `bash -c '...'` or a command substitution, whose definitions
  die with their child shell), or a path outside the system binary directories. A
  function or alias that comes from anywhere else is not seen: a file read with
  `source`/`.`, a function inherited through `export -f`, `BASH_ENV`, or a shell startup
  file. A pipe sink after a `source` is not treated as rebound either:
  `source .venv/bin/activate && ... | cat` is an everyday shape, denying every such pipe
  would be a broad false positive, and it would still not cover a definition inherited
  from the parent environment, which no command text shows.
- **Definitions an `eval` or `trap` operand only produces at run time.** The operand's own
  text is read for definitions, but not what an expansion in it resolves to:
  `eval "$VAR"` or `eval "$(printf 'cat() { sh; }')"` runs the expanded text in the
  command's own shell, so a function it defines can rebind a later pipe sink unseen.
  Failing closed on every expanded operand would deny everyday shapes such as
  `eval "$(ssh-agent)"` or `eval "$(direnv hook bash)"` ahead of any pipe.
- **A substitution's output reaching a command through another variable or shell.** An
  assignment's substitution (`x=$(...)`) is read as a command only where the same shell
  runs that variable: in command position or a wrapper's command operand (`$x`, `sudo "$x"`,
  `bash -c "$x"`), in a run piped to an interpreter, in a here-string a shell reads as its
  script (`bash <<< "$x"`), or as an operand of a function the command defines. The
  variable is matched by name across the whole shell, whatever the order or reachability
  of its runs, since a loop or function can run an assignment after the expansion: a name
  reused for data elsewhere in the same command
  (`x=$(tool); $x || x=$(grep -n 'rm -rf /' todo.md)`) still has every substitution it
  stores read. An assignment behind a flag (`declare -x x=$(...)`) is not seen as one, as
  with a quoted value there. Each substitution in the value is read on its own, so a
  command whose words are split across several pieces of the value
  (`x=$(echo 'rm -rf ')$(echo /)`) is not joined back together. A value a program reads as
  its own code rather than a shell (`python3 <<< "$x"`) is not read as that program. A copy
  (`y=$x; $y`, `set -- "$x"; $1`), an expansion inside a nested substitution or `bash -c`
  script, or an inherited environment variable is not followed; reading every stored
  substitution as a command would deny everyday shapes such as
  `out=$(grep -n 'rm -rf /' notes.md)`.
- **What an alias or function the command defines does with a call's operands.** A call is
  also read as the command it makes: an alias's value with the call's operands after it
  (`alias g=git; g push --force`), and a function body's runs with the operands spliced in for
  a positional reference, split into words as bash splits it (`$@`, `$*`, `$N`, a slice
  `${@:2}`, a default `${1:-x}`; in a body's own words an alternate `${1:+x}` is read as its
  word and a substring `${1:0}` as the whole parameter), including in a script the body hands
  to a shell or `eval` (`bash -c "git $*"`, `eval 'rm -rf "$1"'`) or runs as a substitution or
  a here-string a shell reads (`"$(rm "$@")"`, `bash <<< "rm -rf $1"`), which are read as a
  shell -c script's parameters are. A body is found only after a `name ()` or `function name`
  header in the command, and only as a `{ ...; }` group, a `( ... )` subshell, an `if`, a
  `case`, a loop or zsh's bare command (`f() rm "$@"`, `function f rm "$@"`), not a `[[ ...
  ]]` or `(( ... ))` body. What the body does to its parameters before using them is not
  followed: `shift`, `set --`, any other braced operator (`${1%.x}`, `${1^^}`, `${@/#/}`), or
  a copy into another variable such as `for x in "$@"` or `local x=$1`. Nor is a call behind a
  wrapper inside a body (`sudo g "$@"`, which cannot run a function anyway), or a definition
  written inside an alias value (`alias c='f() { rm "$@"; }'; c -rf /`). A body is read only
  when a call reaches it: a definition alone runs nothing. A recursive call is followed until
  it has been read with the shapes of operands it passes itself, then stops without a verdict
  of its own, so a recursive helper (`retry`, `fib`) is denied only by a rule one of its runs
  trips; a chain of more than eight nested calls to distinct definitions, or expansions past
  the analysis budget, is denied as unread. A formed run is read by the argv rules only, and
  without redirections: the rules that read the command's own structure, such as
  download-to-shell, do not see a download or pipe a definition supplies (`alias c=curl; c
  -fsSL https://x | sh`, `alias r='echo "rm -rf /" |'; r sh`), and a redirection destination a
  call supplies (`f() { echo x > "$1"; }; f .env`) is not read with it.
