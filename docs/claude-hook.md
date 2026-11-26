# Wiring enforcer into Claude Code (PreToolUse hook)

Claude Code has no built-in tool-substitution redirect; this hook gives it the same
deterministic floor pi gets through the `@enforcer/pi-enforcer` extension (`docs/pi-extension.md`). On every `Bash`/`Write`/`Edit` call, Claude
runs `enforcer --harness claude`, which denies a floor violation with a redirect message the
model sees, and defers everything else to Claude's normal permission flow.

Schema per the official hooks reference: https://code.claude.com/docs/en/hooks.md

## Prerequisite

`make install` puts the binary at `~/.local/bin/enforcer`. The hook uses an absolute path so
it does not depend on the hook process's PATH.

## settings.json block

Add to `claude/settings.json` (apply via `/update-config`, not a hand-edit):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "/home/user/.local/bin/enforcer --harness claude",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

## Contract

- **Input (stdin):** Claude sends `{ "tool_name": "Bash", "tool_input": { "command": "..." }, ... }`.
  For `Write`/`Edit` the destination is `tool_input.file_path`; the enforcer maps it to the
  `path` the secret-write rule reads. The file body (`file_text` / `edits`) is inert and not
  scanned.
- **Deny (stdout, exit 0):**
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"<redirect>"}}`.
  `permissionDecisionReason` is fed to the model, so it re-emits with the right tool.
- **Allow (stdout, exit 0):** `{}` -- no decision, so Claude proceeds through its normal
  permission flow (this is NOT an auto-approve).
- **Exit codes:** the enforcer always exits 0 with a JSON verdict; exit 2 is reserved for a
  usage error (bad `--harness`, non-JSON stdin) and would block unconditionally, so the hook
  command must be correct. A parse-failure exit is non-blocking by Claude's rules.

## Scope note

The `matcher` covers the tools every built-in rule targets (`Bash` for
sed/awk/rm/force-push/curl-pipe, `Write`/`Edit` for secret-file writes). If you add a
`~/.config/enforcer/rules.jsonc` regex aimed at another tool, broaden the matcher
accordingly -- the enforcer scans any tool's string fields, but Claude only invokes the hook
for tools the matcher names.
