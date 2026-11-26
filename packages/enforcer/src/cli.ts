/**
 * The enforcer CLI: read a tool call as JSON on stdin, apply the deterministic deny
 * floor, and emit a verdict. Pure classifier -- the harness adapter (or `--harness`
 * mode) maps the verdict into each harness's own block channel.
 *
 * generic mode (default):
 *   in:  { "tool": "<name>", "input": { ... }, "context": { "editTargetTracked"?: bool } }
 *   out: { "decision": "allow" | "deny", "reason"?: "<redirect message>" }
 *
 * claude mode (--harness claude): read claude's PreToolUse hook payload
 *   ({ tool_name, tool_input }) and emit its hookSpecificOutput, so the hook is a
 *   one-liner. A deny returns permissionDecision "deny" with the redirect message as
 *   permissionDecisionReason; an allow returns no decision (the harness proceeds).
 */

import { loadRules, matchesHardDeny } from "./index.js";
import { ENFORCER_VERSION } from "./version.js";

const HELP = `enforcer -- deterministic tool-call deny floor with redirects

usage: enforcer [--harness generic|claude]
       enforcer --version

Reads a tool call as JSON on stdin and writes a verdict as JSON on stdout.

  generic (default)
    in:  {"tool":"bash","input":{"command":"..."},"context":{"editTargetTracked":false}}
    out: {"decision":"allow"|"deny","reason":"..."}

  --harness claude
    in:  claude PreToolUse payload {"tool_name":"Bash","tool_input":{...}}
    out: {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}

  --version, -V
    print "enforcer <version>" and exit 0 without reading stdin.

Rules: the built-in floor plus any regex redirects in $ENFORCER_RULES
(default ~/.config/enforcer/rules.jsonc). Exit 0 on a verdict, 2 on a usage error.`;

interface GenericInput {
	tool?: unknown;
	input?: unknown;
	context?: { editTargetTracked?: boolean };
}

interface ClaudeInput {
	tool_name?: unknown;
	tool_input?: unknown;
}

/** Map a claude tool name + input onto the (tool, input) shape the floor rules key on. */
function fromClaude(payload: ClaudeInput): { tool: string; input: Record<string, unknown> } {
	const tool = String(payload.tool_name ?? "").toLowerCase();
	const raw = (payload.tool_input && typeof payload.tool_input === "object" ? payload.tool_input : {}) as Record<
		string,
		unknown
	>;
	const input: Record<string, unknown> = { ...raw };
	// claude names the write/edit destination file_path; the floor reads input.path.
	if (typeof raw.file_path === "string" && input.path === undefined) input.path = raw.file_path;
	return { tool, input };
}

async function readStdin(): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
	return Buffer.concat(chunks).toString("utf8");
}

function fail(message: string): never {
	process.stderr.write(`${message}\n`);
	process.exit(2);
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	// --version answers before stdin is read, so it works from a pipe or a bare shell.
	if (args.includes("--version") || args.includes("-V")) {
		process.stdout.write(`enforcer ${ENFORCER_VERSION}\n`);
		return;
	}
	if (args.includes("--help") || args.includes("-h")) {
		process.stdout.write(`${HELP}\n`);
		return;
	}
	let harness: "generic" | "claude" = "generic";
	const hIdx = args.indexOf("--harness");
	if (hIdx !== -1) {
		const val = args[hIdx + 1];
		if (val !== "generic" && val !== "claude")
			fail(`enforcer: --harness expects generic|claude, got ${val ?? "(nothing)"}`);
		harness = val;
	}

	const stdin = await readStdin();
	if (stdin.trim().length === 0) fail("enforcer: no JSON on stdin");
	let payload: unknown;
	try {
		payload = JSON.parse(stdin);
	} catch (err) {
		fail(`enforcer: stdin is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
	}

	const { rules, warnings } = loadRules();
	for (const w of warnings) process.stderr.write(`${w}\n`);

	let tool: string;
	let input: Record<string, unknown>;
	let context: { editTargetTracked?: boolean } = {};
	if (harness === "claude") {
		({ tool, input } = fromClaude(payload as ClaudeInput));
	} else {
		const p = payload as GenericInput;
		if (typeof p.tool !== "string") fail("enforcer: generic input needs a string `tool`");
		tool = p.tool;
		input = (p.input && typeof p.input === "object" ? p.input : {}) as Record<string, unknown>;
		if (p.context && typeof p.context === "object") context = p.context;
	}

	const match = matchesHardDeny(tool, input, rules, context);

	if (harness === "claude") {
		if (match) {
			process.stdout.write(
				`${JSON.stringify({
					hookSpecificOutput: {
						hookEventName: "PreToolUse",
						permissionDecision: "deny",
						permissionDecisionReason: match.reason,
					},
				})}\n`,
			);
		} else {
			// No decision: the harness continues to its normal permission flow.
			process.stdout.write(`${JSON.stringify({})}\n`);
		}
		return;
	}

	process.stdout.write(
		`${JSON.stringify(match ? { decision: "deny", reason: match.reason } : { decision: "allow" })}\n`,
	);
}

main().catch((err) => {
	fail(`enforcer: ${err instanceof Error ? err.message : String(err)}`);
});
