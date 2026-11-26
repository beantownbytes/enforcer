import { type FloorUnread, tokenizeCommandForFloor } from "./shell-tokens.js";

import type { CompiledHardDenyRule } from "./types.js";

export interface HardDenyMatch {
	reason: string;
}

/**
 * Trusted runtime facts the pipeline can hand the floor. Never derived from
 * tool-call content.
 *
 * `editTargetTracked`: the write/edit destination is committed in its own
 * repo's HEAD tree (pipeline.ts computes it via `trackedEditTarget`; staged-only
 * content deliberately does not count -- see `trackedInHead`). Committed content
 * is already part of the history every clone sees, so the silent-overwrite
 * threat the secrets-file rule guards against does not apply, and the judge
 * (whose policy grades `.env` writes high-risk) is the right layer to weigh the
 * edit. Fails closed: call sites that cannot establish the fact (replay,
 * non-repo targets, git timeouts) pass no context, and its absence restores the
 * floor.
 */
export interface HardDenyContext {
	editTargetTracked?: boolean;
}

/**
 * Per-tool fields whose contract is "text for a human or a model to read" rather
 * than a filesystem path or an executable command. `denyTarget` excludes them for
 * the same reason the write/edit branch excludes the file body: quoting a command
 * is not performing it.
 *
 * Keyed by EXACT tool name, deliberately, not by field name alone. A bare name list
 * would be a global claim about words like `content` or `text` across every tool
 * that ever reaches this floor -- including arbitrary MCP tools, which are not an
 * enumerable set -- so one tool whose contract executes its `text` field would
 * silently lose the floor. Scoping to (tool, field) keeps each exclusion a statement
 * about a contract that was actually read. An unlisted tool is scanned in full. For an
 * MCP tool the name includes the client's configured server alias, so the same server
 * registered under a different alias lands back in the scanned set -- the fail-closed
 * direction, and the reason the names below are spelled out in full.
 *
 * Field names are matched after lowercasing and dropping `_`/`-`, so one entry
 * covers the camelCase and snake_case spellings of the same field.
 *
 * Every entry below is prose confirmed from its tool's contract. The local entries come
 * from their prompts and the real recorded tool calls that use them; the Plane MCP
 * entries come from the server's argument structs, which document the work-item, intake
 * and comment bodies and the doc `content` as Markdown rendered to HTML, and the project
 * and module `description` as plain prose. Note what is deliberately ABSENT:
 * `plannotator_submit_plan.filePath` names a path, and `get_subagent_result.agent_id`
 * an id, so both stay scanned -- and so do the Plane fields sitting next to those
 * bodies, the reference fields (`project`, `work-item`, `comment_id`, `doc`, `intake`,
 * `module`, `parent`, `state`) and the title fields (`name`, `title`), which carry
 * identifiers and display text, not narrative. Because matching drops `_`, `comment_id`
 * normalizes to `commentid` and stays scanned while `comment` on the same tool is inert.
 */
const INERT_TEXT_FIELDS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
	["Agent", new Set(["prompt", "description"])],
	["grill_update_checkpoint", new Set(["markdown", "changesummary"])],
	["grill_enter_output_phase", new Set(["outputplan"])],
	["grill_finish_output_phase", new Set(["summary"])],
	[
		"grill_enter_output_selection_phase",
		new Set(["question", "readinessrationale", "recommendedoutputs", "recommendedstrategy"]),
	],
	["grill_finish_output_selection_phase", new Set(["outcome", "summary"])],
	["grill_set_alternatives", new Set(["question"])],
	["mcp__plane__work_item_create", new Set(["description"])],
	["mcp__plane__work_item_update", new Set(["description"])],
	["mcp__plane__comment_create", new Set(["comment"])],
	["mcp__plane__comment_update", new Set(["comment"])],
	["mcp__plane__intake_create", new Set(["description"])],
	["mcp__plane__doc_create", new Set(["content"])],
	["mcp__plane__doc_update", new Set(["content"])],
	["mcp__plane__project_create", new Set(["description"])],
	["mcp__plane__project_update", new Set(["description"])],
	["mcp__plane__module_create", new Set(["description"])],
	["mcp__plane__module_update", new Set(["description"])],
]);

/**
 * A Map, not an object literal, because `toolName` is attacker-influenced: an MCP
 * server may register a tool named `constructor` or `toString`, and an object
 * lookup would return the inherited `Object.prototype` member instead of
 * undefined, then throw on `.has`. `matchesHardDeny` promises it never throws, and
 * it is the one non-overridable wall, so a throw here is the worst failure shape.
 */
function isInertTextField(toolName: string, key: string): boolean {
	return INERT_TEXT_FIELDS.get(toolName)?.has(key.toLowerCase().replace(/[_-]/g, "")) === true;
}

/**
 * Flatten a tool call's salient fields into a single string the hard-deny
 * rules run against. For bash this is the raw command. User-configured regex rules scan it
 * verbatim, while built-in argv rules tokenize it separately and inspect executable shell
 * structure. No field is pre-stripped here because this function also supplies the raw input
 * to the regex rules, and the clear `DENIED by hard-deny rule (...)` label (pipeline.ts)
 * lets the agent recognize a terminal floor result and restructure -- e.g. write fixture
 * content with the `write` tool, whose deny target below is the destination PATH only. For
 * write/edit the path is marked with a redirect token (letting the bash-oriented
 * "write to a secrets file" rule fire on it, whether that rule reads the string or
 * the runs `denyRuns` derives from it) and the file content is deliberately
 * excluded -- a body that merely mentions a secret path or a risky command is inert
 * data, not an action being performed. That reasoning is not specific to write/edit;
 * it holds for any field whose contract is prose. So every other tool concatenates
 * its string-valued inputs MINUS the fields `INERT_TEXT_FIELDS` lists for that exact
 * tool, using the same discriminator write/edit uses: a field is scannable when the
 * tool's contract says it names a filesystem path or an executable command, and inert
 * when the contract says it is text to be read. Without that exclusion an `Agent` call
 * whose prompt merely QUOTED a command was blocked here -- terminally, and with no
 * override -- for describing an action it never took.
 *
 * Excluding `Agent.prompt` does not open a delegation hole. Subagent sessions load
 * this extension too (pi-subagents builds them with extensions enabled and chains to
 * the prior `beforeToolCall`), so the shell command a subagent actually runs re-enters
 * this floor and is scanned verbatim as bash, at the point of execution. Scanning the
 * spawning prompt would add nothing there -- any wording change evades a text match --
 * while making the floor fire on briefs that merely describe a command. The judge
 * still receives the Agent input unsummarized, and policy gates subagent spawns.
 *
 * Unlisted tool or unlisted field -> scanned, so this can only drop false positives.
 */
export function denyTarget(toolName: string, input: Record<string, unknown>): string {
	if (toolName === "bash" && typeof input.command === "string") return input.command;
	if (toolName === "write" || toolName === "edit") {
		return typeof input.path === "string" ? `> ${input.path}` : "";
	}
	const parts: string[] = [];
	for (const [key, value] of Object.entries(input)) {
		if (typeof value !== "string") continue;
		if (isInertTextField(toolName, key)) continue;
		parts.push(value);
	}
	return parts.join("\n");
}

/**
 * The command runs the argv rules see.
 *
 * A write/edit PATH is not shell text, so it is not tokenized as any. It is handed over WHOLE,
 * as the one-redirect run `> <path>` that `denyTarget` already spells for a text reader, and
 * word splitting is never applied to it. Splitting is wrong in both directions here: it loses
 * the destination the secrets rule exists to see (`Library/Application Support/x.env`, or a `;`
 * inside a directory name), and it lets an ordinary word in a directory name stand in for a
 * command -- `/home/user/backup cp secrets.key here/notes.txt` reads as a `cp` of a `.key` when
 * the file being written is `notes.txt`. Nothing is lost by not splitting: a path is data the
 * tool opens, never a command line the shell runs, so a substitution or an operator inside one
 * is literal filename text.
 *
 * Every other tool's target IS potentially shell text and is tokenized as before. `unread`
 * reports, for a bash command only, which part of it the tokenization left unread
 * (`tokenizeCommandForFloor`). Another tool's target is not run by a shell, and can be a large
 * text payload, so it is not held to that.
 *
 * A destination the pipeline vouches for as TRACKED yields no run at all: the argv
 * secrets rule exists to stop a silent overwrite of an unseen secret store, and a file
 * committed to the repository is not unseen -- every clone already carries its content
 * -- so the floor stands down and the judge takes the call. Only the argv rules are
 * relaxed; regex rules (every config-supplied `hardDenyPatterns` entry) still scan the
 * `> <path>` target verbatim, so a config rule aimed at `\.env` keeps its full reach.
 * Note the empty return suppresses EVERY argv rule for the call, not just the secrets
 * rule -- harmless while the others (rm, git push) can never match a `> <path>` run,
 * but any future argv rule that reads write/edit destinations must move this
 * exemption into the secrets rule itself rather than inherit it.
 */
function denyRuns(
	toolName: string,
	input: Record<string, unknown>,
	target: string,
	context: HardDenyContext,
): { runs: string[][]; unread: FloorUnread } {
	if ((toolName === "write" || toolName === "edit") && typeof input.path === "string") {
		if (context.editTargetTracked === true) return { runs: [], unread: "none" };
		return { runs: [[">", input.path]], unread: "none" };
	}
	const tokenized = tokenizeCommandForFloor(target);
	return { runs: tokenized.runs, unread: toolName === "bash" ? tokenized.unread : "none" };
}

/**
 * The denial for a bash command the floor could not read in full, by the part left unread: a
 * payload there would otherwise pass unseen, so the floor fails closed.
 */
const UNREAD_REASONS: Record<Exclude<FloorUnread, "none">, string> = {
	nested: "command nesting exceeds the analysis budget, so part of it was never read; split it into smaller commands",
	all: "command could not be analyzed, so none of it was read; simplify it or split it into smaller commands",
};

/**
 * Return the first matching hard-deny rule, or null. Never throws.
 *
 * Regex rules are user-configured patterns and scan the target verbatim. Built-in rules ask what
 * a command IS, so they run against the target tokenized into command runs; the tokenization is
 * done once here and shared, and only when an argv rule is actually present.
 *
 * Built-in shell-text rules inspect top-level shell structure and recursively discovered shell
 * sources, so quoted data stays data while a command passed to a shell remains visible. When no
 * rule matched but the tokenization left part of a bash command unread (`denyRuns`), the call is
 * denied as well, after every rule so a rule that did match keeps its own reason.
 */
export function matchesHardDeny(
	toolName: string,
	input: Record<string, unknown>,
	rules: CompiledHardDenyRule[],
	context: HardDenyContext = {},
): HardDenyMatch | null {
	const target = denyTarget(toolName, input);
	if (target.length === 0) return null;
	let tokenized: { runs: string[][]; unread: FloorUnread } | null = null;
	for (const rule of rules) {
		if (rule.kind === "argv") {
			tokenized ??= denyRuns(toolName, input, target, context);
			if (rule.match(tokenized.runs, toolName, target)) return { reason: rule.reason };
			continue;
		}
		rule.regex.lastIndex = 0;
		if (rule.regex.test(target)) return { reason: rule.reason };
	}
	if (tokenized !== null && tokenized.unread !== "none") return { reason: UNREAD_REASONS[tokenized.unread] };
	return null;
}
