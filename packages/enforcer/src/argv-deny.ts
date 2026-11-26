import { awkProgramHasNativeEscape, extractAwkPrograms } from "./awk-deny.js";
import { GIT_GLOBAL_BOOL_OPTS, GIT_GLOBAL_VALUE_OPTS } from "./git-opts.js";
import type { ExecutableShellAnalysis, ShellCommandAnalysis } from "./shell-tokens.js";
import {
	APPLET_WRAPPERS,
	analyzeExecutableShellSources,
	braceReadings,
	braceSequenceStart,
	executableCommandIndexes,
	expandBraces,
	findExecCommands,
	headBase,
	OPAQUE_SCRIPT_SHELLS,
	opaqueShellReadsScript,
	PROCESS_SUBSTITUTION_WORD,
	REDIRECTION_FD,
	redirectionFreeWords,
	SHELL_HEADS,
	staticWordMatches,
	stripExpansions,
	withoutRedirections,
	withoutShellParameters,
} from "./shell-tokens.js";
import type { CompiledArgvHardDenyRule } from "./types.js";

const GIT_VALUE_OPTS_LOWER = new Set([...GIT_GLOBAL_VALUE_OPTS].map((o) => o.toLowerCase()));
const GIT_BOOL_OPTS_LOWER = new Set([...GIT_GLOBAL_BOOL_OPTS].map((o) => o.toLowerCase()));
/**
 * Globals that ANSWER rather than continue: git prints the version, a path, or the manual and
 * exits, so the words after them are never run as a subcommand.
 *
 * `--exec-path` is here in its BARE form only -- it prints the path and exits, taking no value
 * with it -- while `--exec-path=<dir>` sets one and carries on, and is matched earlier as an
 * inline value.
 */
const GIT_TERMINATING_GLOBALS = new Set([
	"-v",
	"--version",
	"-h",
	"--help",
	"--html-path",
	"--man-path",
	"--info-path",
	"--exec-path",
]);

/** `${NAME}` -- the braced spelling of a plain parameter reference. */
const BRACED_PARAM = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/**
 * The two readings of each word that the shell may actually execute.
 *
 * A word is read BOTH with its expansions stripped and as written, and a rule matches when
 * either reading is dangerous. Neither alone is enough, and the choice is PER WORD rather than
 * per command, because one command can need both at once (`r$()m -rf ${HOME}`):
 *
 * - Stripping is what catches a word spliced apart by an expansion. The shell removes an empty
 *   one before deciding what to run, so `r$()m -rf /`, `rm -r$()f /`, `git pu$()sh --force` and
 *   `rm -rf ~$()` are all the plain commands they look like. A non-empty body is no different,
 *   since nothing static can know it does not expand to nothing -- so the span goes regardless,
 *   which is the fail-closed direction and costs nothing, because no ordinary command is
 *   spelled this way.
 * - But stripping is destructive when the expansion IS the whole word: `${HOME}` would become
 *   empty rather than the home directory it names. So the as-written reading keeps expansions
 *   and only rewrites `${NAME}` to `$NAME`, the same reference the target test recognizes --
 *   `rm -rf ${HOME}` denies exactly like `rm -rf $HOME`.
 *
 * A run is read the same way twice over when a brace expansion in it expands: once as written,
 * and once with each such word replaced by the words bash expands it into
 * (`braceExpandedWords`). The first keeps what an unexpanded word already matches -- a command
 * name any alternative spells (`s{d..f}d`) -- and the second adds the operands only the
 * expansion shows, as `rm -rf {/,x}` is `rm -rf / x`.
 */
interface Readings {
	/** The run read. */
	argv: string[];
	/** Expansions removed: what the word contributes on its own. */
	spliced: string[];
	/** Expansions kept, `${NAME}` normalized to `$NAME`. */
	asWritten: string[];
	/** Whether this is the brace-expanded reading of the run rather than the one as written. */
	braceExpanded: boolean;
	/**
	 * The words whose brace expansion was too large to list (`braceExpandedWords`), kept as
	 * written, by position, each with what its shape says of the words it expands to
	 * (`UnlistedWord`). Past that, one stands for any words at all, so a rule reads one at or
	 * after its command's head as the operand it looks for when its shape allows it.
	 */
	unlisted: ReadonlyMap<number, UnlistedWord>;
}

/**
 * What a word too large to list says of the words it expands to, read from its shape alone, so
 * that whether it fails closed does not depend on how much of the budget was left for it.
 */
interface UnlistedWord {
	/** Every way a word it expands to may start (`unlistedStarts`). */
	starts: UnlistedStart[];
	/** Whether a word it expands to may name a secrets file (`mayNameSecret`). */
	mayNameSecret: boolean;
}

/**
 * One way the words an unlisted word expands to start: with `lead`, literal text, followed by
 * anything, or -- when the word begins with a sequence expression -- by one of its terms
 * (`braceSequenceStart`).
 */
interface UnlistedStart {
	lead: string;
	next: "any" | "digit" | "signed-digit" | "letter";
}

/**
 * Both built-in rules read the same runs, and `matchesHardDeny` hands them the same array, so
 * the readings are derived once and shared rather than recomputed per rule on a path that runs
 * ahead of everything else on every tool call. Keyed weakly: the entry dies with the runs.
 */
const readingsByRuns = new WeakMap<string[][], { toolName: string; readings: Readings[] }>();

function readingsFor(runs: string[][], toolName: string): Readings[] {
	let derived = readingsByRuns.get(runs);
	if (derived === undefined || derived.toolName !== toolName) {
		const budget = { left: MAX_BRACE_EXPANSION };
		braceHeadMatches.clear();
		derived = { toolName, readings: runs.flatMap((argv) => readings(argv, toolName, budget)) };
		readingsByRuns.set(runs, derived);
	}
	return derived.readings;
}

/** A run's readings: as written, and brace-expanded when that changes a word (see `Readings`). */
function readings(argv: string[], toolName: string, budget: { left: number }): Readings[] {
	const words = withoutShellParameters(withoutRedirections(argv));
	const asWritten = wordReadings(argv, words, false, new Map<number, UnlistedWord>());
	const expanded = braceExpandedWords(words, toolName, budget);
	return expanded === null ? [asWritten] : [asWritten, wordReadings(argv, expanded.words, true, expanded.unlisted)];
}

function wordReadings(
	argv: string[],
	words: string[],
	braceExpanded: boolean,
	unlisted: ReadonlyMap<number, UnlistedWord>,
): Readings {
	return {
		argv,
		spliced: words.map(stripExpansions),
		asWritten: words.map((t) => t.replace(BRACED_PARAM, "$$$1")),
		braceExpanded,
		unlisted,
	};
}

/**
 * The listing work, in characters plus one per word of every list built (`expandBraces`), that
 * one tool call's brace expansions may spend together. Ordinary expansions (`src/{a,b}`,
 * `f{1..500}`) cost a few thousand at most; the bound exists for products of groups, which grow
 * exponentially.
 */
const MAX_BRACE_EXPANSION = 1_048_576;

/**
 * A run's words with each unquoted brace expansion replaced by the words bash expands it into
 * (`expandBraces`), so an operand `{/,x}` is read as the two operands `/` and `x` it gives, or
 * null when no word expands. The expansions of a whole tool call share `budget`.
 *
 * Every listing is charged to the budget, a failed one included, so words just past it cannot
 * each spend a whole budget, and each word may spend its own allowance (`wordAllowance`) past
 * what is left. A word too large to list within that is kept as written. For a bash command it
 * is also marked `unlisted`, since bash runs whatever it expands to and none of that was read:
 * a product padded out past the budget (`{,}{,}...{/,x}`) must not hide the word it yields.
 * Another tool's text is not run by a shell, and a compact JSON array of objects is exactly such
 * a product, so there the word is only kept as written. That text is still read as shell, as
 * everywhere on this floor, so its brace groups are expanded like a bash command's.
 */
function braceExpandedWords(
	words: string[],
	toolName: string,
	budget: { left: number },
): { words: string[]; unlisted: ReadonlyMap<number, UnlistedWord> } | null {
	if (!words.some((word) => word.includes("{"))) return null;
	const out: string[] = [];
	const unlisted = new Map<number, UnlistedWord>();
	let changed = false;
	for (const word of words) {
		const expanded = expandBraces(word, Math.max(budget.left, wordAllowance(word)));
		budget.left = Math.max(0, budget.left - expanded.cost);
		if (expanded.kind === "too-large") {
			if (toolName === "bash") {
				unlisted.set(out.length, { starts: unlistedStarts(word), mayNameSecret: mayNameSecret(word) });
				changed = true;
			}
			out.push(word);
			continue;
		}
		changed ||= expanded.words.length !== 1 || expanded.words[0] !== word;
		for (const listed of expanded.words) out.push(listed);
	}
	return changed ? { words: out, unlisted } : null;
}

/**
 * The listing work a word may spend whatever is left of the shared budget, so a large expansion
 * earlier in a call cannot turn a later ordinary one into a word too large to list
 * (`touch f{1..100000}; git add {src,lib}/{a,b}/{x,y}.ts`). It is at least `MIN_WORD_ALLOWANCE`
 * and proportional to the word's length past that. The work of a whole call stays linear in its
 * text all the same, because a word only spends what its own expansion needs, and a word needs
 * tens of characters of groups before its expansion reaches that floor.
 */
function wordAllowance(word: string): number {
	return Math.max(MIN_WORD_ALLOWANCE, 8 * (word.length + 1));
}

/** The smallest `wordAllowance`: enough for a product of a few groups of a few names each. */
const MIN_WORD_ALLOWANCE = 4096;

/**
 * Every way a word its brace expansion gives may start (`UnlistedStart`): the text before its
 * first brace, followed by a term of the sequence expression that brace opens, or by each
 * alternative of the plain comma group it opens (`{img,thumb}_...`), or by anything. Text
 * holding an expansion (`$`, a backtick, a process substitution) says nothing about how the word
 * starts once bash runs it, so it is no lead at all.
 */
function unlistedStarts(word: string): UnlistedStart[] {
	const open = word.indexOf("{");
	const lead = word.slice(0, open);
	if (/[$`<>]/.test(lead)) return [{ lead: "", next: "any" }];
	const close = word.indexOf("}", open);
	const content = close < 0 ? "" : word.slice(open + 1, close);
	if (content.includes("{")) return [{ lead, next: "any" }];
	const sequence = braceSequenceStart(content);
	if (sequence !== null) return [{ lead, next: sequence }];
	if (!content.includes(",") || /[$`<>]/.test(content)) return [{ lead, next: "any" }];
	return content.split(",").map((alternative) => ({ lead: lead + alternative, next: "any" }));
}

/** A sequence expression's group, as `braceSequence` reads it. */
const SEQUENCE_GROUP = /\{(?:[-+]?\d+\.\.[-+]?\d+|[A-Za-z]\.\.[A-Za-z])(?:\.\.[-+]?\d+)?\}/g;
/** An extension `SECRET_BASENAME` names, at the start of the text after a `.`. */
const SECRET_EXTENSION = /^(?:env|pem|key|p12|pfx)(?![A-Za-z0-9_])/i;

/**
 * Whether a word too large to list may expand to a secrets file's name (`SECRET_BASENAME`),
 * read from its shape. A term of a sequence never holds a `.`, so when every group in the word
 * is a sequence, a secret's `.` is a literal one: the word may name a secret only where such a
 * `.` is followed by a secret extension, or by a sequence within the three characters one
 * spans (`img_{00001..40000}.png` names none; `x.p{10..13}` may name `x.p12`). Any other group,
 * or an expansion, may give anything.
 */
function mayNameSecret(word: string): boolean {
	const marked = word.replace(SEQUENCE_GROUP, SEQUENCE_MARK);
	if (/[{}$`<>]/.test(marked)) return true;
	for (let dot = marked.indexOf("."); dot >= 0; dot = marked.indexOf(".", dot + 1)) {
		const after = marked.slice(dot + 1);
		if (after.slice(0, 3).includes(SEQUENCE_MARK) || SECRET_EXTENSION.test(after)) return true;
	}
	return false;
}

/** Stands in `mayNameSecret` for a sequence's terms. */
const SEQUENCE_MARK = "\u0001";

/**
 * Whether a word too large to list stands at or after `head` and, by how its words start, may
 * expand to what the rule looks for (`Readings.unlisted`).
 */
function hasUnlistedFrom({ unlisted }: Readings, head: number, mayExpandTo: (word: UnlistedWord) => boolean): boolean {
	for (const [index, word] of unlisted) if (index >= head && mayExpandTo(word)) return true;
	return false;
}

/**
 * Whether words starting so may include an `rm` flag or a catastrophic target
 * (`isCatastrophicTarget`): a `-` lead, a lead of home (`~`, `~/...`), or a `/` or `*` lead that
 * the target shapes still allow (a lone `/` or `*`, `//`, `/` then `*`, `*` then `/`) --
 * `/var/tmp/f`, `*.o` and `~user` complete to none. A term of a sequence begins with none of
 * those, so a lone `/` or `*` followed by one completes to none either (`/{1..9}`).
 */
function mayBeRmOperand({ lead, next }: UnlistedStart): boolean {
	if (lead === "") return next === "any";
	if (lead[0] === "-") return true;
	if (lead[0] === "~") return lead === "~" || lead.startsWith("~/");
	if (lead === "/" || lead === "*") return next === "any";
	if (lead[0] === "/") return lead.startsWith("//") || lead.startsWith("/*");
	if (lead[0] === "*") return lead.startsWith("*/");
	return false;
}

/**
 * Whether words starting so may include a force flag or the `push` subcommand: from a lead that
 * is a `-` or a prefix of `push`, or from a sequence whose terms may start with a letter or `-`.
 */
function mayBeForcePush({ lead, next }: UnlistedStart): boolean {
	if (lead !== "") return lead.startsWith("-") || "push".startsWith(lead.toLowerCase());
	return next !== "digit";
}

/**
 * Whether a word invokes `name`, and every position in a run that does.
 *
 * Not just `argv[0]`: the regexes these rules replace were unanchored, so `sudo rm -rf /`
 * (a guard-corpus case) and `FOO=1 git push -f` were caught without enumerating wrappers.
 * Scanning every index keeps that, and keeps it without a wrapper allow-list to maintain --
 * the cost is that an `echo rm -rf /` also reads as a command head, which is the pre-existing
 * behaviour and the safe direction for a floor.
 *
 * Tokens are compared by BASENAME, so a path-qualified `/bin/rm` or `./git` is the same command
 * as a bare one. The old `\brm` matched inside such a path as well, and losing that would have
 * been a bypass of the floor. It also matched inside `safe-rm`, which basename comparison
 * deliberately drops: a hyphenated neighbour is a DIFFERENT program -- `safe-rm` exists
 * precisely to refuse `rm -rf /` -- so denying it was an artifact of the word boundary rather
 * than a decision, and a miss there falls through to the judge either way.
 *
 * A leading `!` is stripped first. git runs an `alias.*` value that starts with one as a shell
 * command, so the body of `git -c alias.fp='!git push --force' fp` is a real force push whose
 * head token is `!git`.
 */
function isHead(token: string, name: string): boolean {
	if (!token.includes("{")) return staticWordMatches(token, name);
	let byName = braceHeadMatches.get(token);
	if (byName === undefined) {
		if (braceHeadMatches.size >= MAX_BRACE_HEAD_MATCHES) braceHeadMatches.clear();
		byName = new Map();
		braceHeadMatches.set(token, byName);
	}
	let matches = byName.get(name);
	if (matches === undefined) {
		matches = staticWordMatches(token, name);
		byName.set(name, matches);
	}
	return matches;
}

/**
 * `isHead` results for words holding a brace, whose test walks every group in them. A run is
 * read both as written and brace-expanded (see `Readings`), and a word too large to expand
 * stands in both, so each rule would otherwise walk it twice. Cleared as each tool call's
 * readings are derived, so it holds one call's words.
 */
const braceHeadMatches = new Map<string, Map<string, boolean>>();
const MAX_BRACE_HEAD_MATCHES = 32;

function headIndexes(argv: string[], name: string): number[] {
	const out: number[] = [];
	for (let i = 0; i < argv.length; i++) {
		if (isHead(argv[i], name)) out.push(i);
	}
	return out;
}

/**
 * Whether the run, or a command its wrappers or a `find -exec` invoke, is `name`. A tokenized
 * run is walked through its redirection-free words, since a redirection after a wrapper
 * (`sudo >/dev/null sh`) is not the command it runs, and without the positional parameters of
 * a shell script that never reads them (`withoutShellParameters`).
 */
function isCommand(argv: string[], name: string): boolean {
	return someCommand(argv, (words, index) => isHead(words[index], name));
}

/**
 * `isCommand` for several names at once, walking the run a single time. A word without a brace is
 * matched by its basename in one lookup, as `isHead` would match it against each name.
 */
function isAnyCommand(argv: string[], names: ReadonlySet<string>): boolean {
	return someCommand(argv, (words, index) => {
		const token = words[index];
		if (!token.includes("{")) return names.has(headBase(token));
		for (const name of names) if (isHead(token, name)) return true;
		return false;
	});
}

/**
 * Whether `test` holds for the run's command, or a command its wrappers or a `find -exec` invoke,
 * given the words that command sits in and its index there (the walk `isCommand` describes).
 */
function someCommand(argv: string[], test: (words: string[], index: number) => boolean): boolean {
	const queue = [argv];
	let cursor = 0;
	let work = 0;
	while (cursor < queue.length && work < 100_000) {
		const current = withoutShellParameters(redirectionFreeWords(queue[cursor++]));
		work += current.length;
		for (const index of executableCommandIndexes(current)) {
			if (test(current, index)) return true;
			if (isHead(current[index], "find")) queue.push(...findExecCommands(current, index + 1));
		}
		if (current[0] === "{" && current.length > 1 && test(current, 1)) return true;
	}
	return cursor < queue.length;
}

/** A single-dash flag cluster (`-rf`, `-fu`) rather than a long option or an operand. */
function isShortCluster(token: string): boolean {
	return token.length > 1 && token.startsWith("-") && !token.startsWith("--") && /^-[a-zA-Z]*$/.test(token);
}

/**
 * An `rm` flag that makes the delete recursive or unstoppable, in either spelling.
 * `rm --recursive /` is the same call as `rm -r /`, and the floor is the layer that has to
 * hold when the model is wrong or unreachable.
 */
function isRecursiveOrForceFlag(word: string): boolean {
	const token = word.toLowerCase();
	if (token === "--recursive" || token === "--force") return true;
	return isShortCluster(token) && (token.includes("r") || token.includes("f"));
}

/**
 * A component standing for EVERYTHING directly under its parent rather than for something
 * named. A literal prefix makes it specific -- `~/code*` and `~/.cache` name a place and are
 * the judge's call -- but a leading metacharacter does not narrow anything. The optional `.`
 * is what makes `~/.*` the dotfile HALF of home (`.ssh`, `.gnupg`, `.aws`) rather than a
 * smaller target than `~/*`, and `[`/`{` cover the bracket and brace spellings of the same
 * sweep in a word read as written; the brace-expanded reading (see `Readings`) sees the words
 * such a group gives.
 *
 * A LONE `@`, `+` or `!` is the extglob sweep `~/@(*|.[!.]*)`, which `bash -O extglob -c` turns
 * on for one command. The tokenizer reads its `(` as a subshell and its `|` as a pipeline, so
 * the operand that arrives here is the truncated `~/@` -- the trailing operator is all that
 * survives of it, and `~/@types` keeps naming a directory. Its `?(`/`*(` spellings need no
 * clause: they truncate to `~/?` and `~/*`.
 *
 * `EXPANSION_SUPPRESSED` is deliberately not a metacharacter here: `rm -rf ~/"*"` names a file
 * literally called `*`.
 */
const UNBOUNDED_GLOB = /^\.?(?:[*?[{]|[@+!]$)/;

/**
 * A bare `$VAR` reference, the one expansion spelling that survives to be read here:
 * `stripExpansions` already removes `$( )`, `${ }` and backticks. It is deleted rather than
 * trusted, because nothing static knows it does not expand to nothing -- `rm -rf ~/$TOOL` with
 * `TOOL=` is `rm -rf ~/`, and without this the braces alone would decide the verdict, since
 * `~/${TOOL}` splices to `~/` while `~/$TOOL` does not.
 */
const BARE_REF = /\$(?:[A-Za-z_][A-Za-z0-9_]*|\d+|[@*#?!$])/g;

/**
 * The path an operand names RELATIVE to the home directory, or null when it names none. Only
 * the whole word or a `/`-separated prefix counts, so `$HOMEBREW_PREFIX/Cellar` and a file
 * named `~snapshot` are not home.
 *
 * `$HOME` is matched by its exact spelling, unlike every other comparison here. Shell variable
 * names are case-sensitive, so `home=/tmp/build; rm -rf ${home}` deletes a build directory and
 * nothing else -- the replaced pattern denied it only because the whole rule compiled with `i`.
 *
 * The other tilde forms -- `~user`, `~-`, `~+`, `~1` -- are NOT recognized. They are a gap, but
 * closing them here would add denials to a floor that cannot be overridden, so they belong to
 * their own change rather than to a narrowing one.
 */
function homeRemainder(t: string): string | null {
	if (t === "~" || t === "$HOME") return "";
	if (t.startsWith("~/")) return t.slice(2);
	if (t.startsWith("$HOME/")) return t.slice("$HOME/".length);
	return null;
}

/**
 * The components of a path that NAME something, with `.`, empty and expansion-only segments
 * dropped and resolvable `..` popped, so a word is judged by where it POINTS rather than by how
 * it is spelled -- `~/`, `~//`, `~/./.` and `~/code/..` all name home. A `..` with nothing left
 * to pop is KEPT, and that remainder is exactly what marks a path leaving home
 * (`~/x/../../Users`).
 *
 * A segment is stripped of its bare `$VAR` references BEFORE any of that, so one that names
 * nothing cannot absorb a following `..`: unset, `~/$A/../Applications` is `~/../Applications`,
 * and popping the expansion instead would read it as a bounded path under home.
 *
 * Symlinks make this reading approximate, which costs nothing on this path: both readings of
 * `~/link/..` are ones the floor denies.
 */
function pathSegments(path: string): string[] {
	const out: string[] = [];
	for (const raw of path.split("/")) {
		const segment = raw.replace(BARE_REF, "");
		if (segment === "" || segment === ".") continue;
		if (segment === ".." && out.length > 0 && out.at(-1) !== "..") out.pop();
		else out.push(segment);
	}
	return out;
}

/**
 * A `~`/`$HOME` operand whose deletion takes home itself, everything above it, or everything
 * in it.
 *
 * Depth under home is NOT one of those shapes. `rm -rf ~/code/x/dist` is the tilde spelling of
 * `rm -rf /Users/user/code/x/dist`, which reaches the judge, and a floor that denied one but not
 * the other would be a terminal false positive on the spelling alone.
 *
 * The first component that NAMES something is what decides, since `pathSegments` has already
 * dropped the ones built only out of expansions, which may name nothing at all: `~/$A/$B` and
 * `~/$A$B` are `rm -rf ~` unset, `~/$PROJ/*` is `rm -rf ~/*`, and `~/$A/../Applications` is a
 * path above home. Dropping them BEFORE `..` resolves is what makes that last one hold -- left
 * in, the `..` would pop the expansion and leave a bounded `~/Applications` that never was one.
 */
function isCatastrophicHomePath(t: string): boolean {
	const remainder = homeRemainder(t);
	if (remainder === null) return false;
	const segments = pathSegments(remainder);
	if (segments.length === 0) return true;
	if (segments[0] === "..") return true;
	return UNBOUNDED_GLOB.test(segments[0]);
}

/**
 * An operand whose deletion is unrecoverable: the filesystem root, the home directory, or a
 * glob standing in for everything in scope -- bare, or as the prefix of a path under it.
 *
 * Kept deliberately narrow. `rm -rf ./build` and `rm -rf /Users/user/code/x/dist` are ordinary
 * and must reach the judge, so an over-broad target set here would be a terminal false
 * positive rather than an extra prompt.
 */
function isCatastrophicTarget(t: string): boolean {
	return (
		t === "/" ||
		t.startsWith("//") ||
		t === "/*" ||
		t.startsWith("/*/") ||
		t === "*" ||
		t.startsWith("*/") ||
		isCatastrophicHomePath(t)
	);
}

/**
 * True when a run deletes a catastrophic target recursively.
 *
 * Only the FIRST `rm` needs checking, not every one: a flag or target that follows a later head
 * follows the first head too, so the earliest head has the largest tail and the two tests are
 * equivalent. Re-scanning the tail from every head instead would be quadratic in the length of
 * the run -- and this floor runs synchronously, on every tool call, ahead of everything else.
 *
 * `--` ends the options, so a flag after it is a FILENAME: `rm -- -rf /` removes files literally
 * named `-rf` and `/`, which fails on a directory rather than recursing. Everything after it is
 * read as an operand, while a real flag before it still counts -- `rm -rf -- /` is the
 * catastrophic form.
 *
 * A word too large to list at or after the head may expand to both the flag and the target, so
 * it is read as them unless every word it gives starts with text neither can (`frame_{1..99999}`
 * names only `frame_...` files; `Readings.unlisted`).
 */
function isRecursiveRootDelete(reading: Readings): boolean {
	const { spliced, asWritten } = reading;
	const head = spliced.findIndex((t) => isHead(t, "rm"));
	if (head < 0) return false;
	if (hasUnlistedFrom(reading, head, ({ starts }) => starts.some(mayBeRmOperand))) return true;
	let flagged = false;
	let targeted = false;
	let operandsOnly = false;
	for (let i = head + 1; i < spliced.length; i++) {
		const word = spliced[i];
		if (!operandsOnly && word === "--") {
			operandsOnly = true;
			continue;
		}
		if (!operandsOnly && isRecursiveOrForceFlag(word)) flagged = true;
		else if (operandsOnly || !word.startsWith("-")) {
			if (isCatastrophicTarget(word) || isCatastrophicTarget(asWritten[i])) targeted = true;
		}
		if (flagged && targeted) return true;
	}
	return false;
}

/**
 * The index of git's subcommand within `argv`, walking the global options that sit between
 * `git` and the subcommand, or -1 when there is none.
 *
 * Only options that genuinely take a SEPARATE value consume the next token, read from
 * `GIT_GLOBAL_VALUE_OPTS` rather than guessed: treating every option as value-taking makes a
 * boolean global swallow the real subcommand, so `git --no-pager grep push -f x` would read
 * `push` as the subcommand and hard-deny a read-only grep. An unknown option that does take a
 * separate value therefore has its value read as the subcommand and the command falls through
 * to the judge -- the safe direction to be wrong in here.
 *
 * An option git does not HAVE ends the walk with no subcommand. `git --`, `git -abc` and
 * `git --frobnicate push --force` are all rejected by git itself (`unknown option`) and run no
 * push at all, so reading past them would deny a command that does nothing. The value-less
 * globals are read from `GIT_GLOBAL_BOOL_OPTS` rather than restated here, so every consumer
 * agrees on what a global option is.
 *
 * An inline value is a LONG-option spelling only. git's short globals want a separate word, and
 * reject the glued form outright (`git -c=foo.bar` is `unknown option`), so that shape ends the
 * walk as well. So does a global that ANSWERS instead of continuing: `git --html-path push -f`
 * prints a path and pushes nothing.
 */
function gitSubcommandIndex(argv: string[], head: number): number {
	let i = head + 1;
	while (i < argv.length) {
		const t = argv[i].toLowerCase();
		if (!t.startsWith("-")) return i;
		const inlineValue = t.indexOf("=");
		const name = inlineValue < 0 ? t : t.slice(0, inlineValue);
		if (inlineValue >= 0) {
			if (!name.startsWith("--") || !GIT_VALUE_OPTS_LOWER.has(name)) return -1;
			i += 1;
			continue;
		}
		if (GIT_TERMINATING_GLOBALS.has(t)) return -1;
		if (GIT_VALUE_OPTS_LOWER.has(t)) {
			i += 2;
			continue;
		}
		if (!GIT_BOOL_OPTS_LOWER.has(t)) return -1;
		i += 1;
	}
	return -1;
}

/**
 * An unconditional force flag: `--force` exactly, or a short cluster carrying `f` (`-f`, `-fu`).
 *
 * Matching `--force` as a whole token is what keeps the safety-checked `--force-with-lease` and
 * `--force-if-includes` out. The exemption is a property of the FLAG, not of the command: git
 * documents that a real `--force` disables the lease check, so `git push -f --force-with-lease`
 * is an unconditional force push and stays denied.
 *
 * The cluster may carry `4` and `6`, unlike rm's: they are push options, so `git push -f4` is a
 * force push spelled in one word. No other digit is, so `git push -1f` is `unknown switch` and
 * pushes nothing.
 */
/** A `git push` short cluster carrying `f`. Its other letters are options; `4` and `6` are too. */
const PUSH_FORCE_CLUSTER = /^-[a-z46]*f[a-z46]*$/;

function isForceFlag(word: string): boolean {
	const token = word.toLowerCase();
	return token === "--force" || PUSH_FORCE_CLUSTER.test(token);
}

/**
 * True when a run force-pushes.
 *
 * Every `git` is a candidate head, because one run can carry more than one (`git -c a=b git push
 * -f`), but the tail is not re-scanned per head: the last force flag is found once, and a head
 * qualifies when its subcommand is `push` and that flag comes after it. The subcommand walks
 * only consecutive option tokens, so the walks over all heads together stay linear.
 *
 * `--` ends the options here too: `git push -- --force` pushes a REFSPEC named `--force` (git
 * rejects it as no such ref) rather than forcing, so a flag after the marker does not count. The
 * marker that matters is the one after THIS push, not the first in the run -- a wrapper consumes
 * its own (`env -- git push --force` really does force) -- so both the next force flag and the
 * next marker are pre-computed per position, which also keeps the per-head test O(1).
 *
 * A word too large to list at or after a `git` may expand to `push --force`, so it is read as
 * that unless every word it gives starts with text neither can (`git add f{1..99999}`;
 * `Readings.unlisted`).
 */
function isForcePush(reading: Readings): boolean {
	const argv = reading.spliced;
	const heads = headIndexes(argv, "git");
	if (heads.length > 0 && hasUnlistedFrom(reading, heads[0], ({ starts }) => starts.some(mayBeForcePush))) return true;
	const nextForce: number[] = new Array(argv.length + 1).fill(argv.length);
	const nextEndOfOptions: number[] = new Array(argv.length + 1).fill(argv.length);
	for (let i = argv.length - 1; i >= 0; i--) {
		nextForce[i] = isForceFlag(argv[i]) ? i : nextForce[i + 1];
		nextEndOfOptions[i] = argv[i] === "--" ? i : nextEndOfOptions[i + 1];
	}
	for (const head of heads) {
		const sub = gitSubcommandIndex(argv, head);
		if (sub < 0 || argv[sub].toLowerCase() !== "push") continue;
		if (nextForce[sub + 1] < nextEndOfOptions[sub + 1]) return true;
	}
	return false;
}

/**
 * A write REDIRECTION operator, and the fd-DUPLICATING subset of it.
 *
 * Built from the same `REDIRECTION_FD` as the operator set in shell-tokens.ts, so the two cannot drift on
 * what a descriptor looks like (`2>`, `{fd}>`), but spelled out rather than subtracted from
 * `REDIRECTION_OPERATOR`: a pattern cannot express "that set minus the reads", and the reads
 * are exactly what must not fire. `<`, `<<`, `<<-`, `<<<` and `<&` open nothing for writing --
 * `cat <in.pem` READS a secret, which is the judge's call, not the floor's. `<>` is in: it
 * opens the file for writing as well as reading.
 *
 * `>&` is the ambiguous one. bash duplicates a descriptor when the word after it is a number
 * or `-` (`2>&1`, `>&-`) and CREATES THE FILE otherwise -- `>&out.key` is `&>out.key`. So the
 * operator matches either way and the target decides.
 *
 * Alternation order is load-bearing: JS takes the first branch that matches, so every operator
 * that merely STARTS with `>` has to precede the bare `>`, or `>&2` reads as a write to a file
 * named `&2`.
 */
const WRITE_REDIRECTION = new RegExp(`^(?:${REDIRECTION_FD}(?:>>|>\\||>&|<>|>)|&>>?)`);
const FD_DUPLICATING = new RegExp(`^${REDIRECTION_FD}>&`);
/** What `>&` duplicates rather than creates: a descriptor number, or `-` to close one. */
const FD_TARGET = /^(?:\d+|-)$/;

/**
 * A filename that marks a secret, tested on the word's BASENAME.
 *
 * The directory part is deliberately ignored: what is created is the last component, and a
 * `.env` anywhere in a long path was how the replaced pattern turned
 * `rg -n x ~/code/*.env* 2>/dev/null` into a terminal denial of a read-only search.
 *
 * The lookahead is the old rule's `\b` spelled exactly -- the extension always ends in a word
 * character, so this is the same boundary: `.env.local`, `.env-local` and `id.pem.bak` are
 * secrets files, `known.keys` is not.
 */
const SECRET_BASENAME = /\.(env|pem|key|p12|pfx)(?![A-Za-z0-9_])/i;

function isSecretFile(word: string): boolean {
	return SECRET_BASENAME.test(word.slice(word.lastIndexOf("/") + 1));
}

/**
 * Both readings of ONE word (see `Readings`).
 *
 * A redirection destination is the one word a rule cannot read out of `Readings`:
 * `withoutRedirections` deletes the operator AND its target, so the readings arrays never
 * contain it. Applying the same two readings here keeps `> out.k$()ey` and `> ${HOME}/x.key`
 * from being spelled past the floor.
 */
export function isSecretPath(word: string): boolean {
	return isSecretFile(stripExpansions(word)) || isSecretFile(word.replace(BRACED_PARAM, "$$$1"));
}

/**
 * True when a run redirects a WRITE at a secrets file.
 *
 * Read from the raw `argv` rather than from `Readings`, for the reason above. A process
 * substitution only looks like an operator -- `>(cmd)` is a word naming a `/dev/fd` path, and
 * its body is tokenized as a run of its own -- so it is skipped exactly as
 * `withoutRedirections` skips it. An operator carrying its own destination consumes nothing; a
 * bare one takes the following word, which is then not re-examined as an operator.
 *
 * bash brace-expands a destination too and writes it when that leaves one word, so that word is
 * tested as well (`isSecretDestination`).
 */
function hasSecretRedirect(argv: string[], toolName: string): boolean {
	for (let i = 0; i < argv.length; i++) {
		const word = argv[i];
		if (PROCESS_SUBSTITUTION_WORD.test(word)) continue;
		const operator = word.match(WRITE_REDIRECTION);
		if (operator === null) continue;
		let target = word.slice(operator[0].length);
		if (target === "") {
			target = argv[i + 1] ?? "";
			i += 1;
		}
		if (FD_DUPLICATING.test(operator[0]) && FD_TARGET.test(target)) continue;
		if (isSecretDestination(target, toolName)) return true;
	}
	return false;
}

/**
 * Whether a redirection destination names a secret, as written or as the file bash writes when
 * its brace expansion leaves exactly one word (`> .{e..e}nv` writes `.env`, `> {x.key,}` writes
 * `x.key`); two or more words make bash refuse the redirection as ambiguous. A word that may
 * expand to nothing does not count toward those two, since bash drops it before counting
 * (`> {$xv,.en}v` writes `.env` with `xv` unset), and each of the word's readings
 * (`braceReadings`) is counted on its own.
 *
 * The listing is bounded by a small multiple of the destination's length, since an ordinary
 * destination expands to a handful of words. Past that bound, bash may still write one: nested
 * empty groups (`{{,}{,}...,.e{n..n}v}`) give many empty words, which bash drops, and one name.
 * So a bash destination too large to list is read as a secret -- one that large is ambiguous
 * unless it is padding of exactly that kind. Another tool's text is not run by a shell, and a
 * write or edit tool's path is a filename rather than shell text (see `denyRuns` in
 * hard-deny.ts), which is never expanded.
 */
function isSecretDestination(target: string, toolName: string): boolean {
	if (isSecretPath(target)) return true;
	if (toolName === "write" || toolName === "edit") return false;
	const expanded = braceReadings(target, wordAllowance(target));
	if (expanded.kind === "too-large") return toolName === "bash";
	return expanded.readings.some(
		(words) => words.filter((word) => !mayExpandToNothing(word)).length <= 1 && words.some(isSecretPath),
	);
}

/**
 * Whether a word may give no text once bash expands it: nothing is left of it but parameter
 * expansions and substitutions, so bash may drop it as an unquoted null word (`$xv` with `xv`
 * unset, `$(:)`).
 */
function mayExpandToNothing(word: string): boolean {
	return stripExpansions(word).replace(BARE_REF, "") === "";
}

/**
 * `cp`/`mv` options that take a SEPARATE value, so the word after them is not an operand.
 *
 * Case-sensitive, unlike the command name: `-t` is `--target-directory` and takes one, while
 * `-T` is `--no-target-directory` and takes none, so folding case would make `cp -T a.key dst`
 * swallow the secret as an option value. `-S`/`-s` divide the same way.
 */
const COPY_VALUE_OPTS = new Set(["-t", "--target-directory", "-S", "--suffix"]);
const NO_VALUE_OPTS = new Set<string>();

/**
 * True when any operand of a `cp`/`mv`/`tee` run names a secrets file.
 *
 * EVERY operand is tested, not just the destination, because which operand becomes the created
 * file is not statically decidable: `cp a.key /etc/ssl` writes `/etc/ssl/a.key` when the
 * destination is a directory and `/etc/ssl` when it is not, and only the filesystem knows
 * which. Testing all of them is the fail-closed reading, it is exactly the coverage the
 * replaced pattern had (`\bcp\b.*\.key`), and it also catches the exfil direction a
 * destination-only test misses -- `cp id.pem /tmp/x` renames a secret to a plain name.
 *
 * Only the FIRST head needs checking, for the same reason as in `isRecursiveRootDelete` and
 * with the same consequence: because the test is over the whole tail, the earliest head's tail
 * contains every later head's, so one pass is equivalent to re-scanning from each and the rule
 * stays linear in a run of repeated `cp` tokens.
 *
 * `--` ends the options: after it a word starting with `-` is a FILENAME, which only widens
 * what is checked. A bare `-` is an operand in both directions. A word too large to list at or
 * after the head is read as a secret's name unless its shape rules one out (`mayNameSecret`;
 * `Readings.unlisted`).
 */
function hasSecretOperand(reading: Readings, isTarget: (token: string) => boolean, valueOpts: Set<string>): boolean {
	const { spliced, asWritten } = reading;
	const head = spliced.findIndex(isTarget);
	if (head < 0) return false;
	if (hasUnlistedFrom(reading, head, (word) => word.mayNameSecret)) return true;
	let operandsOnly = false;
	for (let i = head + 1; i < spliced.length; i++) {
		const word = spliced[i];
		if (!operandsOnly && word === "--") {
			operandsOnly = true;
			continue;
		}
		if (!operandsOnly && word.startsWith("-") && word !== "-") {
			if (valueOpts.has(word)) i += 1;
			continue;
		}
		if (isSecretFile(word) || isSecretFile(asWritten[i])) return true;
	}
	return false;
}

/**
 * True when a run writes, copies or moves something into a file whose name marks it a secret.
 *
 * Both halves are needed and neither can be expressed in the other's terms: the redirect half
 * reads the raw `argv`, because the readings have had exactly those words removed, while the
 * `cp`/`mv`/`tee` half reads the redirect-STRIPPED readings, because a destination is not an
 * operand -- `cp a.txt b.txt 2> ~/err.log` must not read the error log as a third file being
 * copied. The redirect half reads each run once, from its as-written reading.
 */
function isSecretWrite(reading: Readings, toolName: string): boolean {
	return (
		(!reading.braceExpanded && hasSecretRedirect(reading.argv, toolName)) ||
		hasSecretOperand(reading, (t) => isHead(t, "cp") || isHead(t, "mv"), COPY_VALUE_OPTS) ||
		hasSecretOperand(reading, (t) => isHead(t, "tee"), NO_VALUE_OPTS)
	);
}

/** The shells a download piped into executes: every shell, plus the `dsh` distributed shell. */
const SHELL_COMMANDS: ReadonlySet<string> = new Set([...SHELL_HEADS, "dsh"]);

function isShellCommand(argv: string[]): boolean {
	return isAnyCommand(argv, SHELL_COMMANDS);
}

/** A regex alternation matching any of `names` literally. */
function alternation(names: Iterable<string>): string {
	return [...names].map((name) => name.replace(".", "\\.")).join("|");
}

/**
 * The raw-text fallback for a non-Bash target: `download` piped, optionally through `sudo` and an
 * `APPLET_WRAPPERS` binary, to a `SHELL_COMMANDS` shell.
 */
function downloadPipeShellPattern(download: string): RegExp {
	return new RegExp(
		String.raw`${download}\s.+\|\s*(sudo\s+)?(?:(?:${alternation(APPLET_WRAPPERS)})\s+)?(?:${alternation(SHELL_COMMANDS)})\b`,
		"i",
	);
}
const CURL_PIPE_SHELL = downloadPipeShellPattern("curl");
const WGET_PIPE_SHELL = downloadPipeShellPattern("wget");
/**
 * A word whose basename, as `headBase` reads it, is an `OPAQUE_SCRIPT_SHELLS` shell: the linear
 * test that spares a run without one the command walk of `opaqueShellReadsScript`.
 */
const OPAQUE_SHELL_WORD = new RegExp(`(?:^!*|/)(?:${alternation(OPAQUE_SCRIPT_SHELLS)})$`, "i");

/** Whether a command the run or its wrappers invoke is handed a script it cannot be read in (`opaqueShellReadsScript`). */
function handsOpaqueShellScript(argv: string[]): boolean {
	return argv.some((word) => OPAQUE_SHELL_WORD.test(word)) && someCommand(argv, opaqueShellReadsScript);
}
const FORK_BOMB = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/i;
type ShellAnalysis = ExecutableShellAnalysis;
const shellAnalysesByRuns = new WeakMap<string[][], ShellAnalysis[]>();
const downloadPipesByAnalysis = new WeakMap<ShellAnalysis, ReadonlySet<string>>();

function pipedGroupParts(topLevel: ShellCommandAnalysis["topLevel"]): Set<number> {
	const deltas = new Int32Array(topLevel.length + 1);
	const isPipe = (index: number): boolean => {
		const part = topLevel[index];
		return part?.kind === "operator" && part.operator === "|";
	};
	const mark = (start: number, end: number): void => {
		if (isPipe(start - 1)) {
			deltas[start] += 1;
			deltas[end + 1] -= 1;
		}
	};
	const groups: number[] = [];
	for (let i = 0; i < topLevel.length; i++) {
		const part = topLevel[i];
		if (part.kind === "group" && part.boundary === "start") groups.push(i);
		else if (part.kind === "group" && part.boundary === "end") {
			const start = groups.pop();
			if (start !== undefined) mark(start, i);
		}
	}
	const braces: number[] = [];
	for (let i = 0; i < topLevel.length; i++) {
		const part = topLevel[i];
		if (part.kind !== "command") continue;
		if (part.argv[0] === "{") braces.push(i);
		else if (part.argv[0] === "}") {
			const start = braces.pop();
			if (start !== undefined) mark(start, i);
		}
	}
	const marked = new Set<number>();
	let coverage = 0;
	for (let i = 0; i < topLevel.length; i++) {
		coverage += deltas[i];
		if (coverage > 0) marked.add(i);
	}
	return marked;
}

/**
 * Whether a `download` run in the analysis hands what it fetches to a command that may execute
 * it: its output reaches, through a `|` chain, a `SHELL_COMMANDS` shell or a run the pipeline walk
 * judged an executing sink (`SinkVerdicts.executingSinks`: `| $SHELL`, `| s?`, `| /tmp/cat`, a
 * defined `cat`, `| cat "$(sh)"`), or its own output redirections reach one
 * (`SinkVerdicts.outputExecutedRuns`: `> >(sh)`). A sink named by a variable counts whatever
 * the variable is called (`| $PAGER` too), since its value may name a shell.
 */
function hasDownloadPipeToShell(analysis: ShellAnalysis, download: string): boolean {
	if (
		analysis.piped &&
		analysis.analysis.topLevel.some((part) => part.kind === "command" && isCommand(part.argv, download))
	)
		return true;
	let downloads = downloadPipesByAnalysis.get(analysis);
	if (downloads === undefined) {
		const found = new Set<string>();
		const { executingSinks, outputExecutedRuns } = analysis.sinkVerdicts;
		const grouped = pipedGroupParts(analysis.analysis.topLevel);
		let depth = 0;
		let shellDepth = 0;
		let reachesShell = false;
		let newlinePending = false;
		for (let i = analysis.analysis.topLevel.length - 1; i >= 0; i--) {
			const part = analysis.analysis.topLevel[i];
			if (part.kind === "group") {
				depth += part.boundary === "end" ? 1 : -1;
				continue;
			}
			if (part.kind === "operator") {
				if (part.operator === "|") {
					newlinePending = false;
					continue;
				}
				if (part.operator === "\n") {
					newlinePending = true;
					continue;
				}
				if (depth <= shellDepth && !grouped.has(i)) reachesShell = false;
				newlinePending = false;
				continue;
			}
			if (newlinePending && depth <= shellDepth && !grouped.has(i)) reachesShell = false;
			newlinePending = false;
			const ownOutputExecuted = outputExecutedRuns.has(part.argv);
			if (reachesShell || ownOutputExecuted) {
				if (isCommand(part.argv, "curl")) found.add("curl");
				if (isCommand(part.argv, "wget")) found.add("wget");
			}
			if (ownOutputExecuted || executingSinks.has(part.argv) || isShellCommand(part.argv)) {
				reachesShell = true;
				shellDepth = depth;
			}
			if (part.argv[0] === "}") depth += 1;
			if (part.argv[0] === "{") depth = Math.max(0, depth - 1);
		}
		downloads = found;
		downloadPipesByAnalysis.set(analysis, downloads);
	}
	return downloads.has(download);
}

function isForkBomb({ analysis }: ShellAnalysis): boolean {
	const { topLevel } = analysis;
	const signature = topLevel.map((part) =>
		part.kind === "command"
			? part.argv.length === 1 && [":", "{", "}"].includes(part.argv[0])
				? part.argv[0]
				: part.argv[0] === "{" && part.argv[1] === ":"
					? "{:"
					: "?"
			: part.kind === "operator"
				? part.operator
				: part.boundary === "start"
					? "("
					: ")",
	);
	const patterns = [
		[":", "(", ":", "|", ":", "&", ")", ";", ":"],
		[":", "(", ")", "{:", "|", ":", "&", "}", ";", ":"],
		[":", "(", ")", "{", ":", "|", ":", "&", "}", ";", ":"],
	];
	return patterns.some((pattern) => {
		for (let start = 0; start < signature.length; start++) {
			let cursor = start;
			let matched = true;
			for (const token of pattern) {
				while (signature[cursor] === "\n") cursor += 1;
				if (signature[cursor] !== token) {
					matched = false;
					break;
				}
				cursor += 1;
			}
			if (matched) return true;
		}
		return false;
	});
}

/** The command's executable shell sources (`analyzeExecutableShellSources`), analyzed once per tokenization. */
function shellAnalysesFor(runs: string[][], source: string): ShellAnalysis[] {
	let analyses = shellAnalysesByRuns.get(runs);
	if (analyses === undefined) {
		analyses = analyzeExecutableShellSources(source);
		shellAnalysesByRuns.set(runs, analyses);
	}
	return analyses;
}

/**
 * Whether a built-in text rule matches: over the command's shell structure for a bash command, or
 * over the raw text with `fallback` for another tool's target and for a bash command whose shell
 * analysis could not be taken.
 */
function matchesBuiltInText(
	runs: string[][],
	source: string,
	toolName: string,
	match: (analysis: ShellAnalysis) => boolean,
	fallback: RegExp,
): boolean {
	if (toolName !== "bash") return fallback.test(source);
	const analyses = shellAnalysesFor(runs, source);
	if (analyses.length === 0) return fallback.test(source);
	return analyses.some(match);
}

/**
 * Whether an awk program in the command, or in any shell source it executes (`bash -c '...'`,
 * `eval`, a substitution body), carries an awk-native escape. The command itself is always read,
 * even when its analysis could not be taken.
 */
function hasAwkNativeEscape(runs: string[][], target: string): boolean {
	const nested = shellAnalysesFor(runs, target).slice(1);
	return [target, ...nested.map((analysis) => analysis.source)].some((source) =>
		extractAwkPrograms(source).some(awkProgramHasNativeEscape),
	);
}

/**
 * The built-in hard-deny rules that are argv-shaped, expressed as predicates over tokenized
 * command runs instead of regexes over the raw string.
 *
 * These built-in rules are about the SHAPE of a command -- which program, which flags, which
 * operand -- and every attempt to express that as a regex has had to re-derive shell word
 * splitting inline: option runs on both sides of a flag cluster, `--`, git's global options in
 * four spellings, quoted values containing spaces, and a hand-written "one command" bound so a
 * chained `tail -f` is not read as a force push. Tokenizing first makes both directions precise
 * at once -- misses AND the terminal false positives -- and closes the arrangements no regex
 * round reached: backslash-escaped values, command substitution, mixed quoting.
 *
 * The secrets rule is the same argument run the other way. Its pattern was a write
 * operator, `.*`, and a secret extension, and the `.*` crossed `;` and `|` -- so a
 * discarded-stderr redirect in one command paired with a `.env` mentioned in the next, and
 * read-only `rg`/`cat`/`jq` calls were hard-denied with no judge behind the floor to overrule
 * it. Which word is WRITTEN is a position, not a distance, and positions only exist after
 * tokenizing.
 *
 * Config-supplied `hardDenyPatterns` stay regex; only these built-ins are token predicates.
 */
export const DEFAULT_HARD_DENY_ARGV: CompiledArgvHardDenyRule[] = [
	{
		kind: "argv",
		match: (runs, toolName, target) =>
			matchesBuiltInText(
				runs,
				target,
				toolName,
				(analysis) => hasDownloadPipeToShell(analysis, "curl"),
				CURL_PIPE_SHELL,
			),
		reason: "curl piped to a shell",
	},
	{
		kind: "argv",
		match: (runs, toolName, target) =>
			matchesBuiltInText(
				runs,
				target,
				toolName,
				(analysis) => hasDownloadPipeToShell(analysis, "wget"),
				WGET_PIPE_SHELL,
			),
		reason: "wget piped to a shell",
	},
	{
		kind: "argv",
		match: (runs, toolName, target) => matchesBuiltInText(runs, target, toolName, isForkBomb, FORK_BOMB),
		reason: "fork bomb",
	},
	{
		kind: "argv",
		match: (runs, toolName) => readingsFor(runs, toolName).some(isRecursiveRootDelete),
		reason: "recursive/force delete targeting /, ~, $HOME or *",
	},
	{
		kind: "argv",
		match: (runs, toolName) => readingsFor(runs, toolName).some(isForcePush),
		reason: "git push --force",
	},
	{
		kind: "argv",
		match: (runs, toolName) => readingsFor(runs, toolName).some((reading) => isSecretWrite(reading, toolName)),
		reason: "write/move to a secrets file",
	},
	{
		kind: "argv",
		match: (runs, toolName) =>
			toolName === "bash" &&
			readingsFor(runs, toolName).some(
				({ spliced, asWritten }) => isCommand(spliced, "sed") || isCommand(asWritten, "sed"),
			),
		reason:
			"sed is hard-denied; use slice lines for range reads, ripgrep (rg) or slice grep for searching/extracting, and the edit tool for in-place edits",
	},
	{
		kind: "argv",
		match: (runs, toolName, target) => toolName === "bash" && hasAwkNativeEscape(runs, target),
		reason:
			'awk in-program file writes (print/printf > file) and getline command/file forms ("cmd" | getline, getline < file) are hard-denied; print/printf to stdout and redirect with the shell, use the write/edit tools for files, and run commands directly rather than via awk getline',
	},
	{
		kind: "argv",
		match: (runs, toolName) =>
			readingsFor(runs, toolName).some(
				({ spliced, asWritten }) => handsOpaqueShellScript(spliced) || handsOpaqueShellScript(asWritten),
			),
		reason:
			"script handed to csh, tcsh or PowerShell (a -c/-Command string, an encoded command, or piped input), whose syntax the floor cannot read; run the commands directly or through sh -c",
	},
];
