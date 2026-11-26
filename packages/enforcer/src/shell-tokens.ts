/**
 * Shell-aware tokenizer for the hard-deny floor.
 *
 * The floor's argv-shaped rules (`rm -rf /`, `git push --force`) were regexes over the raw
 * command string, and every review round found another token arrangement that shielded the
 * dangerous word from the pattern -- long flags, `--`, options on either side of the flag
 * cluster, git's global options, quoted option values. Each fix traded one direction against
 * the other: a floor MISS falls through to the judge (recoverable), but a floor FALSE POSITIVE
 * is terminal, because `matchesHardDeny` short-circuits the pipeline before the judge and the
 * user cannot override it. Tokenizing makes both directions precise at once.
 *
 * This tokenizer deliberately shares no definition with a whitespace-only operator splitter.
 * Such a splitter is correct only where an upstream rule has already rejected `$` and
 * backticks, and this module runs before any such rejection, so retrofitting one here would
 * change fail-closed behavior.
 */

/**
 * How much nested text one tokenization may descend into, in characters.
 *
 * The floor must keep seeing dangerous content that appears inside quotes, because a quoted
 * string is routinely the thing that gets executed (`node -e "...execSync('git push -f')"`,
 * a heredoc body piped to a shell). Descent replaces the old raw-text scan for that, so it
 * must not be escapable simply by adding layers -- a fixed DEPTH cap would be, since wrapping
 * a command in one more `bash -c "..."` is mechanical.
 *
 * A work budget bounds the same cost without handing out that lever: every level's text is a
 * strict substring of its parent's, so realistic commands (even hundreds of layers deep) are
 * covered in full, and only inputs orders of magnitude larger than any real tool call run out.
 * The scan itself never backtracks, so this is the only bound needed.
 */
export const MAX_NEST_WORK = 2_000_000;

/** What reading a substitution's body costs `MAX_NEST_WORK`, over the characters of its opener. */
const SUBSTITUTION_WORK = 12;
const SUBSTITUTION_OPENER = /[$<>]\(/g;

/**
 * The work reading `source` costs a budget: one per character, plus `SUBSTITUTION_WORK` for each
 * substitution it opens. Each opener starts a body scanner of its own, which costs a dozen plain
 * characters, so a source dense with nested substitutions (`"$("$(...)")"`) spends its budget in
 * proportion to the work its reads take rather than to its length alone.
 */
function nestedSourceCost(source: string): number {
	let openers = 0;
	SUBSTITUTION_OPENER.lastIndex = 0;
	while (SUBSTITUTION_OPENER.exec(source) !== null) openers += 1;
	return source.length + openers * SUBSTITUTION_WORK;
}

/**
 * Stands in for a character that was written but cannot expand, because quoting or a backslash
 * made it literal.
 *
 * Dequoting alone loses the difference between `rm -rf ~` and `rm -rf "~"`, and they are not
 * the same command: bash expands a bare tilde to the home directory, but a quoted one is just
 * a file named `~`. Same for a quoted `*`, and for `$HOME` in SINGLE quotes -- while `"$HOME"`
 * in double quotes does still expand. Passing the character through would make the floor deny
 * an ordinary delete of a literal file, which is the terminal direction of being wrong.
 *
 * Redirection characters are suppressed for the same reason: `git push origin ">" --force`
 * passes a literal `>` as a refspec, and reading it as an operator would consume `--force` as
 * its destination and walk a real force push past the floor.
 *
 * A quoted `/` is deliberately NOT suppressed: quoting changes nothing about what it names.
 */
export const EXPANSION_SUPPRESSED = "\u0000";
const SUPPRESSED_BY_SINGLE_QUOTES = /[~*$<>]/g;

/** A `${...}` span, kept whole, or a character double quotes suppress, as `{`, `}` and `,` also are. */
const SUPPRESSED_IN_DOUBLE_QUOTED_TEXT = /\$\{[^}]*\}|[{},~*<>]/g;
const SUPPRESSED_IN_SINGLE_QUOTED_TEXT = /[{},~*$<>]/g;

function suppressQuotedMetacharacters(text: string, quote: "'" | '"'): string {
	if (quote === "'") return text.replace(SUPPRESSED_IN_SINGLE_QUOTED_TEXT, EXPANSION_SUPPRESSED);
	return text.replace(SUPPRESSED_IN_DOUBLE_QUOTED_TEXT, (match) => (match.length > 1 ? match : EXPANSION_SUPPRESSED));
}

/**
 * Characters that end a command run.
 *
 * Unquoted `(` and `)` are in here as SYNTAX, not as text: a subshell group runs the commands
 * inside it, so `(git push --force)` must present a `git` head rather than a `(git` token. The
 * substitution forms (`$(`, `<(`, `>(`) are consumed before this set is consulted, so a
 * parenthesis reaching it is always grouping.
 */
/**
 * A finished word worth re-reading as a command in its own right.
 *
 * A word can only hold whitespace or shell punctuation by having been quoted or escaped, and
 * that is exactly how a script payload is passed: `sh -c "rm -rf /"` and `sh -c rm\ -rf\ /` are
 * the same call, but the second has no quoted run to descend into -- only a finished word that
 * reads as a command. Testing the ASSEMBLED word covers both.
 *
 * This is in ADDITION to descending into each quoted run on its own, which is what isolates a
 * payload glued to its surroundings -- `git -c alias.fp='!git push --force' fp` reads as a push
 * only when the quoted value is read by itself. A word that is NOTHING BUT one quoted run is
 * left to that path alone: the run is re-read from its raw text, with its own quoting and
 * redirections intact, where the assembled word has already had them neutralized. Only words that quoting or escaping actually
 * changed are tested, so a word carrying a substitution verbatim (`$(echo /)`) is not handed
 * back to the tokenizer to produce itself again; its body is descended into on its own.
 *
 * A backtick carries a command whatever its body holds: a double-quoted run keeps it live, so
 * ``"`cmd`"`` runs `cmd` exactly as `"$(cmd)"` does, and bash reading such a run can meet it
 * inside a `'` that the double quotes made literal (``"x'`cmd`'"``). A single-quoted run holding
 * one is re-read too, as it already is once the backtick body holds a space: the fail-closed
 * direction.
 */
const CARRIES_A_COMMAND = /[\s;&|()`]/;

/**
 * The POSIX-family shells: their `-c` string, a here-string, or piped stdin is their script,
 * found by the same invocation walk (`shellScriptOperand`) and read as shell source.
 */
const POSIX_SHELL_HEADS = [
	"ash",
	"bash",
	"dash",
	"hush",
	"ksh",
	"ksh93",
	"lksh",
	"mksh",
	"oksh",
	"posh",
	"rbash",
	"sh",
	"yash",
	"zsh",
];

/** The shells whose script is read as shell source: a `-c` string, a here-string, or piped stdin. */
export const SHELL_SOURCE_HEADS: ReadonlySet<string> = new Set([...POSIX_SHELL_HEADS, "fish"]);

/**
 * Shells whose script the floor cannot read (`opaqueShellReadsScript`). Reading a csh or
 * PowerShell script as shell source misses commands those shells run: neither takes `\"` as an
 * escape inside double quotes, so `tcsh -c 'echo "A\" ; <cmd> ; echo "\"'` runs `<cmd>` where a
 * POSIX reading sees one quoted operand, and csh defines an alias as `alias name 'body'`.
 * PowerShell's `-EncodedCommand` is base64 and not read at all. A script handed to one is
 * denied rather than half-read.
 */
export const OPAQUE_SCRIPT_SHELLS: ReadonlySet<string> = new Set([
	"csh",
	"powershell",
	"powershell.exe",
	"pwsh",
	"pwsh.exe",
	"tcsh",
]);

/** Every shell, whichever way its script is read: what a download piped into one executes. */
export const SHELL_HEADS: ReadonlySet<string> = new Set([...SHELL_SOURCE_HEADS, ...OPAQUE_SCRIPT_SHELLS]);

/** Multi-call binaries whose first operand names the applet they run (`busybox sh -c ...`). */
export const APPLET_WRAPPERS: ReadonlySet<string> = new Set(["busybox", "toybox"]);

/**
 * Heads whose ARGUMENTS may themselves execute, so a quoted word handed to one is read
 * back as a command (`ssh host 'rm -rf /'`, `timeout 5 'rm -rf /'`, `bash -c '...'`).
 * Shells and interpreters run their string arguments outright; the wrappers (`env`,
 * `sudo`, `timeout`, `xargs`, `find` with `-exec`, ...) hand their arguments to `exec`,
 * where a quoted word that assembled into a program name or script still runs. `trap`
 * belongs with `eval`: its handler operand is a command string the shell runs later.
 *
 * This is the boundary this module draws: a quoted word only EXECUTES from an executable
 * position, and a prose operand (`git commit -m 'docs: warn against rm -rf ~'`, a grep
 * pattern) is data to the command that receives it. Re-reading every quoted word as a
 * command made the floor -- terminal, with no judge behind it -- fire on commit messages
 * that merely documented a dangerous shape. The set errs toward inclusion (a miss falls
 * through to the judge only for the quoted reading; a false positive is terminal), and
 * membership is matched like `isHead` in argv-deny.ts: lowercased, leading `!` stripped
 * (a git shell-alias body), compared by basename.
 */
const INTERPRETER_LIKE_HEADS = new Set([
	...SHELL_HEADS,
	...APPLET_WRAPPERS,
	"env",
	"eval",
	"trap",
	"command",
	"exec",
	"xargs",
	"timeout",
	"nice",
	"nohup",
	"watch",
	"flock",
	"setsid",
	"unshare",
	"stdbuf",
	"script",
	"chroot",
	"sudo",
	"doas",
	"su",
	"ssh",
	"osascript",
	"awk",
	"gawk",
]);

/**
 * Interpreters that execute a STRING argument only behind an eval-style flag
 * (`node -e`, `python -c`, `perl -pe`, `php -r`). Without the flag they run a script
 * FILE, and a quoted argument is ordinary data (`node server.js --config "notes: never
 * rm -rf / on prod"`), so counting the bare name re-created the terminal prose false
 * positive. Their SCRIPT slot -- the first operand that is not an option -- arms them
 * too, because a substitution written there is what gets run (`python3 <(echo
 * 'rm -rf /')` carries no `-c`). `find` is flag-gated as well but is deliberately NOT
 * here: it runs nothing positionally, so it has no script slot to arm. Shells stay in
 * the unconditional set above: they execute strings through too many channels to gate
 * on one flag -- `bash <(echo 'rm -rf /')` -- and a shell name in a run is a far
 * stronger execution signal than a script interpreter's.
 */
const SCRIPT_ARGUMENT_HEADS = new Set(["node", "bun", "deno", "perl", "ruby", "php"]);
const PYTHON_HEAD = /^python[0-9.]*$/;

/**
 * The sourcing builtins execute a file's contents in the current shell, exactly like
 * `bash <(...)` -- but ONLY from command position, or behind a `BUILTIN_RUNNERS` prefix
 * (`command source x`). They are builtins, so no exec wrapper can run them (`sudo source
 * x` fails), and both spellings are common ordinary words elsewhere in a run (`find .
 * -name ...`, a literal `source` operand), so matching them anywhere would re-create the
 * prose false positive.
 */
const SOURCING_HEADS = new Set(["source", "."]);

/**
 * The wrappers that run a shell builtin, in the current shell: `command alias x=...`,
 * `builtin export X=...` and `command source x` do exactly what the bare builtin does. No
 * exec wrapper (`sudo`, `env`, `nohup`) can run a builtin, so only these two links are
 * followed to a declaring or sourcing builtin.
 */
const BUILTIN_RUNNERS = new Set(["command", "builtin"]);

/**
 * The index of the builtin a run's command chain (`executableCommandIndexes`) runs: its
 * command, or the first link behind a `BUILTIN_RUNNERS` prefix. Undefined when the chain
 * ends on a runner that runs nothing (`command -v source`, a bare `builtin`).
 */
function builtinIndex(chain: readonly number[], argv: readonly string[]): number | undefined {
	return chain.find((index) => !BUILTIN_RUNNERS.has(headBase(argv[index])));
}

/**
 * A token that carries a live substitution (`$(...)`, `<(...)`, `>(...)`, backticks).
 * In a script interpreter's SCRIPT slot this stands in for the eval flag: `python3
 * <(echo 'rm -rf /')` runs the substitution's output as its script, so the run executes
 * even though no `-c` appears. A single-quoted lookalike does not match -- the
 * tokenizer replaces a quote-suppressed `$` with `EXPANSION_SUPPRESSED` in the
 * assembled token -- while a double-quoted `"$(...)"` keeps its `$(` and genuinely
 * executes, so matching it is correct.
 */
const CARRIES_SUBSTITUTION = /\$\(|<\(|>\(|`/;

/**
 * A word carrying a PROCESS substitution, the only spelling whose parenthesized command
 * can be the interpreter a run feeds (see `processSubstitutionsRunInterpreter`, which reads
 * the body's commands). Matched on the word text, it vetoes the awk sink exemption
 * whatever the body runs, the fail-closed direction. A command substitution is excluded:
 * `$(...)` splices TEXT into the run, so `find $(which node)` hands a path to find rather
 * than piping anything into node. Behind a pipe its body does read the pipe (`cat $(sh)`),
 * which the pipe-chain walk reads from the body's commands (`substitutionsReadPipe`).
 */
const PROCESS_SUBSTITUTION = /<\(|>\(/;

/** `node`/`bun`/`deno`: `-e`/`--eval` evaluate a string, `-p`/`--print` evaluate and print. */
const NODE_EVAL_FLAG = /^(-e|--eval|-p|--print)$/;

/**
 * `perl`/`ruby`: `-e`/`-E` plus their cluster idioms (`-ne`, `-pe`, `-lne`) -- at most
 * two letters before the `e`, so an ordinary long-ish word flag does not arm. `-p`
 * alone is not here: `perl -p file` runs a script FILE, and only the `e` in the cluster
 * brings inline code.
 */
const PERL_EVAL_FLAG = /^-[A-Za-z]{0,2}[eE]$/;

/**
 * The eval-style flag that arms each flag-gated head, keyed by the head itself. One
 * SHARED flag set armed the wrong interpreters, because the same letter means different
 * things to each: `-r` is inline code to php but "preload a module" to node and ruby, so
 * the everyday `node -r dotenv/config app.js --message "<prose>"` re-read its message as
 * a command and terminally denied it -- the exact false positive this module exists to
 * stop.
 *
 * A miss errs in the safe direction -- an unlisted spelling, or an ATTACHED payload like
 * `perl -e'code'` whose flag and code fuse into one token, suppresses toward the judge,
 * which is the recoverable miss the module doc accepts.
 */
const EVAL_FLAG_BY_HEAD = new Map<string, RegExp>([
	["node", NODE_EVAL_FLAG],
	["bun", NODE_EVAL_FLAG],
	["deno", NODE_EVAL_FLAG],
	["perl", PERL_EVAL_FLAG],
	["ruby", PERL_EVAL_FLAG],
	["php", /^-[rRBE]$/],
]);

/** `python -c '<code>'` is the only spelling that takes inline code. */
const PYTHON_EVAL_FLAG = /^-c$/;

/**
 * A shell's inline-code flag, in the spellings a wrapper chain uses: `-c`, and the
 * login/interactive clusters (`-lc`, `-ic`). Only ever read from the token DIRECTLY
 * behind an interpreter name, so an unrelated `-c` on the run's own head (`grep -c
 * bash '<prose>'`) is not mistaken for one.
 */
const SHELL_EVAL_FLAG = /^(-[A-Za-z]*c[A-Za-z]*|--command)$/;

/**
 * What may precede an unquoted `=` for the word to be an ASSIGNMENT whose value can
 * execute: a shell variable (`VAR='cmd'`; expanding it later runs the command) or a
 * dotted config key (`git -c alias.nuke='!rm -rf /'`, `ssh -o ProxyCommand='...'`).
 * A long option (`curl --data-raw='rm -rf /'`) also puts an unquoted `=` before the
 * quote, but its value is data to the receiving tool, and treating every `--flag=`
 * value as executable re-created the terminal prose false positive this module is
 * drawing the boundary against -- so the name shape, not the `=` alone, is the gate.
 * The exotic flags whose value truly executes (`git clone --upload-pack='...'`) fall
 * to the judge, which still reads the full command.
 */
const ASSIGNMENT_NAME = /^[A-Za-z_][A-Za-z0-9_.]*$/;

/** A whole word that LOOKS like an assignment (`VAR=...`), for the position check below. */
const ASSIGNMENT_WORD = /^[A-Za-z_][A-Za-z0-9_.]*=/;

/**
 * The word text before an assignment's `=`: the shell variable it sets, with an optional array
 * subscript (`arr[i]`) and `+` marking an append.
 */
const ASSIGNED_NAME = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?$/;

/**
 * A parameter expansion that yields the variable's value (`$x`, `${x}`, `${x:-...}`,
 * `${arr[i]}`), capturing its name in group 1 or 2. `${x:+word}` and `${x+word}` are not one:
 * they yield `word`, never the value.
 */
const VALUE_EXPANSION = String.raw`\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_]|(?:\[[^\]]*\])?:?\+))`;

/** Every `VALUE_EXPANSION` in a word. */
const VALUE_EXPANSIONS = new RegExp(VALUE_EXPANSION, "g");

/**
 * Builtins that take assignments as their operands, so the words behind them are an
 * assignment prefix like a bare `VAR='cmd'`: `export X='rm -rf ~'` stores the same
 * command the bare spelling does (and propagates it to subshells), and `alias` is the
 * shell's own version of the `git config alias.*` attack already covered above. Only
 * from command position, or behind a `BUILTIN_RUNNERS` prefix (`command alias x=...`) --
 * they are builtins, and `alias` is an ordinary word elsewhere.
 * A flag between the head and the assignment (`declare -x X='cmd'`) breaks the prefix
 * and suppresses toward the judge, the recoverable direction.
 */
const ASSIGNMENT_PREFIX_HEADS = new Set(["export", "declare", "typeset", "readonly", "local", "alias"]);

/**
 * A dotted `section.key` word, the two-argument `git config` spelling of the alias
 * attack: `git config alias.nuke '!rm -rf /'` stores the same shell alias `-c` sets
 * inline, with no `=` in the shell text at all. A quoted value directly behind such a
 * key, in a run headed by `git` that carries a `config` word, is an executable
 * assignment value like any other. All three conditions are required -- a dotted
 * previous word alone is usually a FILENAME (`node server.js "notes ..."`), and
 * treating that as executable would re-create the prose false positive.
 */
const DOTTED_CONFIG_KEY = /^[A-Za-z_][-A-Za-z0-9_]*(\.[-A-Za-z0-9_.]+)+$/;

/** A token reduced to the name a head set is matched on: lowercased, leading `!`
 * stripped (a git shell-alias body), compared by basename -- as `isHead` in argv-deny.ts. */
export function headBase(token: string): string {
	const bare = token.toLowerCase().replace(/^!+/, "");
	return bare.slice(bare.lastIndexOf("/") + 1);
}

/** What a brace group's content gives as a sequence expression (see `braceSequence`). */
type BraceSequence = { kind: "terms"; terms: string[] } | { kind: "literal" } | { kind: "too-large" };

const BRACE_SEQUENCE = /^(?:([-+]?\d+)\.\.([-+]?\d+)|([A-Za-z])\.\.([A-Za-z]))(?:\.\.([-+]?\d+))?$/;
const ZERO_PADDED = /^[-+]?0\d/;

/**
 * What the content of a brace group gives as a sequence expression (`{1..10}`, `{a..e..2}`,
 * `{01..10}`): its terms in order, `literal` when it is not one -- bash then keeps the braces
 * as text -- or `too-large` when listing its terms would cost more than `limit`, each costing
 * its length plus one.
 *
 * Read as bash 5 reads it: both ends integers or both single letters (a letter range runs
 * through the characters between, so `{Z..a}` yields `[`, `\` and the rest), the increment's
 * sign ignored and a zero increment read as one, and an integer end written with a leading
 * zero padding every term to the wider end's width. The numbers are 64-bit, as bash parses them
 * with `strtoimax`: an end or increment outside that range, or an increment whose magnitude is,
 * leaves the group literal, while any within it counts (`{r..r..10000000000000000}` is `r`).
 */
function braceSequence(content: string, limit: number): BraceSequence {
	const match = BRACE_SEQUENCE.exec(content);
	if (match === null) return { kind: "literal" };
	const numeric = match[1] !== undefined;
	const [first, last] = numeric ? [match[1], match[2]] : [match[3], match[4]];
	const start = numeric ? BigInt(first) : BigInt(first.charCodeAt(0));
	const end = numeric ? BigInt(last) : BigInt(last.charCodeAt(0));
	const increment = BigInt(match[5] ?? "1");
	const magnitude = (increment < 0n ? -increment : increment) || 1n;
	if (!inInt64(start) || !inInt64(end) || !inInt64(increment) || !inInt64(magnitude)) return { kind: "literal" };
	const count = (start <= end ? end - start : start - end) / magnitude + 1n;
	const width =
		numeric && (ZERO_PADDED.test(first) || ZERO_PADDED.test(last)) ? Math.max(first.length, last.length) : 0;
	const longest = numeric ? Math.max(width, String(start).length, String(end).length) : 1;
	if (count * BigInt(longest + 1) > BigInt(Math.max(limit, 0))) return { kind: "too-large" };
	const step = start <= end ? magnitude : -magnitude;
	const terms: string[] = [];
	for (let k = 0n, value = start; k < count; k++, value += step) {
		if (!numeric) terms.push(String.fromCharCode(Number(value)));
		else if (value < 0n) terms.push(`-${String(-value).padStart(width - 1, "0")}`);
		else terms.push(String(value).padStart(width, "0"));
	}
	return { kind: "terms", terms };
}

/** Whether `value` fits bash's 64-bit integers. */
function inInt64(value: bigint): boolean {
	return value >= -(2n ** 63n) && value <= 2n ** 63n - 1n;
}

/**
 * What every term of a sequence expression starts with, from its content (`1..9`, `a..z`), or
 * null when the content is not one bash expands (see `braceSequence`): a digit, a digit or a
 * minus sign when an end is negative, or a letter -- or a character between `Z` and `a` for a
 * range across them.
 */
export function braceSequenceStart(content: string): "digit" | "signed-digit" | "letter" | null {
	const match = BRACE_SEQUENCE.exec(content);
	if (match === null || braceSequence(content, 0).kind === "literal") return null;
	if (match[1] === undefined) return "letter";
	return Number(match[1]) < 0 || Number(match[2]) < 0 ? "signed-digit" : "digit";
}

/** A character a numeric sequence's terms can hold. */
const NUMERIC_TERM_CHARACTER = /[\d-]/;

/** How much of one sequence `staticWordMatches` lists (`braceSequence`); a longer one is kept as text. */
const MAX_SEQUENCE_COST = 65_536;

/** Brace nesting deeper than this is treated as matching any name. */
const MAX_BRACE_DEPTH = 64;

/**
 * Whether any brace expansion of `text` names `name`: lowercased, leading `!`s stripped,
 * compared by basename (as `headBase`). Braces pair innermost-first; a group with a
 * top-level comma or a `a..b[..n]` sequence expands, and any other group or unpaired
 * brace is literal text.
 *
 * The expansions are never enumerated -- a word with dozens of groups has more of them
 * than can be listed. Instead the word is run through a small automaton for the accepted
 * shape (`.../<name>`, or `!*<name>` with no slash), carrying the SET of automaton states
 * reachable after each piece of text: a group maps its input set through every
 * alternative and unions the results. The cost is linear in the word's length. A numeric
 * sequence against a name with no digit or `-` is not even walked: each of its terms breaks
 * every partial match, leaving only the always-live state, however many terms it has.
 */
export function staticWordMatches(text: string, name: string): boolean {
	if (!text.includes("{")) return headBase(text) === name;
	const pairs = new Map<number, number>();
	const open: number[] = [];
	for (let i = 0; i < text.length; i++) {
		if (text[i] === "{") open.push(i);
		else if (text[i] === "}" && open.length > 0) pairs.set(open.pop() as number, i);
	}

	// States 0..m+1 track a `/<name>` suffix (0 is the always-live "anything so far");
	// states m+2..2m+2 track the whole word as `!*<name>`, m+2 being "only `!`s so far".
	const m = name.length;
	const slashDone = m + 1;
	const bareStart = m + 2;
	const bareDone = bareStart + m;
	const step = (states: Set<number>, c: string): Set<number> => {
		const next = new Set<number>([0]);
		for (const state of states) {
			if (state === 0) {
				if (c === "/") next.add(1);
			} else if (state < slashDone) {
				if (c === name[state - 1]) next.add(state + 1);
			} else if (state === bareStart) {
				if (c === "!") next.add(bareStart);
				if (c === name[0]) next.add(bareStart + 1);
			} else if (state > bareStart && state < bareDone) {
				if (c === name[state - bareStart]) next.add(state + 1);
			}
		}
		return next;
	};

	let tooDeep = false;
	const feedLiteral = (states: Set<number>, literal: string): Set<number> => {
		let current = states;
		for (const c of literal.toLowerCase()) current = step(current, c);
		return current;
	};
	const feedRange = (states: Set<number>, start: number, end: number, depth: number): Set<number> => {
		let current = states;
		let i = start;
		while (i < end) {
			const close = pairs.get(i);
			if (close === undefined) {
				current = feedLiteral(current, text[i]);
				i += 1;
				continue;
			}
			current = feedGroup(current, i, close, depth + 1);
			i = close + 1;
		}
		return current;
	};
	const feedGroup = (states: Set<number>, openAt: number, closeAt: number, depth: number): Set<number> => {
		if (depth > MAX_BRACE_DEPTH) {
			tooDeep = true;
			return states;
		}
		const commas: number[] = [];
		for (let i = openAt + 1; i < closeAt; i++) {
			const close = pairs.get(i);
			if (close !== undefined) i = close;
			else if (text[i] === ",") commas.push(i);
		}
		const union = new Set<number>();
		if (commas.length > 0) {
			let from = openAt + 1;
			for (const to of [...commas, closeAt]) {
				for (const state of feedRange(states, from, to, depth)) union.add(state);
				from = to + 1;
			}
			return union;
		}
		const content = text.slice(openAt + 1, closeAt);
		const start = braceSequenceStart(content);
		if ((start === "digit" || start === "signed-digit") && !NUMERIC_TERM_CHARACTER.test(name)) return new Set([0]);
		const sequence = braceSequence(content, MAX_SEQUENCE_COST);
		if (sequence.kind !== "terms") {
			const inner = feedRange(step(states, "{"), openAt + 1, closeAt, depth);
			return step(inner, "}");
		}
		for (const alternative of sequence.terms) for (const state of feedLiteral(states, alternative)) union.add(state);
		return union;
	};

	const final = feedRange(new Set([0, bareStart]), 0, text.length, 0);
	return tooDeep || final.has(slashDone) || final.has(bareDone);
}

/**
 * The words a word's brace expansions give, in the order bash emits them, or `too-large` when
 * listing them would cost more than a budget, with the listing work `cost` spent either way
 * (see `expandBraces`).
 */
export type BraceWords = { kind: "words"; words: string[]; cost: number } | { kind: "too-large"; cost: number };

/** Alternatives nested deeper than this make `expandBraces` give up. */
const MAX_EXPANSION_DEPTH = 1024;

/** The scanning `expandBraces` may do per character of its word before it gives up. */
const BRACE_SCAN_WORK_PER_CHARACTER = 16;

/**
 * The end of the expansion span a word's spelling opens at `at` -- a command, process or
 * arithmetic substitution, a `${...}` parameter expansion or a backtick substitution -- or
 * `at` itself when none starts there. Brace expansion passes these through whole: the braces
 * and commas inside them are theirs, not a brace group's (`{$(echo a,b),c}` is two words).
 */
function expansionSpanEnd(word: string, at: number): number {
	const c = word[at];
	const next = word[at + 1];
	if ((c === "$" || c === "<" || c === ">") && next === "(") return readSubstitution(word, at).end;
	if (c === "$" && next === "{") return readBraced(word, at).end;
	if (c === "`") return readBackticks(word, at).end;
	return at;
}

/**
 * The words bash's brace expansion turns `word` into, as a word's spelling in a run spells it:
 * a quoted or escaped `{`, `}` or `,` is `EXPANSION_SUPPRESSED` there, so every brace and comma
 * left is live, and a backslash is a literal character.
 *
 * Read the way bash's `brace_expand` reads it. The group that expands is the first `{` with a
 * matching `}`: nested braces counted, and a `}` at the group's own level matching only once a
 * comma, or a `..` not directly before a `}`, has appeared at that level -- so `x{},/}` is `x}`
 * and `x/`, while `{a}` and `{x{b,c}}`'s outer braces stay text. A group whose content holds a
 * comma anywhere splits at its own commas, each alternative itself expanded; any other is read
 * as a sequence expression (`braceSequence`), and kept as text when it is not one
 * (`{a..9}`). The text before the group is kept, and each alternative is followed by every
 * expansion of the text after it. Words the expansion leaves empty are dropped, as bash drops
 * an unquoted null word (`{,}` gives none).
 *
 * Approximations, all in the direction of reading more words: a quoted `.` is spelled as
 * itself, so `{"1..3"}` reads as the sequence bash keeps as text; a word whose only other text
 * is empty quotes (`''{,}`) loses the empty words bash keeps; and bash's exemption of a `{`
 * that starts the word and is followed by `}` (`{},x}` stays text) is not applied, since the
 * spelling cannot tell that `{` from one behind empty quotes (`''{},x}`), which bash expands.
 * A quoted or escaped backtick, and a `(` escaped behind a `$`, are spelled as themselves too,
 * so a span that looks like a substitution may be text (`{\`,/,\`}` is three words, one of them
 * `/`): when a span holds a brace or comma, the word is also read with no span passed through,
 * and the words of both readings are listed.
 *
 * `limit` bounds the listing work: every list of two or more words built on the way -- a
 * product, a group's alternatives, a sequence's terms -- costs the length of its words plus one
 * each, so a product of groups (`{a,b}{a,b}...`) cannot be listed past it. Beyond it, past
 * `MAX_EXPANSION_DEPTH` nested alternatives, or past `BRACE_SCAN_WORK_PER_CHARACTER` steps of
 * scanning per character (unmatched braces make the scan quadratic), the result is
 * `too-large`. The work spent is reported either way, so a caller sharing one budget across
 * words charges a failed listing too. A word with no group that expands comes back as itself.
 */
export function expandBraces(word: string, limit: number): BraceWords {
	const expanded = braceReadings(word, limit);
	if (expanded.kind === "too-large") return expanded;
	const [first, second] = expanded.readings;
	const words = second === undefined || sameWords(first, second) ? first : [...first, ...second];
	return { kind: "words", words, cost: expanded.cost };
}

/**
 * The readings `expandBraces` lists for a word, each on its own: the one with every span passed
 * through whole, and, when a span holds a brace or comma, the one with none passed through. A
 * caller that counts a reading's words (a redirection is ambiguous past one) must count each
 * reading apart, since their union repeats the words both give.
 */
export type BraceReadings =
	| { kind: "readings"; readings: string[][]; cost: number }
	| { kind: "too-large"; cost: number };

/** The readings of `word` (`BraceReadings`), each with its empty words dropped, bounded as `expandBraces` is. */
export function braceReadings(word: string, limit: number): BraceReadings {
	if (!word.includes("{") || !word.includes("}")) return { kind: "readings", readings: [[word]], cost: 0 };
	const spans = new Map<number, number>();
	let spanHidesBraces = false;
	for (let i = 0; i < word.length; ) {
		const end = expansionSpanEnd(word, i);
		if (end > i) {
			spans.set(i, end);
			spanHidesBraces ||= /[{},]/.test(word.slice(i, end));
		}
		i = Math.max(end, i + 1);
	}
	const listed = listBraceWords(word, limit, spans);
	let cost = listed.spent;
	if (listed.words === null) return { kind: "too-large", cost };
	const readings = [listed.words];
	if (spanHidesBraces) {
		const unspanned = listBraceWords(word, limit - cost, new Map());
		cost += unspanned.spent;
		if (unspanned.words === null) return { kind: "too-large", cost };
		readings.push(unspanned.words);
	}
	const kept = readings.map((reading) =>
		reading.length === 1 && reading[0] === word ? reading : reading.filter((w) => w.length > 0),
	);
	return { kind: "readings", readings: kept, cost };
}

function sameWords(a: string[], b: string[]): boolean {
	return a.length === b.length && a.every((word, k) => word === b[k]);
}

/**
 * The words `expandBraces` lists for `word` with `spans` passed through whole, empty ones
 * included, or null when that is too large, with the listing work spent (see `expandBraces` for
 * the bounds).
 */
function listBraceWords(
	word: string,
	limit: number,
	spans: ReadonlyMap<number, number>,
): { words: string[] | null; spent: number } {
	let work = BRACE_SCAN_WORK_PER_CHARACTER * word.length;
	let spent = 0;
	/** Charges a list about to be built to the listing work, and says whether it still fits. */
	const spend = (count: number, length: number): boolean => {
		if (count <= 1) return true;
		spent += count + length;
		return spent <= limit;
	};
	// A group matches only behind a `,` or `..` inside it, so none matches past the last one
	// before the end of the text being read: `separatorBefore[i]` is the last one before `i`.
	const separatorBefore = new Int32Array(word.length + 1);
	separatorBefore[0] = -1;
	for (let i = 0; i < word.length; i++)
		separatorBefore[i + 1] = word[i] === "," || (word[i] === "." && word[i + 1] === ".") ? i : separatorBefore[i];
	const tooLarge = Symbol();

	/**
	 * The `}` matching the `{` at `open`, or null when it has none before `to`. A `}` at the
	 * group's own level matches only behind a comma or a `..` (not directly before a `}`) there.
	 */
	const matchClose = (open: number, to: number): number | null | typeof tooLarge => {
		let level = 0;
		let separated = false;
		const lastSeparator = separatorBefore[to];
		for (let j = open + 1; j < to; j++) {
			if (!separated && j > lastSeparator) return null;
			if (--work < 0) return tooLarge;
			const spanEnd = spans.get(j);
			if (spanEnd !== undefined) {
				j = spanEnd - 1;
				continue;
			}
			const c = word[j];
			if (c === "{") level += 1;
			else if (c === "}") {
				if (level > 0) level -= 1;
				else if (separated) return j;
			} else if (level === 0 && (c === "," || (c === "." && word[j + 1] === "." && word[j + 2] !== "}")))
				separated = true;
		}
		return null;
	};
	/** The alternatives between `open` and `close`, split at the group's own commas. */
	const splitAlternatives = (open: number, close: number): [number, number][] => {
		const parts: [number, number][] = [];
		let level = 0;
		let start = open + 1;
		for (let j = open + 1; j < close; j++) {
			const spanEnd = spans.get(j);
			if (spanEnd !== undefined) {
				j = spanEnd - 1;
				continue;
			}
			const c = word[j];
			if (c === "{") level += 1;
			else if (c === "}" && level > 0) level -= 1;
			else if (c === "," && level === 0) {
				parts.push([start, j]);
				start = j + 1;
			}
		}
		parts.push([start, close]);
		return parts;
	};
	const expandRange = (from: number, to: number, depth: number): string[] | typeof tooLarge => {
		if (depth > MAX_EXPANSION_DEPTH) return tooLarge;
		let words = [""];
		let wordsLength = 0;
		let pending = "";
		const flush = (): boolean => {
			if (pending.length === 0) return true;
			const length = wordsLength + words.length * pending.length;
			if (!spend(words.length, length)) return false;
			words = words.map((w) => w + pending);
			wordsLength = length;
			pending = "";
			return true;
		};
		let i = from;
		while (i < to) {
			let open = -1;
			let close = -1;
			for (let k = i; k < separatorBefore[to]; k++) {
				if (--work < 0) return tooLarge;
				const spanEnd = spans.get(k);
				if (spanEnd !== undefined) {
					k = spanEnd - 1;
					continue;
				}
				if (word[k] !== "{") continue;
				const match = matchClose(k, to);
				if (match === tooLarge) return tooLarge;
				if (match !== null) {
					open = k;
					close = match;
					break;
				}
			}
			if (open < 0) {
				pending += word.slice(i, to);
				break;
			}
			pending += word.slice(i, open);
			const content = word.slice(open + 1, close);
			const alternatives: string[] = [];
			let alternativesLength = 0;
			if (content.includes(",")) {
				for (const [start, end] of splitAlternatives(open, close)) {
					const part = expandRange(start, end, depth + 1);
					if (part === tooLarge) return tooLarge;
					if (
						!spend(
							part.length,
							part.reduce((total, alternative) => total + alternative.length, 0),
						)
					)
						return tooLarge;
					for (const alternative of part) {
						alternatives.push(alternative);
						alternativesLength += alternative.length;
					}
				}
			} else {
				const sequence = braceSequence(content, limit - spent);
				if (sequence.kind === "too-large") return tooLarge;
				if (sequence.kind === "literal") {
					pending += word.slice(open, close + 1);
					i = close + 1;
					continue;
				}
				for (const term of sequence.terms) {
					alternatives.push(term);
					alternativesLength += term.length;
				}
				if (!spend(alternatives.length, alternativesLength)) return tooLarge;
			}
			if (!flush()) return tooLarge;
			const count = words.length * alternatives.length;
			const length = wordsLength * alternatives.length + alternativesLength * words.length;
			if (!spend(count, length)) return tooLarge;
			const product: string[] = [];
			for (const w of words) for (const alternative of alternatives) product.push(w + alternative);
			words = product;
			wordsLength = length;
			i = close + 1;
		}
		return flush() ? words : tooLarge;
	};

	const expanded = expandRange(0, word.length, 0);
	return { words: expanded === tooLarge ? null : expanded, spent };
}

function isGitHead(token: string): boolean {
	return headBase(token) === "git";
}

/**
 * An interpreter-like head decides the run from COMMAND POSITION, where the wrappers
 * themselves sit (`sudo bash -c ...`, `timeout 5 'rm -rf /'`, `env FOO=1 sh ...`, and
 * every pipe sink: `echo 'rm -rf /' | sh`). Further along it needs the shell's own
 * inline-code flag directly behind it -- the `<wrapper> <shell> -c '<payload>'` shape,
 * which is how an interpreter reached by a wrapper that is NOT itself a head gets
 * covered (`docker run --rm img sh -c '...'`).
 *
 * Matching the name at any position instead read an ORDINARY WORD as proof of
 * execution: `bash`, `sh`, `env`, `script`, `watch`, `command` and `trap` are everyday
 * operands, so `grep bash "rm -rf /"`, `git -C env commit -m "<prose>"` and
 * `node build.js bash "<prose>"` were terminally denied on the strength of an unrelated
 * word. The old note called that over-match harmless because it "only re-reads the run's
 * quoted words" -- but re-reading the sibling operand IS the terminal false positive
 * not a no-op. What this gives up -- an interpreter handed a POSITIONAL
 * payload from behind an unlisted wrapper (`docker run img awk '<prog>'`) -- suppresses
 * toward the judge, which still reads the whole command.
 *
 * A flag-gated head needs an arming token as well, and arming is scoped BOTH ways. By
 * head: only the flags that head reads as inline code arm it (see `EVAL_FLAG_BY_HEAD`),
 * and only those collected from heads seen so far, since a flag follows its own
 * interpreter. By position: a substitution counts only in a script interpreter's own
 * script slot, the first operand that is not an option. Arming on a substitution
 * anywhere denied `find $(cat dirs.txt) -name "rm -rf /..."` and `node build.js
 * "$(git rev-parse HEAD)" "note: rm -rf / ..."` -- prose operands beside an unrelated
 * substitution, the false positive this module draws the boundary against. A flag that
 * takes a SEPARATE value can eat the slot (`node --require ./x <(payload)`), which
 * suppresses toward the judge: the recoverable direction, and the substitution body
 * still contributes its own runs regardless.
 *
 * `arming` holds at most one pattern per interpreter family, so the flag test stays
 * linear in the run's length -- the floor runs synchronously on every tool call.
 */
function shellReadsDynamicScript(argv: string[], index: number): boolean {
	for (let i = index + 1; i < argv.length; i++) {
		if (SHELL_EVAL_FLAG.test(argv[i])) return false;
		if (argv[i] === "-O" || argv[i] === "-o") {
			i += 1;
			continue;
		}
		if (argv[i].startsWith("-")) continue;
		return CARRIES_SUBSTITUTION.test(argv[i]);
	}
	return false;
}

function runsQuotedArguments(argv: string[]): boolean {
	const arming: RegExp[] = [];
	let armed = false;
	let awaitingScript = false;
	let commandIndex = 0;
	const chain = executableCommandIndexes(argv);
	const actualCommand = chain.at(-1) ?? argv.length;
	if (PIPELINE_INTERPRETER_HEADS.has(headBase(argv[actualCommand] ?? ""))) return true;
	const builtin = builtinIndex(chain, argv);
	if (builtin !== undefined && SOURCING_HEADS.has(headBase(argv[builtin]))) return true;
	for (let t = 0; t < argv.length; t++) {
		const token = argv[t];
		// Command position is the first word that actually names the command: a reserved
		// word a command may sit directly behind and a leading assignment prefix both sit
		// in front of it (`{ sh; }`, `do sh -c '...'`, `FOO=1 sh -c '...'`) without
		// displacing it. A quoted lookalike steps over one word too many, which only
		// grants command position to an operand -- over-marking, the fail-closed direction.
		if (t === commandIndex && precedesCommand(token, argv[t - 1])) commandIndex = t + 1;
		const base = headBase(token);
		if (PIPELINE_INTERPRETER_HEADS.has(base) && (t === commandIndex || SHELL_EVAL_FLAG.test(argv[t + 1] ?? "")))
			return true;
		const isPython = PYTHON_HEAD.test(base);
		const evalFlag = isPython ? PYTHON_EVAL_FLAG : EVAL_FLAG_BY_HEAD.get(base);
		if (evalFlag !== undefined) {
			if (!arming.includes(evalFlag)) arming.push(evalFlag);
			if (isPython || SCRIPT_ARGUMENT_HEADS.has(base)) awaitingScript = true;
		} else if (awaitingScript && !token.startsWith("-")) {
			awaitingScript = false;
			if (CARRIES_SUBSTITUTION.test(token)) armed = true;
		}
		if (!armed) armed = arming.some((pattern) => pattern.test(token));
	}
	return arming.length > 0 && armed;
}

/**
 * What may sit in front of a redirection character inside the SAME word: nothing, a file
 * descriptor number, `{name}`, or the `&` of `&>` -- plus an operator already in progress, so
 * the several-character forms (`<>`, `<<<`, `>|`) stay whole. Anything else means the operator
 * starts a new word: bash reads `git push>log` as `git push` with a redirect, not as a command
 * named `push>log`, so gluing them would hide the subcommand.
 */
const REDIRECT_PREFIX = /^(?:\d*|&|\{[A-Za-z_][A-Za-z0-9_]*\})[<>&|]*$/;

/** The characters a redirection operator is spelled with (`<`, `>>`, `>&`, `>|`, `&>`). */
const REDIRECTION_OPERATOR_CHARS = new Set(["<", ">", "&", "|"]);

/** A redirection operator read inside the word being scanned. */
interface RedirectionInWord {
	/** The quoted or escaped text glued in front of the operator, which bash passes as an argument. */
	gluedArgument: string | undefined;
	/** `gluedArgument` as the command receives it (see `received` in `lexSource`). */
	gluedReceived: string | undefined;
	/** How many quoted runs the word held when the operator started. */
	quotedRunsBefore: number;
}

/**
 * The end of a redirection operator that opens its target for writing (`>`, `>>`, `>|`, `>&`,
 * `&>`, `&>>`, `<>`), with or without a descriptor in front; the reading ones (`<`, `<&`, `<<`,
 * `<<<`) do not match.
 */
const WRITING_REDIRECTION_END = />[|&]?$/;

/** A here-string operator starting a word and feeding the command's standard input (`<<<`, `0<<<`). */
const STDIN_HERE_STRING = /^0?<<</;

/** A redirection operator still live in an assembled word: quoted ones arrive suppressed. */
const LIVE_REDIRECTION = /&?[<>]/;

/**
 * The text a here-string hands its reader, from the word bash expands for it: `spelled` is that
 * word as assembled and `received` the same word as the reader receives it. The received text is
 * used, since a shell reading it parses that text afresh and a quoted `~`, `$` or quote is live
 * there (`bash <<< 'rm -rf ~'` deletes the home directory, and `bash <<< 'echo "'\''$(cmd)'\''"'`
 * runs `cmd`), which the suppressed spelling would hide. A redirection glued behind the word ends
 * it; it is found in the spelling, where a quoted `<` or `>` arrives suppressed, and when the two
 * do not line up the whole received word is kept.
 */
function hereStringText(spelled: string, received: string): string {
	const end = spelled.search(LIVE_REDIRECTION);
	if (end === -1 || spelled.length !== received.length) return received;
	return received.slice(0, end);
}

/** A word ending on the bare `<<-` operator, whose delimiter is the next word; `<<<-` is a here-string of `-`. */
const TAB_STRIPPING_HEREDOC = /(?:^|[^<])<<-$/;

/**
 * The keywords that open and close a compound command, for the pipe-chain walk below.
 * A compound pipes its members' COMBINED output onward, so a separator between them
 * does not end the chain -- but only parens reach that walk as group parts, and every
 * other spelling arrives as an ordinary word in command position.
 */
const COMPOUND_CLOSERS = new Set(["}", "esac", "fi", "done"]);
const COMPOUND_OPENERS = new Set(["{", "case", "if", "for", "while", "until", "select"]);

/**
 * Reserved words a command may sit DIRECTLY behind, with only whitespace between them:
 * `if true; then sudo 'rm -rf /'; fi` and `for i in 1; do source 'x'; done` are both one
 * run, because only punctuation starts a new one here. Command position has to step over
 * them, or the wrapper and sourcing heads -- and a `VAR=`/`export` assignment prefix --
 * stop being recognized the moment they appear inside a loop or conditional body.
 */
const COMMAND_PREFIX_WORDS = new Set([
	"{",
	"!",
	"if",
	"elif",
	"then",
	"else",
	"while",
	"until",
	"do",
	"time",
	"coproc",
	"function",
]);

/** The name `coproc NAME cmd` and `function NAME { ...; }` put before the command. */
const NAMED_BEFORE_COMMAND = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Whether a word stands in FRONT of its run's command rather than being it -- a reserved
 * word, an assignment prefix (`FOO=1 sh -c '...'`), or the one extra word `time`,
 * `coproc` and `function` may carry (`time -p sudo '...'`, `coproc NAME sudo '...'`,
 * `function NAME { ...; }`), which is why this reads the word before it too. Both computations of command position go through this:
 * they were written separately, drifted on the assignment half, and a `VAR=value` prefix
 * then hid a payload from one reader while the other saw it.
 */
function precedesCommand(token: string, previous: string | undefined): boolean {
	if (COMMAND_PREFIX_WORDS.has(token) || ASSIGNMENT_WORD.test(token)) return true;
	if (previous === "time") return token === "-p" || token === "--portability";
	return previous === "function" && NAMED_BEFORE_COMMAND.test(token);
}

/** Commands whose command operand is another executable command. */
const EXEC_ARGUMENT_WRAPPERS = new Set([
	...SHELL_SOURCE_HEADS,
	...APPLET_WRAPPERS,
	"builtin",
	"chroot",
	"command",
	"doas",
	"env",
	"eval",
	"exec",
	"flock",
	"nice",
	"nohup",
	"setsid",
	"script",
	"ssh",
	"stdbuf",
	"su",
	"sudo",
	"time",
	"timeout",
	"trap",
	"unshare",
	"watch",
	"xargs",
]);
/** Wrapper options whose value is the following argv word rather than an inline suffix. */
const WRAPPER_VALUE_OPTIONS = new Map<string, ReadonlySet<string>>([
	["chroot", new Set(["--groups", "--userspec"])],
	["doas", new Set(["-C", "-u"])],
	["env", new Set(["-a", "--argv0", "-C", "--chdir", "-P", "-u", "--unset"])],
	["exec", new Set(["-a"])],
	["flock", new Set(["-E", "--conflict-exit-code", "--fd", "--length", "--start", "-w", "--timeout", "--wait"])],
	["nice", new Set(["-n", "--adjustment"])],
	[
		"script",
		new Set([
			"-B",
			"-E",
			"--echo",
			"-I",
			"--log-in",
			"--log-io",
			"--log-out",
			"--log-timing",
			"--logging-format",
			"-m",
			"-O",
			"-o",
			"--output-limit",
			"-t",
			"-T",
		]),
	],
	[
		"ssh",
		new Set([
			"-B",
			"-b",
			"-c",
			"-D",
			"-E",
			"-e",
			"-F",
			"-I",
			"-i",
			"-J",
			"-L",
			"-l",
			"-m",
			"-O",
			"-o",
			"-P",
			"-p",
			"-Q",
			"-R",
			"-S",
			"-W",
			"-w",
		]),
	],
	["stdbuf", new Set(["-e", "--error", "-i", "--input", "-o", "--output"])],
	[
		"sudo",
		new Set([
			"-a",
			"--auth-type",
			"-c",
			"-C",
			"--close-from",
			"-D",
			"--chdir",
			"--chroot",
			"-g",
			"--group",
			"-h",
			"--host",
			"--login-class",
			"-p",
			"--prompt",
			"-R",
			"-r",
			"--role",
			"-t",
			"-T",
			"--command-timeout",
			"--type",
			"-U",
			"--other-user",
			"-u",
			"--user",
		]),
	],
	["time", new Set(["-f", "--format", "-o", "--output-file"])],
	["timeout", new Set(["-k", "--kill-after", "-s", "--signal"])],
	[
		"unshare",
		new Set([
			"--boottime",
			"-G",
			"--load-interp",
			"--map-group",
			"--map-groups",
			"--map-user",
			"--map-users",
			"--monotonic",
			"--owner",
			"--propagation",
			"-R",
			"--root",
			"-S",
			"--setgid",
			"--setgroups",
			"--setuid",
			"-w",
			"--wd",
			"--whitelist-env",
		]),
	],
	["watch", new Set(["-q", "--equexit", "-n", "--interval", "-s", "--shotsdir"])],
	[
		"xargs",
		new Set([
			"-a",
			"--arg-file",
			"-d",
			"--delimiter",
			"-E",
			"-I",
			"-J",
			"-L",
			"-n",
			"-P",
			"-R",
			"-S",
			"-s",
			"--max-args",
			"--max-chars",
			"--max-procs",
			"--process-slot-var",
		]),
	],
]);
/**
 * The long options of the getopt_long wrappers other than their value options above, so an
 * abbreviation can be resolved against the whole set: getopt_long takes any prefix that names
 * only one long option (`env --uns` for `--unset`). An option whose value is optional is listed
 * here, since getopt_long takes its value only attached with `=` (`xargs --replace=R`), never
 * from the next word.
 */
const WRAPPER_OTHER_LONG_OPTIONS = new Map<string, readonly string[]>([
	["chroot", ["help", "skip-chdir", "version"]],
	[
		"env",
		[
			"block-signal",
			"debug",
			"default-signal",
			"help",
			"ignore-environment",
			"ignore-signal",
			"list-signal-handling",
			"null",
			"split-string",
			"version",
		],
	],
	[
		"flock",
		["close", "exclusive", "fcntl", "help", "nb", "no-fork", "nonblocking", "shared", "unlock", "verbose", "version"],
	],
	["nice", ["help", "version"]],
	["script", ["append", "command", "flush", "force", "help", "quiet", "return", "timing", "version"]],
	["stdbuf", ["help", "version"]],
	[
		"su",
		[
			"command",
			"fast",
			"group",
			"help",
			"login",
			"no-pty",
			"preserve-environment",
			"pty",
			"session-command",
			"shell",
			"supp-group",
			"user",
			"version",
			"whitelist-environment",
		],
	],
	[
		"sudo",
		[
			"askpass",
			"background",
			"bell",
			"edit",
			"help",
			"list",
			"login",
			"no-update",
			"non-interactive",
			"preserve-env",
			"preserve-groups",
			"remove-timestamp",
			"reset-timestamp",
			"set-home",
			"shell",
			"stdin",
			"validate",
			"version",
		],
	],
	["time", ["append", "help", "portability", "quiet", "verbose", "version"]],
	["timeout", ["foreground", "help", "preserve-status", "verbose", "version"]],
	[
		"unshare",
		[
			"cgroup",
			"clear-env",
			"fork",
			"forward-signals",
			"help",
			"ipc",
			"keep-caps",
			"kill-child",
			"map-auto",
			"map-current-user",
			"map-root-user",
			"map-subids",
			"mount",
			"mount-binfmt",
			"mount-proc",
			"net",
			"pid",
			"time",
			"user",
			"uts",
			"version",
		],
	],
	[
		"watch",
		[
			"beep",
			"chgexit",
			"color",
			"differences",
			"errexit",
			"exec",
			"follow",
			"help",
			"no-color",
			"no-rerun",
			"no-title",
			"no-wrap",
			"precise",
			"version",
		],
	],
	[
		"xargs",
		[
			"eof",
			"exit",
			"help",
			"interactive",
			"max-lines",
			"no-run-if-empty",
			"null",
			"open-tty",
			"replace",
			"show-limits",
			"verbose",
			"version",
		],
	],
]);
/** Every long option of each getopt_long wrapper, by name without its leading `--`. */
const WRAPPER_LONG_OPTIONS = new Map<string, readonly string[]>(
	[...WRAPPER_OTHER_LONG_OPTIONS].map(([base, others]) => [
		base,
		[
			...[...(WRAPPER_VALUE_OPTIONS.get(base) ?? [])]
				.filter((option) => option.startsWith("--"))
				.map((option) => option.slice(2)),
			...others,
		],
	]),
);
const SHELL_SOURCE_CARRIERS = new Set([
	...SHELL_SOURCE_HEADS,
	"env",
	"eval",
	"find",
	"flock",
	"git",
	"script",
	"ssh",
	"su",
	"trap",
	"watch",
]);
const AWK_HEADS = new Set(["awk", "gawk"]);
const PIPELINE_INTERPRETER_HEADS = new Set([...AWK_HEADS, ...SHELL_HEADS, "eval", "osascript", "trap"]);
const COMMAND_STRING_OPTIONS: ReadonlySet<string> = new Set(["-c", "--command"]);
/** util-linux su runs the `--session-command` value as it runs a `-c` one. */
const SU_COMMAND_STRING_OPTIONS: ReadonlySet<string> = new Set([...COMMAND_STRING_OPTIONS, "--session-command"]);

/** The options whose value the wrapper `base` runs as a shell command string. */
function commandStringOptions(base: string): ReadonlySet<string> {
	return base === "su" ? SU_COMMAND_STRING_OPTIONS : COMMAND_STRING_OPTIONS;
}
const TERMINATING_WRAPPER_OPTIONS = new Map<string, ReadonlySet<string>>([
	["command", new Set(["-v", "-V", "--help", "--version"])],
	["env", new Set(["--help", "--version"])],
	["sudo", new Set(["-e", "--edit", "-h", "--help", "-K", "-l", "--list", "-V", "--version", "-v", "--validate"])],
	["time", new Set(["--help", "--version"])],
	["xargs", new Set(["--help", "--version"])],
]);

function commandPositionIndex(argv: string[]): number {
	let index = 0;
	while (index < argv.length) {
		if (precedesCommand(argv[index], argv[index - 1])) {
			index += 1;
			continue;
		}
		if (
			argv[index - 1] === "coproc" &&
			NAMED_BEFORE_COMMAND.test(argv[index]) &&
			COMPOUND_OPENERS.has(argv[index + 1] ?? "")
		) {
			index += 1;
			continue;
		}
		break;
	}
	return index;
}

/**
 * The long options among `options` a `--name` word can stand for: the one it names exactly,
 * else every one it is a prefix of. getopt_long reads the word as an option only when this is
 * a single name, and rejects it otherwise.
 */
function longOptionCandidates(options: readonly string[], name: string): string[] {
	return options.includes(name) ? [name] : options.filter((option) => option.startsWith(name));
}

/**
 * `token` as the wrapper `base` reads it: a `--name` or `--name=value` word naming exactly one
 * of its long options, by prefix or in full, spelled out in full (`env --uns` is `--unset`);
 * any other word, an ambiguous or unknown long option included, as written. The tool refuses to
 * run on an ambiguous or unknown long option, so reading one as a flag hides no command.
 */
function spelledWrapperOption(base: string, token: string): string {
	const options = WRAPPER_LONG_OPTIONS.get(base);
	const long = /^--([^=]+)(=[\s\S]*)?$/.exec(token);
	if (options === undefined || long === null) return token;
	const named = longOptionCandidates(options, long[1]);
	return named.length === 1 ? `--${named[0]}${long[2] ?? ""}` : token;
}

/**
 * Whether `token` is one of `base`'s options that takes the next word as its value (`-u`,
 * `--unset`, or an abbreviation like `--uns`). A long option prefix of several options that
 * all take a value counts too: whichever of them the tool knows, it takes the next word.
 * A `-xyz` cluster is read as getopt reads it, letter by letter until one that takes a value:
 * it takes the next word when that letter ends the word (`sudo -nu root`), and none when the
 * value follows it in the word (`sudo -nuroot`).
 */
function takesWrapperValue(base: string, token: string): boolean {
	const values = WRAPPER_VALUE_OPTIONS.get(base);
	if (values === undefined) return false;
	if (values.has(token)) return true;
	if (/^-[^-]/.test(token)) {
		for (let i = 1; i < token.length; i++) {
			if (values.has(`-${token[i]}`)) return i === token.length - 1;
		}
		return false;
	}
	const options = WRAPPER_LONG_OPTIONS.get(base);
	const long = /^--([^=]+)$/.exec(token);
	if (options === undefined || long === null) return false;
	const named = longOptionCandidates(options, long[1]);
	return named.length > 0 && named.every((name) => values.has(`--${name}`));
}

/**
 * Whether `token` is an `xargs --max-lines` (or an abbreviation) whose count is the number
 * `next`. GNU xargs takes the count only attached (`--max-lines=2`), reading the next word as the
 * command, but uutils xargs takes it from the next word. A number names no command in either
 * reading, so it is read as the count, and the word after it as the command.
 */
function takesXargsLineCount(base: string, token: string, next: string | undefined): boolean {
	return base === "xargs" && spelledWrapperOption(base, token) === "--max-lines" && /^\d+$/.test(next ?? "");
}

/**
 * Whether `token` puts the wrapper `base` in a mode that runs no command (`sudo -l`,
 * `command -v`). A sudo cluster is list mode only when its `l` comes before any value letter:
 * `sudo -nl` lists, but `sudo -pl` is `-p l` and `sudo -ulinus` is `-u linus`.
 */
function terminatesWrapper(base: string, token: string): boolean {
	if (TERMINATING_WRAPPER_OPTIONS.get(base)?.has(spelledWrapperOption(base, token))) return true;
	if (base === "command") return /^-[A-Za-z]*[vV][A-Za-z]*$/.test(token);
	if (base !== "sudo" || !/^-[A-Za-z]+$/.test(token)) return false;
	const values = WRAPPER_VALUE_OPTIONS.get("sudo");
	for (let i = 1; i < token.length; i++) {
		if (token[i] === "l") return true;
		if (values?.has(`-${token[i]}`)) return false;
	}
	return false;
}

function optionCommandTarget(argv: string[], index: number, flags: ReadonlySet<string>): number {
	const base = headBase(argv[index]);
	for (let i = index + 1; i < argv.length; i++) {
		if (flags.has(spelledWrapperOption(base, argv[i]))) return i + 1;
	}
	return argv.length;
}

function splitEnvString(source: string): string[] {
	const words: string[] = [];
	let word = "";
	let quote = "";
	let started = false;
	for (let i = 0; i < source.length; i++) {
		const c = source[i];
		if (quote.length === 0 && (c === " " || c === "\t" || c === "\n")) {
			if (started) words.push(word);
			word = "";
			started = false;
			continue;
		}
		if (c === "'" && quote !== '"') {
			quote = quote === "'" ? "" : "'";
			started = true;
			continue;
		}
		if (c === '"' && quote !== "'") {
			quote = quote === '"' ? "" : '"';
			started = true;
			continue;
		}
		if (c === "\\" && quote !== "'" && i + 1 < source.length) {
			const next = source[++i];
			if (next === "c") break;
			if (next === "_") {
				if (quote === '"') word += " ";
				else if (started) {
					words.push(word);
					word = "";
					started = false;
				}
				continue;
			}
			word += next;
			started = true;
			continue;
		}
		if (c === "#" && quote.length === 0 && !started) break;
		word += c;
		started = true;
	}
	if (started) words.push(word);
	return words;
}

function shellQuote(word: string): string {
	return `'${word.replaceAll("'", `'\\''`)}'`;
}

function envSplitShellSource(source: string): string {
	return splitEnvString(source).map(shellQuote).join(" ");
}

function assignmentOnly(source: string): boolean {
	const words = splitEnvString(source);
	return words.length === 0 || words.every((word) => ASSIGNMENT_WORD.test(word));
}

/** The short options env takes a value for (`-u NAME`, `-C DIR`, ...), as bare letters. */
const ENV_VALUE_LETTERS = new Set(
	[...(WRAPPER_VALUE_OPTIONS.get("env") ?? [])].filter((option) => /^-\w$/.test(option)).map((option) => option[1]),
);

/**
 * How env reads one of its option words, as far as finding its command goes:
 * - `split`: the word carries a split string (`-Ssh`, `-iS'sh -s'`, `--split-string=sh`);
 * - `split-next`: the next word is the split string (`-S`, `-iS`, `--split-string`);
 * - `value-next`: the next word is an option's value (`-u`, `-iu`, `-vC`);
 * - `other`: anything else, a flag cluster or a value given inline (`-iuFOO`) included.
 */
type EnvOptionWord =
	| { kind: "split"; source: string }
	| { kind: "split-next" }
	| { kind: "value-next" }
	| { kind: "other" };

/**
 * Read `word` as env's option parser does: a `-xyz` word is a cluster of short options,
 * read letter by letter until one that takes a value, whose value is the rest of the word or,
 * when the word ends there, the next word. So `-iSsh` is `-i -S sh` and `-iuS` is `-i -u S`.
 * A long option may be abbreviated (`--split=sh`, `--s sh`).
 */
function readEnvOption(word: string): EnvOptionWord {
	const token = spelledWrapperOption("env", word);
	if (token === "--split-string") return { kind: "split-next" };
	const long = /^--split-string=(.*)$/.exec(token);
	if (long !== null) return { kind: "split", source: long[1] };
	if (!token.startsWith("-") || token.startsWith("--")) return { kind: "other" };
	for (let i = 1; i < token.length; i++) {
		const last = i === token.length - 1;
		if (token[i] === "S") return last ? { kind: "split-next" } : { kind: "split", source: token.slice(i + 1) };
		if (ENV_VALUE_LETTERS.has(token[i])) return last ? { kind: "value-next" } : { kind: "other" };
	}
	return { kind: "other" };
}

/**
 * The command string `token` carries attached to one of `options`: the rest of a `-c` word
 * (`-cCMD`) or the value of a `--name=CMD` word naming a long option in `options`.
 */
function attachedCommandStringSource(token: string, options: ReadonlySet<string>): string | null {
	if (token.startsWith("-c") && token.length > 2) return token.slice(2);
	const long = /^(--[^=]+)=([\s\S]*)$/.exec(token);
	return long !== null && options.has(long[1]) ? long[2] : null;
}

/**
 * fish's long options. fish also takes any prefix that names only one of them (`--init` for
 * `--init-command`), so an abbreviation is resolved against the whole set.
 */
const FISH_LONG_OPTIONS = [
	"command",
	"debug",
	"debug-output",
	"debug-stack-frames",
	"features",
	"help",
	"init-command",
	"interactive",
	"login",
	"no-config",
	"no-execute",
	"print-debug-categories",
	"print-rusage-self",
	"private",
	"profile",
	"profile-startup",
	"version",
];
const FISH_COMMAND_LONG_OPTIONS = new Set(["command", "init-command"]);
/** fish's short options that take a value, other than its command options `c` and `C`. */
const FISH_VALUE_LETTERS = new Set(["D", "d", "f", "o", "p"]);

/**
 * How fish reads a word as one of its command options, `-c`/`--command` or `-C`/`--init-command`
 * (whose commands it runs first): `value-next` when the next word is the command, `inline` when
 * the word carries it (`-Ccmd`, `--init-command=cmd`).
 */
type FishCommandOption = { kind: "value-next" } | { kind: "inline"; source: string };

/**
 * Read `word` as fish's option parser does, or null when it is not a command option. A `-xyz`
 * word is a cluster of short options, read letter by letter until one that takes a value, whose
 * value is the rest of the word or, when the word ends there, the next word: `-lc` is `-l -c`,
 * `-iCcmd` is `-i -C cmd`, and `-dc` is `-d c`.
 */
function readFishCommandOption(word: string): FishCommandOption | null {
	const long = /^--([^=]+)(?:=([\s\S]*))?$/.exec(word);
	if (long !== null) {
		const [, name, inline] = long;
		const named = longOptionCandidates(FISH_LONG_OPTIONS, name);
		if (named.length !== 1 || !FISH_COMMAND_LONG_OPTIONS.has(named[0])) return null;
		return inline === undefined ? { kind: "value-next" } : { kind: "inline", source: inline };
	}
	if (!/^-[^-]/.test(word)) return null;
	for (let i = 1; i < word.length; i++) {
		if (word[i] === "c" || word[i] === "C")
			return i === word.length - 1 ? { kind: "value-next" } : { kind: "inline", source: word.slice(i + 1) };
		if (FISH_VALUE_LETTERS.has(word[i])) return null;
	}
	return null;
}

/** The command a fish command option carries in its own word, or null. */
function fishInlineCommand(word: string): string | null {
	const option = readFishCommandOption(word);
	return option?.kind === "inline" ? option.source : null;
}

function scriptTargetIndex(argv: string[], index: number): number {
	let positional = 0;
	let options = true;
	for (let i = index + 1; i < argv.length; i++) {
		const token = argv[i];
		if (options && token === "--") {
			options = false;
			continue;
		}
		if (options && takesWrapperValue("script", token)) {
			i += 1;
			continue;
		}
		if (options && token.startsWith("-")) continue;
		positional += 1;
		if (positional === 2) return i;
	}
	return argv.length;
}

const SHELL_VALUE_LONG_OPTIONS = new Set(["--emulate", "--init-file", "--rcfile"]);

/**
 * The index of the script operand a POSIX-style shell runs, or `argv.length` when it runs none.
 * Invocation options come first -- flag clusters, `-o`/`+o`/`-O`/`+O` with their values, long
 * options -- until `--`, `-`, or the first operand. That operand is the script only when a `c`
 * flag was given; the words after it are `$0`, `$1`, ... Redirections may sit anywhere among
 * them (`bash 2>/dev/null -c '...'`) and are skipped with their destinations.
 *
 * An option whose value this walk does not know ends it early, at the value. When that happens
 * before any `c` flag, the word after the next `-c` spelling is taken as the script instead, so
 * an unknown option cannot hide one.
 */
function shellScriptIndex(argv: string[], index: number): number {
	return shellScriptOperand(argv, index).index;
}

/**
 * The script operand `shellScriptIndex` locates, and how it was found: `options` when a `c` flag
 * among the invocation options names it, `later-flag` when it is the word after a `-c` spelling
 * past the point the option walk stopped, `none` when there is no script (`index` is then
 * `argv.length`).
 */
interface ShellScriptOperand {
	index: number;
	found: "options" | "later-flag" | "none";
	/**
	 * The shell reads its script from standard input: no `c` flag is among its invocation
	 * options, and `-s` is (which makes every operand a positional parameter, `-c` spellings
	 * after `--` included), or no operand follows them, or the operand names standard input
	 * itself (`bash /dev/stdin`).
	 */
	stdin: boolean;
}

/** Script operands that name the shell's own standard input. */
const STDIN_SCRIPT_PATHS = new Set(["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"]);

function shellScriptOperand(argv: string[], index: number): ShellScriptOperand {
	const words = redirectionFreeIndexes(argv).filter((i) => i > index);
	let command = false;
	let stdinFlag = false;
	let k = 0;
	while (k < words.length) {
		const word = argv[words[k]];
		if (word === "--" || word === "-") {
			k += 1;
			break;
		}
		if (word.startsWith("--")) {
			if (word === "--command") command = true;
			k += SHELL_VALUE_LONG_OPTIONS.has(word) ? 2 : 1;
			continue;
		}
		if (!/^[-+][A-Za-z]+$/.test(word)) break;
		const letters = word.slice(1);
		if (word[0] === "-" && letters.includes("c")) command = true;
		if (word[0] === "-" && letters.includes("s")) stdinFlag = true;
		k += 1 + (letters.match(/[oO]/g)?.length ?? 0);
	}
	if (command)
		return k < words.length
			? { index: words[k], found: "options", stdin: false }
			: { index: argv.length, found: "none", stdin: false };
	for (let j = k; j + 1 < words.length; j++) {
		if (SHELL_EVAL_FLAG.test(argv[words[j]])) return { index: words[j + 1], found: "later-flag", stdin: stdinFlag };
	}
	const stdin = stdinFlag || k >= words.length || STDIN_SCRIPT_PATHS.has(argv[words[k]]);
	return { index: argv.length, found: "none", stdin };
}

const CSH_HEADS = new Set(["csh", "tcsh"]);

/**
 * Whether the `OPAQUE_SCRIPT_SHELLS` shell at `argv[index]` is handed a script: a command string,
 * an encoded command, or its standard input. A script FILE is not read for any shell, so
 * `tcsh build.csh` and `pwsh -File build.ps1` are not a script handed to the shell here.
 */
export function opaqueShellReadsScript(argv: string[], index: number): boolean {
	const base = headBase(argv[index]);
	if (!OPAQUE_SCRIPT_SHELLS.has(base)) return false;
	return CSH_HEADS.has(base) ? cshReadsScript(argv, index) : powerShellReadsScript(argv, index, base);
}

/**
 * csh's invocation is read with the POSIX walk (`shellScriptOperand`): option clusters, then `-c`
 * naming the following word as the script, or standard input when no script operand follows.
 * tcsh's `--help` and `--version` are honored only as the first argument and run nothing.
 */
function cshReadsScript(argv: string[], index: number): boolean {
	const operand = shellScriptOperand(argv, index);
	if (operand.found !== "none") return true;
	const first = argv[redirectionFreeIndexes(argv).find((i) => i > index) ?? argv.length];
	return operand.stdin && first !== "--help" && first !== "--version";
}

/**
 * Whether a PowerShell invocation reads a script other than a file. Its switches are matched
 * case-insensitively by any prefix pwsh accepts, behind one or two dashes (Unicode dashes
 * included) or, for a Windows `.exe`, a `/`, with any `:value` suffix cut off: a `-Command` or
 * `-CommandWithArgs` spelling, an `-EncodedCommand` or `-EncodedArguments` spelling (any `-e...`
 * switch but `-ExecutionPolicy`/`-ep`), or a bare dash is a script wherever it sits, so a
 * value-taking switch this walk does not know cannot hide one. `-File` names a script file, or
 * standard input when its value is `-` or missing. The first operand is a script file to pwsh,
 * but the command itself to Windows PowerShell (`powershell`). With neither a file nor
 * `-Help`/`-Version`, pwsh reads its commands from standard input.
 */
function powerShellReadsScript(argv: string[], index: number, base: string): boolean {
	const switchPrefix = base.endsWith(".exe") ? /^(?:[-–—―]{1,2}|\/)/ : /^[-–—―]{1,2}/;
	const operandIsCommand = base.startsWith("powershell");
	const words = redirectionFreeIndexes(argv)
		.filter((i) => i > index)
		.map((i) => argv[i]);
	let file = false;
	let terminating = false;
	for (let k = 0; k < words.length; k++) {
		const prefix = switchPrefix.exec(words[k]);
		if (prefix === null) {
			if (operandIsCommand) return true;
			file = true;
			continue;
		}
		const name = words[k].slice(prefix[0].length).split(":")[0].toLowerCase();
		const spells = (full: string): boolean => name.length > 0 && full.startsWith(name);
		if (name.length === 0 || spells("command") || spells("commandwithargs") || name === "cwa") return true;
		if (name.startsWith("e") && name !== "ep" && !(name.length >= 2 && spells("executionpolicy"))) return true;
		if (spells("help") || name === "?" || spells("version")) terminating = true;
		if (spells("file")) {
			const value = words[k + 1];
			if (value === undefined || value === "-") return true;
			file = true;
			k += 1;
		}
	}
	return !file && !terminating;
}

/**
 * Where env's command starts, as env's own option walk finds it (`envCommandTarget`):
 * - `word`: `index` is an ordinary word, or `argv.length` when env runs no command;
 * - `split-next`: `index` is the split string of the `-S` word before it (`-S 'sh -s'`);
 * - `split-attached`: `index` is the option word carrying the split string `source`
 *   (`-iSsh`, `--split-string=sh`).
 */
type EnvCommandTarget =
	| { kind: "word"; index: number }
	| { kind: "split-next"; index: number }
	| { kind: "split-attached"; index: number; source: string };

/**
 * Walk the `env` at `argv[index]` to its command the way env parses its arguments: an
 * option that takes a value consumes the next word whatever it spells, so `env -u -S cat`
 * unsets `-S` and runs `cat`. A split string holding only assignments is passed over to the
 * word after it.
 */
function envCommandTarget(argv: string[], index: number): EnvCommandTarget {
	let cursor = index + 1;
	while (cursor < argv.length) {
		const token = argv[cursor];
		if (terminatesWrapper("env", token)) return { kind: "word", index: argv.length };
		if (ASSIGNMENT_WORD.test(token)) {
			cursor += 1;
			continue;
		}
		const option = readEnvOption(token);
		if (option.kind === "split-next")
			return assignmentOnly(argv[cursor + 1] ?? "")
				? { kind: "word", index: cursor + 2 }
				: { kind: "split-next", index: cursor + 1 };
		if (option.kind === "split")
			return assignmentOnly(option.source)
				? { kind: "word", index: cursor + 1 }
				: { kind: "split-attached", index: cursor, source: option.source };
		if (option.kind === "value-next" || takesWrapperValue("env", token)) {
			cursor += 2;
			continue;
		}
		if (token === "--") {
			let target = cursor + 1;
			while (ASSIGNMENT_WORD.test(argv[target] ?? "")) target += 1;
			return { kind: "word", index: target };
		}
		if (token.startsWith("-")) {
			cursor += 1;
			continue;
		}
		return { kind: "word", index: cursor };
	}
	return { kind: "word", index: argv.length };
}

function wrapperTargetIndex(argv: string[], index: number, base: string = headBase(argv[index])): number {
	if (base === "env") return envCommandTarget(argv, index).index;
	if (SHELL_SOURCE_HEADS.has(base) && base !== "fish") return shellScriptIndex(argv, index);
	if (base === "fish") {
		for (let i = index + 1; i < argv.length; i++) {
			if (readFishCommandOption(argv[i])?.kind === "value-next") return i + 1;
		}
		return argv.length;
	}
	if (base === "eval") return argv[index + 1] === "--" ? index + 2 : index + 1;
	if (base === "trap") {
		const target = argv[index + 1] === "--" ? index + 2 : index + 1;
		return ["-l", "-p"].includes(argv[target] ?? "") ? argv.length : target;
	}
	if (base === "su") return optionCommandTarget(argv, index, SU_COMMAND_STRING_OPTIONS);
	if (base === "script") {
		const command = optionCommandTarget(argv, index, COMMAND_STRING_OPTIONS);
		return command < argv.length ? command : scriptTargetIndex(argv, index);
	}
	if (base === "flock") {
		const command = optionCommandTarget(argv, index, COMMAND_STRING_OPTIONS);
		if (command < argv.length) return command;
	}
	let cursor = index + 1;
	while (cursor < argv.length) {
		const token = argv[cursor];
		if (terminatesWrapper(base, token)) return argv.length;
		if (base === "sudo" && ASSIGNMENT_WORD.test(token)) {
			cursor += 1;
			continue;
		}
		if (token === "--") {
			let target = cursor + (base === "timeout" || base === "ssh" || base === "chroot" || base === "flock" ? 2 : 1);
			if (base === "sudo" || base === "ssh") while (ASSIGNMENT_WORD.test(argv[target] ?? "")) target += 1;
			return target;
		}
		if (base === "timeout" && !token.startsWith("-")) return cursor + 1;
		if (base === "ssh" && !token.startsWith("-")) {
			cursor += 1;
			while (ASSIGNMENT_WORD.test(argv[cursor] ?? "")) cursor += 1;
			return cursor;
		}
		if (base === "chroot" && !token.startsWith("-")) return cursor + 1;
		if (base === "flock" && !token.startsWith("-")) return cursor + 1;
		if (takesWrapperValue(base, token) || takesXargsLineCount(base, token, argv[cursor + 1])) {
			cursor += 2;
			continue;
		}
		if (token.startsWith("-")) {
			cursor += 1;
			continue;
		}
		return base === "script" ? argv.length : cursor;
	}
	return argv.length;
}

/** Indexes of commands the shell or a known exec wrapper invokes in this run. */
export function executableCommandIndexes(argv: string[]): number[] {
	const indexes: number[] = [];
	let index = commandPositionIndex(argv);
	while (index < argv.length) {
		indexes.push(index);
		const base = headBase(argv[index]);
		if (!EXEC_ARGUMENT_WRAPPERS.has(base)) break;
		const target = wrapperTargetIndex(argv, index, base);
		if (target >= argv.length) break;
		// A shell's script word is the whole program; the words after it are its positional
		// parameters, never a command, even when the script names a wrapper (`bash -c eval x`).
		if (SHELL_SOURCE_HEADS.has(base)) {
			indexes.push(target);
			break;
		}
		index = target;
	}
	return indexes;
}

/**
 * A character through which a shell script may read its positional parameters: an expansion
 * (`$1`, `"$@"`, a substitution), or the sentinel a quoted `$` is spelled as.
 */
const READS_PARAMETERS = new RegExp(`[$\`${EXPANSION_SUPPRESSED}]`);

/**
 * Whether a shell script may read its positional parameters, from its word as the run spells it
 * (`spelled`) and as the shell receives it (`received`, when the tokenizer recorded one).
 *
 * The spelling alone cannot tell a quoted `$` from a quoted `{`, `}`, `,`, `~`, `*`, `<` or `>`,
 * since all of them are `EXPANSION_SUPPRESSED` there, so each sentinel is read as the character
 * the received word holds in its place: `'echo hi, there'` reads none, `'echo $1'` and `"echo
 * \$1"` do. A received word that does not line up with the spelling is not trusted.
 */
function scriptReadsParameters(spelled: string, received: string | undefined): boolean {
	if (!READS_PARAMETERS.test(spelled)) return false;
	if (received === undefined || received.length !== spelled.length) return true;
	for (let k = 0; k < spelled.length; k++) {
		if (spelled[k] === EXPANSION_SUPPRESSED) {
			if (READS_PARAMETERS.test(received[k])) return true;
		} else if (spelled[k] !== received[k] || READS_PARAMETERS.test(spelled[k])) return true;
	}
	return false;
}

/**
 * The run without the positional parameters its shell script never reads, so the words after
 * `bash -c <script>` are not taken for arguments of the command the script names: `bash -c rm
 * -rf /` runs a bare `rm`, with `-rf` as `$0` and `/` as `$1`.
 *
 * Only a POSIX-style shell whose `c` flag was read among its invocation options is trimmed, and
 * only when the script word holds nothing it could reach a parameter through. Otherwise the run
 * is returned unchanged: `bash -c '"$@"' _ rm -rf /` runs its parameters, fish may read options
 * after the script, and a shell named by an untrusted path may be fish.
 *
 * A run whose command is `find` has each `-exec` command trimmed the same way, so `find .
 * -exec bash -c rm -rf / \;` reads as the bare `rm` it runs. A `find` inside an `-exec` command
 * is not descended into, which keeps the walk linear.
 */
export function withoutShellParameters(argv: string[]): string[] {
	const chain = executableCommandIndexes(argv);
	const command = chain.at(-1);
	const received = RECEIVED_WORDS.get(argv);
	const scriptWord = chain.length > 1 && SHELL_SOURCE_HEADS.has(headBase(argv[chain[chain.length - 2]]));
	if (command === undefined || scriptWord || headBase(argv[command]) !== "find")
		return withoutOwnShellParameters(argv, chain, received);
	const out: string[] = [];
	let copied = 0;
	for (const [from, to] of findExecSpans(argv, command + 1)) {
		const span = argv.slice(from, to);
		const trimmed = withoutOwnShellParameters(span, executableCommandIndexes(span), received?.slice(from, to));
		if (trimmed === span) continue;
		for (let i = copied; i < from; i++) out.push(argv[i]);
		for (const word of trimmed) out.push(word);
		copied = to;
	}
	if (copied === 0) return argv;
	for (let i = copied; i < argv.length; i++) out.push(argv[i]);
	return out;
}

/**
 * A positional parameter a shell `-c` script is handed: `text` as the program receives it, and
 * `spelled` as the run's argv spells it, where a quote-suppressed character is
 * `EXPANSION_SUPPRESSED`. Comparing the two tells a character the outer shell still expands
 * (`~`, `*`, `$HOME`) from a literal one.
 */
interface ShellParameter {
	text: string;
	spelled: string;
	/**
	 * `varies` when the outer shell may turn the word into none or several (an unquoted
	 * expansion, a glob, a brace expansion), which shifts the index of every parameter after it.
	 */
	wordCount: "one" | "varies";
}

/** A character that makes a `$` before it an expansion rather than a literal `$`. */
const PARAMETER_START = /[A-Za-z0-9_@*#?$!{-]/;

/** A brace expansion bash may expand into several words: live braces around a `,` or `..`. */
const BRACE_EXPANSION = /\{[^{}\u0000]*(?:,|\.\.)[^{}\u0000]*\}/;

/**
 * A list expansion, which gives one word per element even inside double quotes: `"$@"`,
 * `"${@...}"`, `"${arr[@]}"`, `"${!prefix@}"`.
 */
const LIST_EXPANSION = /\$(?:@|\{(?:@|![^}]*[@*]|[^}]*\[[@*]\]))/;

/**
 * Whether the outer shell may turn the word at `index` of a run into none or several words: an
 * unquoted expansion (`SPLITTING_WORDS`), a list expansion quoted or not, a glob (`GLOB_WORDS`,
 * a live `*`) or a brace expansion. A run without those records is judged from its spelling
 * alone, as `UNSTABLE_WORD` judges it, less the tilde, which always gives one word.
 */
function wordCountMayVary(argv: string[], index: number): boolean {
	const word = argv[index];
	if (LIST_EXPANSION.test(word) || BRACE_EXPANSION.test(word)) return true;
	const splitting = SPLITTING_WORDS.get(argv);
	const globs = GLOB_WORDS.get(argv);
	if (splitting === undefined || globs === undefined) return /[$`*?[]/.test(word);
	return splitting.has(index) || globs.has(index) || /\*/.test(word);
}

/** Text that may start a positional-parameter reference, to pass over a script that makes none. */
const POSITIONAL_REFERENCE_START = /\$(?:[@*0-9]|\{)/;

/**
 * The positional-parameter references a pattern spells out whole: `$@`, `$*`, `$N` (`$10` is
 * `${1}` followed by `0`), the braced `${@}`, `${*}`, `${N}`, and the slices `${@:k}` and
 * `${@:k:n}`.
 */
const FIXED_POSITIONAL_REFERENCE = /\$(?:([@*0-9])|\{(?:([@*]|[0-9]+)|([@*]):([0-9]+)(?::([0-9]+))?)\})/y;

/**
 * The start of a braced expansion of the parameters whose word runs to its matching `}`
 * (`braceEndReader`): a default or assignment form (`${1:-x}`, `${@-x}`, `${1=x}`, `${1?x}`),
 * whose value is the parameters when they are set, or a list form this does not parse (a slice
 * of `@` or `*` with a negative or computed offset, `${@: -1}`, `${@:1:$#}`, or the last
 * parameter, `${!#}`), which may name any of them. Any other braced operator (`${1%.x}`,
 * `${1:+x}`, `${1:2}`) is left alone: its value is not the parameter's text.
 */
const BRACED_POSITIONAL_REFERENCE = /\$\{(?:([0-9]+|[@*])(:?)[-=?]|([@*]):|!#)/y;

/** The parameters a positional-parameter reference names. */
type PositionalTarget =
	| { kind: "all"; star: boolean }
	| { kind: "index"; index: number }
	| { kind: "slice"; star: boolean; from: number; length: number | undefined }
	| { kind: "any"; star: boolean };

/**
 * A positional-parameter reference read at a `$`: its spelling, the index just past it, what it
 * names, and for a default or assignment form whether a set but empty parameter also takes the
 * default word (`colon`, as in `${1:-x}`).
 */
interface PositionalReference {
	raw: string;
	end: number;
	target: PositionalTarget;
	defaulted?: { colon: boolean };
}

/**
 * A reader of the index of the `}` that closes the `${` at a given index of `source`, or
 * undefined when it never closes. The word is read as bash reads it: a backslash escapes the
 * character after it, and quoted spans, command substitutions and backtick bodies are passed
 * over, a quote that never closes being a plain character. Every `${` a read passes is recorded,
 * so a later read inside it costs nothing, and `charge` is told how many characters each read
 * scanned.
 */
function braceEndReader(source: string, charge: (scanned: number) => void): (at: number) => number | undefined {
	const ends = new Map<number, number | undefined>();
	return (at) => {
		if (ends.has(at)) return ends.get(at);
		const open = [at];
		let i = at + 2;
		while (i < source.length && open.length > 0) {
			const c = source[i];
			let read: Scanned | undefined;
			if (c === "\\") {
				i += 2;
				continue;
			}
			if (c === "'" || c === '"') read = readQuoted(source, i, c);
			else if (c === "$" && source[i + 1] === "'") read = readAnsiCQuoted(source, i);
			else if (c === "`") read = readBackticks(source, i);
			else if (c === "$" && source[i + 1] === "(") read = readSubstitution(source, i);
			if (read !== undefined) {
				charge(read.end - i);
				i = read.complete || c === "`" || source[i + 1] === "(" ? read.end : i + 1;
				continue;
			}
			if (c === "$" && source[i + 1] === "{") {
				if (!ends.has(i)) {
					open.push(i);
					i += 2;
					continue;
				}
				const known = ends.get(i);
				if (known === undefined) break;
				i = known + 1;
				continue;
			}
			if (c === "}") ends.set(open.pop() as number, i);
			i += 1;
		}
		charge(i - at);
		for (const unclosed of open) ends.set(unclosed, undefined);
		return ends.get(at);
	};
}

/** The positional-parameter reference at `at` in `source`, whose `${` ends `braceEnd` reads. */
function readPositionalReference(
	source: string,
	at: number,
	braceEnd: (at: number) => number | undefined,
): PositionalReference | undefined {
	FIXED_POSITIONAL_REFERENCE.lastIndex = at;
	const fixed = FIXED_POSITIONAL_REFERENCE.exec(source);
	if (fixed !== null) {
		const [raw, digit, braced, sliced, from, length] = fixed;
		const name = digit ?? braced;
		const target: PositionalTarget =
			sliced !== undefined
				? {
						kind: "slice",
						star: sliced === "*",
						from: Number(from),
						length: length === undefined ? undefined : Number(length),
					}
				: name === "@" || name === "*"
					? { kind: "all", star: name === "*" }
					: { kind: "index", index: Number(name) };
		return { raw, end: FIXED_POSITIONAL_REFERENCE.lastIndex, target };
	}
	BRACED_POSITIONAL_REFERENCE.lastIndex = at;
	const braced = BRACED_POSITIONAL_REFERENCE.exec(source);
	if (braced === null) return undefined;
	const close = braceEnd(at);
	if (close === undefined) return undefined;
	const [, name, colon, listed] = braced;
	const spelling = { raw: source.slice(at, close + 1), end: close + 1 };
	if (name === undefined) return { ...spelling, target: { kind: "any", star: listed === "*" } };
	return {
		...spelling,
		target:
			name === "@" || name === "*" ? { kind: "all", star: name === "*" } : { kind: "index", index: Number(name) },
		defaulted: { colon: colon === ":" },
	};
}

/** Characters a spliced parameter keeps bare because they read as themselves. */
const SPLICE_WORD_CHARACTER = /[A-Za-z0-9_\-./:@%+^]/;

/**
 * A parameter as unquoted shell text that reads as its value: split into fields at blanks
 * (`split`, an unquoted reference), or one word (a double-quoted one). A character the outer
 * shell still expands stays live, as do the glob characters an unquoted reference leaves live;
 * every other character is escaped. When `text` and `spelled` do not line up, every character
 * that could expand is taken to.
 */
function spliceParameter(parameter: ShellParameter, split: boolean): string {
	const { text, spelled } = parameter;
	const aligned = spelled.length === text.length;
	const live = (k: number): boolean => !aligned || spelled[k] !== EXPANSION_SUPPRESSED;
	let out = "";
	let i = 0;
	while (i < text.length) {
		const c = text[i];
		if ((c === "$" || c === "`") && live(i)) {
			const read =
				c === "`"
					? readBackticks(text, i)
					: text[i + 1] === "("
						? readSubstitution(text, i)
						: text[i + 1] === "{"
							? readBraced(text, i)
							: undefined;
			out += read?.raw ?? c;
			i = read?.end ?? i + 1;
			continue;
		}
		if (c === " " || c === "\t" || c === "\n") out += split ? " " : c === "\n" ? '"\n"' : `\\${c}`;
		else if (SPLICE_WORD_CHARACTER.test(c) || "?[]".includes(c)) out += c;
		else if (c === "*") out += split || live(i) ? c : `\\${c}`;
		else if ("~{},".includes(c) && live(i)) out += c;
		else out += `\\${c}`;
		i += 1;
	}
	return out;
}

/**
 * What splicing a script's positional parameters into it gives: `unreferenced` when the script
 * makes no reference to one, `spliced` with the resulting readings, or `over-budget` when they
 * would outgrow the nesting budget, so the script is left unread.
 */
type SplicedScript = { kind: "unreferenced" } | { kind: "spliced"; texts: string[] } | { kind: "over-budget" };

/**
 * Where a positional-parameter reference sits, which decides how its parameters are spliced:
 * `whole-double-quoted` is a double-quoted string holding nothing but the reference (`"$1"`),
 * and `heredoc` an unquoted heredoc body, which takes the parameters' text as it is.
 */
type ReferenceContext = "unquoted" | "double-quoted" | "whole-double-quoted" | "heredoc";

/**
 * How many double-quoted command substitutions and backtick bodies deep the splice descends. Past
 * it the script is left unread rather than recursing toward the call stack's limit.
 */
const MAX_SPLICE_DEPTH = 100;

/** A `<<` or `<<-` heredoc operator anywhere in a text, not a `<<<` here-string. */
const HEREDOC_OPERATOR = /(?:^|[^<])<<(?!<)/;

/** A backslash-newline line continuation, which bash removes before it tokenizes. */
const LINE_CONTINUATION = /\\\n/g;

/**
 * A construct in a frame's source that makes bash expand a `$(...)` or backtick written even
 * inside single quotes, so a single-quoted word there is not inert. Bash does this wherever it
 * evaluates text as arithmetic or re-parses it:
 *   - `((` (arithmetic command / `for (( ))` / a `$(( ))` expansion),
 *   - a `let` command,
 *   - any `[` (an array subscript `a[$(cmd)]`, a `${a[...]}` expansion, a `[[` conditional whose
 *     `-eq`-family operators are arithmetic, or an old `$[ ]` expansion -- one class, since bash
 *     evaluates every bracketed subscript arithmetically and a subscript may nest brackets),
 *   - `${` (a parameter expansion, whose subscript or `:off:len` substring bounds are arithmetic),
 *   - `<<` (a heredoc, whose unquoted body expands),
 *   - `$'` (an ANSI-C quote, whose `\xNN` escapes can spell any of the above after decoding).
 * Deliberately broad and matched on the raw text: it only ever over-denies a single-quoted
 * substitution that sits beside one of these, which main denied outright, so it is the
 * fail-closed direction and never a regression. Every branch is a fixed short literal, so the
 * test stays linear (no unbounded repetition to backtrack).
 */
const SINGLE_QUOTES_LIVE_CONTEXT = /<<|\(\(|\$\{|\$'|\[|(?:^|[^\w-])let(?![\w-])/;

/**
 * `script` with each positional-parameter reference replaced by the parameters it names (`$0`
 * is the first), spliced the way the shell expands them (`spliceParameter`): outside quotes each
 * parameter splits into words, inside double quotes `"$@"` is one word per parameter and `"$*"`
 * or `"$N"` one word. A reference at or past a parameter whose word count varies may land on any
 * parameter from that one on, so it splices all of them. Building stops once the text or the
 * scan passes `limit` characters, since every reference can repeat every parameter.
 *
 * An unquoted heredoc body takes the parameters' text as it is, which is shell source when the
 * heredoc feeds a shell; but a nested source's body lines are read as shell structure, where a
 * quote in that text could swallow the lines after it. So a script with such a body, or with a
 * `<<` whose body may not have been placed, gives two readings: one with the parameters escaped
 * as outside quotes, and one with every body or unquoted reference taking their text as it is.
 *
 * The script's structure is read by `SubstitutionBody`, the scanner that finds where a command
 * substitution ends, in its `"top-level"` scope, so comments, `case` patterns, `${...}`
 * expansions, arithmetic and heredoc bodies are placed as bash places them in a script; quoted
 * spans are read here, as `readSubstitution` reads them. A single quote that never closes is a
 * plain character, so it cannot hide the references after it. A command substitution or
 * backtick body inside double quotes is spliced on its own.
 */
function spliceShellParameters(script: string, parameters: readonly ShellParameter[], limit: number): SplicedScript {
	if (!POSITIONAL_REFERENCE_START.test(script)) return { kind: "unreferenced" };
	const varies = parameters.findIndex((parameter) => parameter.wordCount === "varies");
	const shifted = (from: number): boolean => varies !== -1 && varies <= from;
	type Selection =
		| { kind: "default-word" }
		| { kind: "parameters"; named: readonly ShellParameter[]; list: boolean; star: boolean };
	/**
	 * The parameters a reference names, or `default-word` when a default or assignment form
	 * takes its own word instead (the parameter unset, or empty under a colon form).
	 */
	const select = (reference: PositionalReference): Selection => {
		const { target, defaulted } = reference;
		const chosen = (named: readonly ShellParameter[], list: boolean, star: boolean): Selection => ({
			kind: "parameters",
			named,
			list,
			star,
		});
		if (target.kind === "any") return chosen(parameters, true, target.star);
		if (target.kind === "all") {
			const named = parameters.slice(varies === 0 ? 0 : 1);
			return defaulted !== undefined && named.length === 0
				? { kind: "default-word" }
				: chosen(named, true, target.star);
		}
		if (target.kind === "slice") {
			const end = target.length === undefined ? parameters.length : target.from + target.length;
			const named = shifted(end - 1)
				? parameters.slice(Math.min(varies, target.from))
				: parameters.slice(target.from, end);
			return chosen(named, true, target.star);
		}
		if (shifted(target.index)) return chosen(parameters.slice(varies), true, false);
		const parameter = parameters[target.index];
		if (parameter === undefined) return defaulted === undefined ? chosen([], false, false) : { kind: "default-word" };
		if (defaulted?.colon === true && parameter.text === "") return { kind: "default-word" };
		return chosen([parameter], false, false);
	};
	const splices = new Map<string, string>();
	const splice = (reference: PositionalReference, context: ReferenceContext): string => {
		const key = `${context}:${reference.raw}`;
		let text = splices.get(key);
		if (text !== undefined) return text;
		const selected = select(reference);
		if (selected.kind === "default-word")
			text = context === "whole-double-quoted" ? `"${reference.raw}"` : reference.raw;
		else if (context === "heredoc") text = selected.named.map((parameter) => parameter.text).join(" ");
		else if (context === "unquoted")
			text = selected.named.map((parameter) => spliceParameter(parameter, true)).join(" ");
		else {
			const words = selected.named.map((parameter) => spliceParameter(parameter, false));
			const joined = words.join(selected.star ? "\\ " : " ");
			if (context === "double-quoted") text = `"${joined}"`;
			else if (selected.list && !selected.star) text = words.map((word) => word || '""').join(" ");
			else text = joined || '""';
		}
		splices.set(key, text);
		return text;
	};
	let work = 0;
	const exceeded = (out: string): boolean => work + out.length > limit;
	const charge = (scanned: number): void => {
		work += scanned;
	};
	/**
	 * One reading of the script, with its parameters spliced `as-is` or `escaped` in an unquoted
	 * heredoc body and at an unquoted reference, and how many references it spliced outside and
	 * inside such bodies. Undefined once the budget or the depth is spent.
	 */
	const reading = (
		text: "escaped" | "as-is",
	): { text: string; references: number; heredocReferences: number } | undefined => {
		const bare: ReferenceContext = text === "as-is" ? "heredoc" : "unquoted";
		let references = 0;
		let heredocReferences = 0;
		const heredocBody = (text: string): string => {
			const ends = braceEndReader(text, charge);
			let out = "";
			for (let k = 0; k < text.length; k++) {
				if (text[k] === "\\" || (text[k] === "$" && text[k + 1] === "$")) {
					out += text.slice(k, k + 2);
					k += 1;
					continue;
				}
				const found = readPositionalReference(text, k, ends);
				if (found === undefined) out += text[k];
				else {
					out += splice(found, bare);
					heredocReferences += 1;
					k = found.end - 1;
				}
			}
			return out;
		};
		const doubleQuoted = (
			source: string,
			start: number,
			depth: number,
			ends: (at: number) => number | undefined,
		): { text: string; end: number } | undefined => {
			const whole = readPositionalReference(source, start + 1, ends);
			if (whole !== undefined && source[whole.end] === '"') {
				references += 1;
				return { text: splice(whole, "whole-double-quoted"), end: whole.end + 1 };
			}
			let text = '"';
			let j = start + 1;
			while (j < source.length && source[j] !== '"') {
				if (exceeded(text)) return undefined;
				const c = source[j];
				if (c === "\\" || (c === "$" && source[j + 1] === "$")) {
					text += source.slice(j, j + 2);
					j += 2;
					continue;
				}
				const found = readPositionalReference(source, j, ends);
				if (found !== undefined) {
					text += splice(found, "double-quoted");
					references += 1;
					j = found.end;
					continue;
				}
				if ((c === "$" && source[j + 1] === "(") || c === "`") {
					const read = c === "`" ? readBackticks(source, j, "double-quoted") : readSubstitution(source, j);
					const opener = c === "`" ? "`" : "$(";
					const body = commands(read.text, depth + 1, c === "`" ? "top-level" : "substitution");
					if (body === undefined) return undefined;
					const written = c === "`" ? escapeBacktickBody(body, "double-quoted") : body;
					text += `${opener}${written}${read.complete ? (c === "`" ? "`" : ")") : ""}`;
					if (exceeded(text)) return undefined;
					j = read.end;
					continue;
				}
				text += c;
				j += 1;
			}
			if (j < source.length) {
				text += '"';
				j += 1;
			}
			return { text, end: j };
		};
		const commands = (source: string, depth: number, scope: HeredocContext): string | undefined => {
			if (depth > MAX_SPLICE_DEPTH) return undefined;
			work += nestedSourceCost(source);
			const ends = braceEndReader(source, charge);
			let body = new SubstitutionBody("commands", source, 0, scope);
			let out = "";
			let i = 0;
			while (i < source.length) {
				if (exceeded(out)) return undefined;
				const c = source[i];
				if (!body.inComment) {
					if (c === "\\") {
						if (source[i + 1] !== "\n") body.quoted(source.slice(i, i + 2));
						out += source.slice(i, i + 2);
						i += 2;
						continue;
					}
					if (c === "'" || (c === "$" && source[i + 1] === "'")) {
						const read = c === "'" ? readQuoted(source, i, "'") : readAnsiCQuoted(source, i);
						if (read.complete) {
							body.quoted(read.raw);
							out += read.raw;
							i = read.end;
							continue;
						}
					} else if (c === '"') {
						const read = doubleQuoted(source, i, depth, ends);
						if (read === undefined) return undefined;
						body.quoted(source.slice(i, read.end));
						out += read.text;
						i = read.end;
						continue;
					} else if (c === "`") {
						const read = readBackticks(source, i);
						const inner = commands(read.text, depth + 1, "top-level");
						if (inner === undefined) return undefined;
						body.quoted(read.raw);
						out += `\`${escapeBacktickBody(inner, "unquoted")}${read.complete ? "`" : ""}`;
						if (exceeded(out)) return undefined;
						i = read.end;
						continue;
					} else if (c === "$" && source[i + 1] !== "$") {
						const found = readPositionalReference(source, i, ends);
						if (found !== undefined) {
							body.quoted(found.raw);
							out += splice(found, bare);
							references += 1;
							i = found.end;
							continue;
						}
					} else if (c === "$") {
						out += "$$";
						body.read(i);
						i = body.read(i + 1);
						continue;
					}
				}
				const next = body.read(i);
				const skipped = next > i + 1 ? body.skippedBodies : [];
				if (skipped.reduce((length, { read }) => length + read.raw.length, i + 1) !== next) return undefined;
				out += c;
				for (const { heredoc, read } of skipped) {
					out += heredoc.quoted ? read.text : heredocBody(read.text);
					out += read.raw.slice(read.text.length);
				}
				i = next;
				if (body.closed) body = new SubstitutionBody("commands", source, i, scope);
			}
			return out;
		};
		const spliced = commands(script, 0, "top-level");
		return spliced === undefined || exceeded(spliced) ? undefined : { text: spliced, references, heredocReferences };
	};
	const escaped = reading("escaped");
	if (escaped === undefined) return { kind: "over-budget" };
	if (escaped.references + escaped.heredocReferences === 0) return { kind: "unreferenced" };
	if (escaped.heredocReferences === 0 && !HEREDOC_OPERATOR.test(script))
		return { kind: "spliced", texts: [escaped.text] };
	work += escaped.text.length;
	const raw = reading("as-is");
	return raw === undefined ? { kind: "over-budget" } : { kind: "spliced", texts: [escaped.text, raw.text] };
}

/**
 * The script at `script` in `words` read with the positional parameters after it spliced in
 * (`spliceShellParameters`), so `bash -c 'git push "$@"' _ --force` is also read as the
 * `git push --force` it runs. `words` are the run's argv words, `received` the same words as the
 * program receives them. A script handed no parameter is `unreferenced`.
 */
function parameterSplicedSource(
	words: string[],
	received: readonly string[],
	script: number,
	limit: number,
): SplicedScript {
	if (script + 1 >= words.length) return { kind: "unreferenced" };
	const parameters = words.slice(script + 1).map(
		(spelled, k): ShellParameter => ({
			text: received[script + 1 + k] ?? spelled,
			spelled,
			wordCount: wordCountMayVary(words, script + 1 + k) ? "varies" : "one",
		}),
	);
	return spliceShellParameters(received[script] ?? words[script], parameters, limit);
}

/**
 * `withoutShellParameters` for a run whose own command chain (`chain`) may end at a shell.
 * `received` is the run's words as the program receives them, when the tokenizer recorded them.
 */
function withoutOwnShellParameters(argv: string[], chain: number[], received: readonly string[] | undefined): string[] {
	if (chain.length < 2) return argv;
	const shell = chain[chain.length - 2];
	const base = headBase(argv[shell]);
	if (!SHELL_SOURCE_HEADS.has(base) || base === "fish" || namedByUntrustedPath(argv[shell])) return argv;
	const script = shellScriptOperand(argv, shell);
	if (script.found !== "options" || script.index + 1 >= argv.length) return argv;
	return scriptReadsParameters(argv[script.index], received?.[script.index]) ? argv : argv.slice(0, script.index + 1);
}

/**
 * A word that starts a redirection, and one that is ONLY the operator so its destination is the
 * next word.
 *
 * The whole operator set matters, not just `>`/`<`: bash takes a following word for `>&`, `<&`,
 * `<>`, `>|`, `<<` and `<<<` as readily as for `>`, and a duplicating form that names its target
 * inline (`2>&1`, `<&-`) takes none. The fd in front may be a number or a `{name}` bash assigns,
 * and a here-doc may strip tabs (`<<-`). Missing one puts a destination or a here-doc delimiter
 * back among the operands.
 */
export const REDIRECTION_FD = String.raw`(?:\d*|\{[A-Za-z_][A-Za-z0-9_]*\})`;
const REDIRECTION_SYMBOL = String.raw`(?:>>|>\||>&|<<<|<<-|<<|<>|<&|>|<)`;
const REDIRECTION_OPERATOR = `(?:${REDIRECTION_FD}${REDIRECTION_SYMBOL}|&>>?)`;
/** `<(cmd)` / `>(cmd)` -- an ARGUMENT naming a `/dev/fd` path, not a redirection. */
export const PROCESS_SUBSTITUTION_WORD = /^[<>]\(/;
const REDIRECTION = new RegExp(`^${REDIRECTION_OPERATOR}`);
const REDIRECTION_ALONE = new RegExp(`^${REDIRECTION_OPERATOR}$`);
const REDIRECTION_SYMBOL_START = new RegExp(`^(?:${REDIRECTION_SYMBOL}|&>>?)`);
/** The longest redirection operator, in characters (`<<<`, `<<-`, `&>>`). */
const LONGEST_REDIRECTION_SYMBOL = 3;

/** A redirection operator read from the source, and the index just past it. */
export interface RedirectionOperator {
	text: string;
	end: number;
}

/**
 * The redirection operator spelled at `start` in `source`, without any descriptor in front of it
 * (`>`, `>>`, `>&`, `<<<`, `<<-`, `&>`, ...), or `undefined` when none is. A line continuation
 * inside it is skipped as the shell skips it, so `>\` newline `>` reads as `>>`.
 */
export function readRedirectionOperator(source: string, start: number): RedirectionOperator | undefined {
	let spelled = "";
	const ends: number[] = [];
	let i = start;
	while (spelled.length < LONGEST_REDIRECTION_SYMBOL && i < source.length) {
		if (source[i] === "\\" && source[i + 1] === "\n") {
			i += 2;
			continue;
		}
		spelled += source[i];
		i += 1;
		ends.push(i);
	}
	const text = REDIRECTION_SYMBOL_START.exec(spelled)?.[0];
	return text === undefined ? undefined : { text, end: ends[text.length - 1] };
}

/**
 * Drop redirections and their destinations.
 *
 * A process substitution only looks like one: `<(cmd)` is a word naming a `/dev/fd` path, so
 * dropping it would hide an argument -- `git <(echo x) push --force` passes that path as git's
 * subcommand and pushes nothing.
 *
 * A destination is not an operand: `rm -rf ./build 2> ~/cleanup.err` removes `./build` and
 * writes stderr to a file, and reading `~/cleanup.err` as a second thing being deleted would
 * hard-deny an ordinary command with no way to override it. An operator that carries its own
 * destination (`2>&1`, `>log`) consumes nothing, so only a bare one takes the following word.
 */
export function withoutRedirections(argv: string[]): string[] {
	const indexes = redirectionFreeIndexes(argv);
	const words = indexes.map((index) => argv[index]);
	const received = RECEIVED_WORDS.get(argv);
	if (received !== undefined) {
		const kept = indexes.map((index) => received[index]);
		RECEIVED_WORDS.set(words, kept);
	}
	return words;
}

/** A run's words with its redirections removed, and the raw argv index each one came from. */
interface RedirectionFreeView {
	words: string[];
	indexes: number[];
}

/** Every tokenized run's redirection-free view, keyed by the run's own argv array. */
const REDIRECTION_FREE_VIEWS = new WeakMap<string[], RedirectionFreeView>();

/**
 * For every tokenized run, and for its redirection-free view, the indexes of the words that
 * carry a `?` or `[` bash reads as a glob: one written bare, not quoted or escaped. The argv
 * keeps those characters as themselves either way, so only the tokenizer can tell
 * `awk '/colou?r/'` (one fixed word) from `awk c?t` (whatever files match).
 */
const GLOB_WORDS = new WeakMap<string[], ReadonlySet<number>>();

/**
 * For every tokenized run, and for its redirection-free view, the indexes of the words holding
 * an expansion written outside quotes (`$x`, `$(...)`, a backtick), which bash splits into
 * fields and can drop entirely when empty. The argv spells `"$x"` and `$x` alike, so only the
 * tokenizer can tell a word that stays one word from one that may become none or several.
 */
const SPLITTING_WORDS = new WeakMap<string[], ReadonlySet<number>>();

/**
 * For every tokenized run that holds a word the program receives differently from how the argv
 * spells it, and for its redirection-free view and `withoutRedirections` of it, the words as the
 * program receives them (see `received` in `lexSource`), paired by position. A quoted `$` and a
 * quoted `{` are both `EXPANSION_SUPPRESSED` in the argv, so only these words tell them apart.
 */
const RECEIVED_WORDS = new WeakMap<string[], readonly string[]>();

/**
 * The words of a tokenized run with its redirections removed, as the tokenizer read them.
 *
 * Unlike `withoutRedirections`, this knows what was quoted: `timeout '1'>/dev/null sh` keeps
 * its duration `1` and `<<<'' cat /bin/sh` keeps `cat`, where stripping the assembled words
 * drops the one and hands the other to the here-string. An array the tokenizer did not
 * produce is returned unchanged.
 */
export function redirectionFreeWords(argv: string[]): string[] {
	return REDIRECTION_FREE_VIEWS.get(argv)?.words ?? argv;
}

/** The indexes of the words `withoutRedirections` keeps, in order. */
function redirectionFreeIndexes(argv: string[]): number[] {
	const kept: number[] = [];
	for (let i = 0; i < argv.length; i++) {
		if (PROCESS_SUBSTITUTION_WORD.test(argv[i]) || !REDIRECTION.test(argv[i])) kept.push(i);
		else if (REDIRECTION_ALONE.test(argv[i])) i += 1;
	}
	return kept;
}

/** The inline program of one awk invocation. */
export interface AwkInlineProgram {
	/** The bare program operand and/or every `-e`/`--source` value (awk concatenates those). */
	fragments: string[];
	/** Whether `fragments` is the whole program: no `-f` program file and no unrecognized option. */
	complete: boolean;
	/** One past the first operand: the words before it are options, option values, or the program. */
	end: number;
}

/**
 * The inline program of the awk invocation whose head is at `head` in `words`. `fragments` is
 * empty when no inline program can be confidently located.
 *
 * Options are skipped in both the short (`-F:`, `-Ffs`, `-v x=1`) and gawk long
 * (`--field-separator`, `--assign`) spellings; `--` ends option parsing. `-e prog`/`--source prog`/
 * `--source=prog`/attached `-eprog` contribute their VALUE as a program fragment (these ARE inline
 * programs -- treating `--source` as a plain value-option would both miss the program and misread
 * the following data file as one). `-f progfile`/`--file` marks a program-bearing option whose
 * contents we cannot see (fail-closed for that fragment) and, like any `-e`/`--source`, means the
 * bare operand is a data file rather than the program. An UNRECOGNIZED `-`-led option makes the
 * bare-operand inference uncertain (its arity is unknown), so the bare operand is no longer taken
 * as a program -- but any `-e`/`--source` fragment already collected stays, since it is a definite
 * program. `executableCommandIndexes` already walked any wrapper to awk's index, which resolves
 * the wrapped `sudo awk '...'` case.
 */
export function awkInlineProgram(words: readonly string[], head: number): AwkInlineProgram {
	const fragments: string[] = [];
	let optionsEnded = false;
	let sawProgramOption = false;
	let sawProgramFile = false;
	let uncertain = false;
	let j = head + 1;
	while (j < words.length) {
		const t = words[j];
		// A `-`-led word is an option (an awk program never starts with `-`), regardless of shell
		// quoting -- awk parses the post-shell argv, so `--source='{...}'` (which merges to
		// `--source={...}`) is still the option. Anything else is the first operand.
		if (optionsEnded || t.length <= 1 || t[0] !== "-") {
			if (!sawProgramOption && !uncertain) fragments.push(t);
			j += 1;
			break;
		}
		if (t === "--") {
			optionsEnded = true;
			j += 1;
			continue;
		}
		if (t === "-f" || t === "--file") {
			sawProgramOption = true;
			sawProgramFile = true;
			j += 2;
			continue;
		}
		if (t.startsWith("--file=") || /^-f./.test(t)) {
			sawProgramOption = true;
			sawProgramFile = true;
			j += 1;
			continue;
		}
		if (t === "-e" || t === "--source") {
			sawProgramOption = true;
			if (j + 1 < words.length) fragments.push(words[j + 1]);
			j += 2;
			continue;
		}
		if (t.startsWith("--source=")) {
			sawProgramOption = true;
			fragments.push(t.slice("--source=".length));
			j += 1;
			continue;
		}
		if (t.startsWith("-e") && t.length > 2) {
			sawProgramOption = true;
			fragments.push(t.slice(2));
			j += 1;
			continue;
		}
		if (t === "-F" || t === "-v" || t === "--field-separator" || t === "--assign") {
			j += 2;
			continue;
		}
		if (t.startsWith("-F") || t.startsWith("-v") || t.startsWith("--field-separator=") || t.startsWith("--assign=")) {
			j += 1;
			continue;
		}
		uncertain = true;
		j += 1;
	}
	return {
		fragments,
		complete: fragments.length > 0 && !sawProgramFile && !uncertain,
		end: Math.min(j, words.length),
	};
}

/** Wrappers that run their command operand directly, handing it their own input unchanged. */
const INPUT_PRESERVING_WRAPPERS = new Set([
	"chroot",
	"command",
	"doas",
	"env",
	"exec",
	"nice",
	"nohup",
	"setsid",
	"stdbuf",
	"sudo",
	"time",
	"timeout",
	"unshare",
]);

/**
 * What in an awk program can run the text awk reads: `system()`, a print or getline pipe
 * (`print | cmd`, `$0 | getline`; a `||` is refused with them), and a gawk indirect call
 * (`@f()`, which reaches builtins such as `system` by a computed name).
 */
const AWK_PROGRAM_RUNS_INPUT = /system|\||@/;

/**
 * A character that can make a word expand into something other than exactly one known
 * word: a parameter, command or arithmetic expansion, a tilde, or a glob or brace
 * expansion. Quoted `~`, `*`, `$` (single quotes) and braces are already suppressed in the
 * argv, so they do not count; a quoted `?` or `[` still does, which only over-reads a word
 * as expanding (`wordMayExpand` tells those apart by quoting).
 */
const UNSTABLE_WORD = /[$`~*?[{]/;

/** `UNSTABLE_WORD` without the glob characters `?` and `[`, which `GLOB_WORDS` tracks by quoting. */
const EXPANDING_WORD = /[$`~*{]/;

/**
 * Whether the word at `index` of `argv` can expand into something other than exactly one
 * known word. A `?` or `[` counts only where the tokenizer saw it bare (`GLOB_WORDS`), so a
 * quoted awk program such as `'!seen[$0]++'` stays one word; an array the tokenizer did not
 * produce is read by its characters alone, the fail-closed direction.
 */
function wordMayExpand(argv: string[], index: number): boolean {
	const globWords = GLOB_WORDS.get(argv);
	if (globWords === undefined) return UNSTABLE_WORD.test(argv[index]);
	return EXPANDING_WORD.test(argv[index]) || globWords.has(index);
}

/**
 * Whether an awk run leaves what is piped into it as data, so the run is not an interpreter
 * for the pipeline stages feeding it: the run's command is awk or gawk, named bare or by a
 * system binary path (`trustedCommandName`), reached only through such wrappers that pass
 * their input straight through (not `xargs`, which turns it into arguments, nor a shell)
 * and carry no option -- an option of unknown arity could hide the real command
 * (`env --argv0 awk /bin/sh` runs sh) -- its whole program is inline, static and cannot
 * run input, and no process substitution could hand its output on to an interpreter.
 * No redirection may stand before the first operand: the scanner glues a quoted or empty
 * word onto a following operator (`-F '2'>/dev/null` and `-F ''>/dev/null` pass `2` and
 * the empty string to `-F`), so dropping one can drop an operand. Redirections after it
 * are dropped. No word through the first operand may expand, since an
 * expansion can shift which word awk takes as its program (`awk -F $(true) : '<prog>'`)
 * or add options after an `-e` program (`gawk -e 1 $opts`).
 */
function awkLeavesInputAsData(argv: string[]): boolean {
	if (argv.some((token) => PROCESS_SUBSTITUTION.test(token))) return false;
	const kept = redirectionFreeIndexes(argv);
	const words = kept.map((index) => argv[index]);
	const chain = executableCommandIndexes(words);
	const head = chain.at(-1);
	if (head === undefined || !AWK_HEADS.has(trustedCommandName(words[head]))) return false;
	for (let link = 0; link + 1 < chain.length; link++) {
		if (!INPUT_PRESERVING_WRAPPERS.has(trustedCommandName(words[chain[link]]))) return false;
		if (words.slice(chain[link] + 1, chain[link + 1]).some((word) => word.startsWith("-"))) return false;
	}
	const program = awkInlineProgram(words, head);
	if (!program.complete || kept.slice(0, program.end).some((index) => wordMayExpand(argv, index))) return false;
	if (kept[program.end - 1] !== program.end - 1) return false;
	return !program.fragments.some((fragment) => AWK_PROGRAM_RUNS_INPUT.test(fragment));
}

/** The `NAME` of an `alias NAME=value` operand. */
const ALIAS_DEFINITION = /^([^=]+)=/;

/**
 * The `alias NAME=value` operands of a run: each `NAME`, and its value as the shell stores it,
 * taken from the word as the command receives it (`RECEIVED_WORDS`), since bash re-reads the
 * value as shell text when it expands the alias. The `alias` is found in the run's
 * `redirectionFreeWords` (`>/dev/null alias cat=sh`).
 */
function aliasOperands(argv: string[]): { name: string; value: string }[] {
	const words = redirectionFreeWords(argv);
	if (!words.includes("alias")) return [];
	const aliasIndex = executableCommandIndexes(words).find((index) => words[index] === "alias");
	if (aliasIndex === undefined) return [];
	const received = RECEIVED_WORDS.get(words) ?? words;
	const operands: { name: string; value: string }[] = [];
	for (let k = aliasIndex + 1; k < words.length; k++) {
		const name = ALIAS_DEFINITION.exec(words[k])?.[1];
		if (name === undefined) continue;
		const word = received[k] ?? words[k];
		operands.push({ name, value: word.slice(word.indexOf("=") + 1) });
	}
	return operands;
}

/** Whether the run at `p` in `topLevel` is a function header: a word followed by an empty `()`. */
function isFunctionHeader(topLevel: readonly ShellTopLevelPart[], p: number): boolean {
	const next = topLevel[p + 1];
	const after = topLevel[p + 2];
	return next?.kind === "group" && next.boundary === "start" && after?.kind === "group" && after.boundary === "end";
}

/**
 * The command names a source defines as a function (`name() ...`, a word followed by an empty
 * `()`; `function name ...`) or an alias (`alias name=...`, `aliasOperands`), kept exactly as
 * spelled: bash accepts a path as a function name (`/usr/bin/cat() { sh; }`), so a trusted
 * spelling can be rebound too. A definition anywhere in the source counts, before or after a
 * use and in any group, which over-marks: the fail-closed direction.
 */
function definedCommandNames(topLevel: readonly ShellTopLevelPart[]): Set<string> {
	const names = new Set<string>();
	for (let p = 0; p < topLevel.length; p++) {
		const part = topLevel[p];
		if (part.kind !== "command" || part.argv.length === 0) continue;
		const { argv } = part;
		if (isFunctionHeader(topLevel, p)) names.add(argv[argv.length - 1]);
		const command = commandPositionIndex(argv);
		for (let k = 0; k < command && k + 1 < argv.length; k++) {
			if (argv[k] === "function") names.add(argv[k + 1]);
		}
		for (const { name } of aliasOperands(argv)) names.add(name);
	}
	return names;
}

/**
 * A nested source's text and how it is read: `gate` for a script bash runs, `prose` for
 * double-quoted text whose substitutions alone run.
 */
interface BodyScript {
	text: string;
	mode: "gate" | "prose";
}

/**
 * A run of a function body, with each of its nested sources that bash runs, or whose
 * substitutions it runs, when the run runs (`executedBodySources`).
 */
interface BodyRun {
	run: string[];
	sources: BodyScript[];
	/** The run calls a name the source defines (`definedCallIndex`), set once the body is kept. */
	calls?: boolean;
}

/**
 * What a source defines a command name to run: an alias's `value`, which bash re-reads as shell
 * text in place of the name (its lex kept once taken), or the runs of a function's `body`.
 */
type CommandDefinition = { kind: "alias"; value: string; lexed?: LexedSource } | { kind: "function"; body: BodyRun[] };

/**
 * Text that may start a positional-parameter reference in a run's word, to pass over a body run
 * that makes none; a double-quoted `*` is spelled `EXPANSION_SUPPRESSED`.
 */
const MAY_REFERENCE_POSITIONAL = /\$(?:[@*1-9\u0000]|\{[@*1-9!])/;

/** Whether a body run or one of its executed sources may reference a positional parameter. */
function bodyRunReferences({ run, sources }: BodyRun): boolean {
	return (
		redirectionFreeWords(run).some((word) => MAY_REFERENCE_POSITIONAL.test(word)) ||
		sources.some((source) => POSITIONAL_REFERENCE_START.test(source.text))
	);
}

/** A command or backtick substitution opening in text. */
const SUBSTITUTION_IN_TEXT = /\$\(|`/;

/**
 * The nested sources of a body run that the function's own shell runs, with the call's
 * operands as its positional parameters, when the run runs: every command, backtick and process
 * substitution; an `eval` or `trap` operand (`runsSourceInCurrentShell`: `eval 'rm -rf "$1"'`);
 * and an unquoted here-string or heredoc the run reads as a script (`hereStringReader`), each
 * read as a script. A double-quoted word holding a substitution is read as prose, so only its
 * substitutions run (`echo "$(rm "$@")"`). A here-string whose word holds no live expansion
 * (`receivedText`) or a heredoc with a quoted delimiter is left out: the shell it feeds expands
 * its text with positional parameters of its own.
 */
function executedBodySources(
	run: string[],
	sources: readonly NestedSource[],
	definedNames: ReadonlySet<string>,
): BodyScript[] {
	if (sources.length === 0) return [];
	const readsScript = hereStringReader(redirectionFreeWords(run), definedNames, false) === "script";
	const currentShell = runsSourceInCurrentShell(run);
	return sources.flatMap((inner): BodyScript[] => {
		const stdinScript =
			readsScript &&
			((inner.kind === "here-string" && inner.receivedText !== true) ||
				(inner.kind === "heredoc" && inner.quote !== "'"));
		const currentShellSource = currentShell && inner.kind === "argument-source";
		if (
			inner.kind === "command-substitution" ||
			inner.kind === "backtick" ||
			inner.kind === "process-substitution" ||
			stdinScript ||
			currentShellSource
		)
			return [{ text: inner.source, mode: "gate" }];
		if (inner.kind === "quoted-potential" && inner.quote === '"' && SUBSTITUTION_IN_TEXT.test(inner.source))
			return [{ text: inner.source, mode: "prose" }];
		return [];
	});
}

/**
 * What tells one body run from another as a call reads it: its words as spelled and as received,
 * which of them split (`SPLITTING_WORDS`, since `"$1"` and `$1` are spelled alike), and its
 * executed sources.
 */
function bodyRunKey({ run, sources }: BodyRun): unknown[] {
	const words = redirectionFreeWords(run);
	return [words, RECEIVED_WORDS.get(words) ?? null, [...(SPLITTING_WORDS.get(words) ?? [])], sources];
}

/**
 * The command names a tokenization's sources define (`definedCommandNames`), with what each
 * one runs where the source spells it out (`commandDefinitions`), so a call to one can be read
 * as the command it makes (`definitionCallRuns`).
 */
class DefinedCommands extends Set<string> {
	readonly definitions = new Map<string, CommandDefinition[]>();
	/**
	 * The runs written inside a function body. A definition runs nothing, so such a run is read
	 * as a call only when a call reaches its function (`definitionCallRuns`).
	 */
	readonly bodyRuns = new WeakSet<string[]>();
	private readonly kept = new Set<string>();

	/**
	 * Keep `definition` as one of what `name` runs. A function keeps only its body runs that may
	 * reference a positional parameter (`bodyRunReferences`) or call a name the source defines,
	 * since its other runs are read where the body stands, and one with neither is not kept; nor
	 * is a definition identical to one already kept (`bodyRunKey`), so a source repeating a
	 * definition costs its calls nothing more.
	 */
	define(name: string, definition: CommandDefinition): void {
		let kept = definition;
		if (definition.kind === "function") {
			for (const { run } of definition.body) this.bodyRuns.add(run);
			const body = definition.body.flatMap((bodyRun) => {
				const calls = definedCallIndex(redirectionFreeWords(bodyRun.run), this) !== undefined;
				return calls || bodyRunReferences(bodyRun) ? [{ ...bodyRun, calls }] : [];
			});
			if (body.length === 0) return;
			kept = { kind: "function", body };
		}
		const key = JSON.stringify([name, kept.kind === "alias" ? kept.value : kept.body.map(bodyRunKey)]);
		if (this.kept.has(key)) return;
		this.kept.add(key);
		const known = this.definitions.get(name);
		if (known === undefined) this.definitions.set(name, [kept]);
		else known.push(kept);
	}
}

/** How a compound command a function body may be was opened: by a `(` group or a reserved word. */
type CompoundOpener = "group" | "keyword";

/**
 * The aliases a source defines with their values (`aliasOperands`), and the functions it
 * defines with the runs of their bodies (`BodyRun`). A function's body is the compound command
 * after its header (`name ()`, `function name`): a `{ ...; }` group, a `( ... )` subshell, or
 * an `if`, `case` or loop, delimited by the reserved words in each run's bare leading words and
 * by parenthesis groups, so the runs of a body nested inside it belong to the inner function
 * only. A `)` with no `(` open inside the compound, as a `case` arm ends with, closes nothing.
 * A header followed by a simple command takes that command as its body, as zsh reads
 * `f() rm "$@"` and `function f rm "$@"`.
 */
function commandDefinitions(lexed: LexedSource, definedNames: ReadonlySet<string>): [string, CommandDefinition][] {
	const { topLevel, bareLeadingWords } = lexed;
	const found: [string, CommandDefinition][] = [];
	const openers: CompoundOpener[] = [];
	const bodies: { body: BodyRun[]; depth: number }[] = [];
	const sourcesByRun = nestedSourcesByRun(lexed.nestedSources);
	let pending: string | undefined;
	const open = (opener: CompoundOpener): void => {
		openers.push(opener);
		if (pending === undefined) return;
		const body: BodyRun[] = [];
		bodies.push({ body, depth: openers.length });
		found.push([pending, { kind: "function", body }]);
		pending = undefined;
	};
	const close = (opener: CompoundOpener): void => {
		if (openers.at(-1) !== opener) return;
		openers.pop();
		while ((bodies.at(-1)?.depth ?? 0) > openers.length) bodies.pop();
	};
	for (let p = 0; p < topLevel.length; p++) {
		const part = topLevel[p];
		if (part.kind === "operator") continue;
		if (part.kind === "group") {
			if (part.boundary === "start") open("group");
			else close("group");
			continue;
		}
		const { argv } = part;
		for (const { name, value } of aliasOperands(argv)) found.push([name, { kind: "alias", value }]);
		const wasPending = pending;
		const bare = bareLeadingWords.get(argv) ?? 0;
		let namedHere = false;
		let commandFollows = false;
		for (let k = 0; k < bare; k++) {
			const word = argv[k];
			if (COMPOUND_OPENERS.has(word)) open("keyword");
			else if (COMPOUND_CLOSERS.has(word)) close("keyword");
			else if (word === "function" && k + 1 < argv.length) {
				pending = argv[++k];
				namedHere = true;
			} else if (!COMMAND_PREFIX_WORDS.has(word)) {
				commandFollows = true;
				break;
			}
		}
		const bareBodyOf =
			wasPending !== undefined && pending === wasPending
				? wasPending
				: namedHere && commandFollows && pending !== undefined
					? pending
					: undefined;
		if (bodies.length > 0 || bareBodyOf !== undefined) {
			const bodyRun: BodyRun = {
				run: argv,
				sources: executedBodySources(argv, sourcesByRun.get(argv) ?? [], definedNames),
			};
			bodies.at(-1)?.body.push(bodyRun);
			if (bareBodyOf !== undefined) found.push([bareBodyOf, { kind: "function", body: [bodyRun] }]);
		}
		if (bareBodyOf !== undefined) pending = undefined;
		if (isFunctionHeader(topLevel, p)) {
			pending = argv[argv.length - 1];
			p += 2;
		}
	}
	return found;
}

/**
 * Heads whose string operand the current shell runs itself, so the functions and aliases it
 * defines stay live for the rest of the command: `eval`, and a `trap` handler (a `DEBUG` trap
 * runs before the very next command). Every other executable argument source (`bash -c`,
 * `su -c`, `env -S`) runs in a child process whose definitions die with it.
 */
const CURRENT_SHELL_SOURCE_HEADS = new Set(["eval", "trap"]);

/** Whether a run's command or one of its wrappers is a `CURRENT_SHELL_SOURCE_HEADS` head. */
function runsSourceInCurrentShell(run: string[]): boolean {
	const words = redirectionFreeWords(run);
	return executableCommandIndexes(words).some((index) => CURRENT_SHELL_SOURCE_HEADS.has(headBase(words[index])));
}

/**
 * Add to `definedNames` the command names `lexed` defines (`definedCommandNames`) and those its
 * `eval` and `trap` operands define (`runsSourceInCurrentShell`), at any depth, so the pipeline
 * walk that follows already knows them: `eval 'cat() { sh; }'; echo '...' | cat` rebinds the
 * sink before bash reaches it. What each one runs (`commandDefinitions`) is added alongside,
 * once the operands' names are known, since a body's here-string may feed one of them.
 * Each source is read once per set (`definitionsRead`), so
 * nested operands, whose analysis calls this again, stay linear. An operand not yet lexed is
 * charged to `lookahead`; false when that ran out before every operand was read, so the walk
 * cannot know every name a sink may be rebound to.
 */
function collectDefinedNames(lexed: LexedSource, definedNames: DefinedCommands, lookahead: { left: number }): boolean {
	const kept = lexed.definitionsRead;
	if (kept?.into === definedNames) return kept.read;
	const verdict = { into: definedNames, read: true };
	lexed.definitionsRead = verdict;
	for (const name of definedCommandNames(lexed.topLevel)) definedNames.add(name);
	let read = true;
	const currentShellRuns = new Map<string[], boolean>();
	for (const inner of lexed.nestedSources) {
		if (inner.kind !== "argument-source" || inner.run === undefined) continue;
		const currentShell = currentShellRuns.get(inner.run) ?? runsSourceInCurrentShell(inner.run);
		currentShellRuns.set(inner.run, currentShell);
		if (!currentShell) continue;
		if (inner.lexed === undefined) {
			if (lookahead.left <= 0) {
				read = false;
				continue;
			}
			lookahead.left -= nestedSourceCost(inner.source);
		}
		read = collectDefinedNames(lexedNestedSource(inner, lookahead), definedNames, lookahead) && read;
	}
	for (const [name, definition] of commandDefinitions(lexed, definedNames)) definedNames.define(name, definition);
	verdict.read = read;
	return read;
}

/** How many `env -S` strings one run is unfolded through before it counts as rebound. */
const MAX_ENV_SPLITS = 16;

/**
 * The run with its first `env -S` string, separate (`-S 'a b'`) or attached (`-S'a b'`,
 * `--split-string=...`), replaced by the words it splits into, which env goes on parsing as
 * its own arguments (`env -S '-- /tmp/cat'`, `env -S 'env -i' /tmp/cat`); undefined when no
 * link of the run's command `chain` (`executableCommandIndexes`) behind an `env` is one. Only
 * the split string env's own walk reaches (`envCommandTarget`) counts, so an option value
 * spelled `-S` (`env -u -S /tmp/cat`) stays a value.
 */
function unfoldEnvSplit(argv: string[], chain: readonly number[]): string[] | undefined {
	for (let link = 1; link < chain.length; link++) {
		if (headBase(argv[chain[link - 1]]) !== "env") continue;
		const target = envCommandTarget(argv, chain[link - 1]);
		switch (target.kind) {
			case "word":
				continue;
			case "split-next":
				return [
					...argv.slice(0, target.index - 1),
					...splitEnvString(argv[target.index]),
					...argv.slice(target.index + 1),
				];
			case "split-attached":
				return [...argv.slice(0, target.index), ...splitEnvString(target.source), ...argv.slice(target.index + 1)];
		}
	}
	return undefined;
}

/**
 * `argv` with every `env -S` string its command chain reaches unfolded into env's own
 * arguments, one after another (`unfoldEnvSplit`): `env -iS'sh -s'` reads as `env sh -s`.
 * Undefined when that takes more than `MAX_ENV_SPLITS` unfoldings.
 */
function unfoldEnvSplits(argv: string[]): string[] | undefined {
	let unfolded = argv;
	for (let splits = 0; ; splits++) {
		const next = unfoldEnvSplit(unfolded, executableCommandIndexes(unfolded));
		if (next === undefined) return unfolded;
		if (splits === MAX_ENV_SPLITS) return undefined;
		unfolded = next;
	}
}

/**
 * A run's redirection-free words with their `env -S` strings unfolded (`unfoldEnvSplits`),
 * when the run has one and the unfolded reading runs its quoted arguments
 * (`runsQuotedArguments`): the interpreter can sit inside a split string (`env -Ssh`,
 * `env -iS'sh -s'`). Undefined otherwise, including a run with more split strings than
 * `unfoldEnvSplits` unfolds, which `rebindsCommandName` counts as rebound behind a pipe.
 */
function envSplitSinkWords(commandWords: string[]): string[] | undefined {
	const unfolded = unfoldEnvSplits(commandWords);
	return unfolded !== undefined && unfolded !== commandWords && runsQuotedArguments(unfolded) ? unfolded : undefined;
}

/**
 * Whether a run's name may not mean the program it usually does, so what is piped into it
 * can reach a shell. `commandWords` are the run's words with its redirections removed, as the
 * tokenizer recorded them (`>out cat` runs `cat`; `env -u '2'>x cmd` keeps `2` as `-u`'s
 * operand). A command or wrapper -- inside the string an `env -S` splits, too -- is named by a
 * path outside the system binary directories (`/tmp/cat` may be a symlink to `sh`), by a name
 * the source defines as a function or alias (`definedCommandNames`), or by a word that can
 * expand into another name (`UNSTABLE_WORD`: `$x`, `c*t`); or a word in front of its command
 * position is a defined name, since a quoted keyword (`'time'`, `\time`) arrives dequoted yet
 * names a command. `env -S` strings are unfolded into env's own arguments first
 * (`unfoldEnvSplits`); a run needing more than `MAX_ENV_SPLITS` of them counts as rebound.
 */
function rebindsCommandName(commandWords: string[], definedNames: ReadonlySet<string>): boolean {
	const argv = unfoldEnvSplits(commandWords);
	if (argv === undefined || namesDefinedCommand(argv, definedNames)) return true;
	return executableCommandIndexes(argv).some(
		(index) => UNSTABLE_WORD.test(argv[index]) || namedByUntrustedPath(argv[index]),
	);
}

/**
 * Exec wrappers that do not pass the run's stdin on to the command they run: `xargs` reads it
 * for the command's arguments and gives the command `/dev/null`.
 */
const STDIN_WITHHOLDING_WRAPPERS = new Set(["xargs"]);

/**
 * What a here-string's reader makes of its text: `script` for a shell that parses it as a
 * command line of its own, `program` for Python reading its program from it, `data` for
 * anything else.
 */
type HereStringReader = "data" | "script" | "program";

/**
 * The reading of two that covers the other: a program is read as an executing payload, which
 * emits every run the script reading does and the quoted words besides.
 */
function widerReader(a: HereStringReader, b: HereStringReader): HereStringReader {
	if (a === "program" || b === "program") return "program";
	return a === "script" || b === "script" ? "script" : "data";
}

/**
 * How a run reads the here-string it is fed: as a `script` when a command of its chain
 * (`executableCommandIndexes`), behind any wrapper and inside any `env -S` string, is a shell
 * that reads its script from standard input (`shellScriptOperand`), or a name that may not mean
 * the program it usually does (`rebindsCommandName`), the test a pipe sink passes too; as a
 * `program` when that command is Python reading its program from standard input
 * (`pythonReadsStdinProgram`). Every run reads a script when an `eval` or `trap` operand could
 * not be read for its definitions (`definitionsUnread`), as every pipe sink does. A command that
 * reads its stdin as data (`cat <<< '...'`) reads `data`, as does a shell behind a wrapper that
 * withholds the run's stdin from its command (`STDIN_WITHHOLDING_WRAPPERS`).
 */
function hereStringReader(
	commandWords: string[],
	definedNames: ReadonlySet<string>,
	definitionsUnread: boolean,
): HereStringReader {
	if (definitionsUnread || rebindsCommandName(commandWords, definedNames)) return "script";
	const words = unfoldEnvSplits(commandWords) ?? commandWords;
	for (const index of executableCommandIndexes(words)) {
		const base = headBase(words[index]);
		if (STDIN_WITHHOLDING_WRAPPERS.has(base)) return "data";
		if (SHELL_SOURCE_HEADS.has(base) && shellScriptOperand(words, index).stdin) return "script";
		if (PYTHON_HEAD.test(base) && pythonReadsStdinProgram(words, index)) return "program";
	}
	return "data";
}

/** Python long options that take the next word as their value. */
const PYTHON_VALUE_LONG_OPTIONS = new Set(["--check-hash-based-pycs"]);

/**
 * Whether the Python at `argv[index]` reads its program from standard input: its options give
 * no `-c` program and no `-m` module, and no script operand follows them other than `-` or a
 * path naming standard input itself (`STDIN_SCRIPT_PATHS`: `python3 /dev/stdin`); or
 * they ask for interactive mode (`-i`), which reads statements from standard input after any
 * script or `-c` program has run. `-W` and `-X` take the rest of their word or the next word as
 * their value. Redirections are skipped with their destinations.
 */
function pythonReadsStdinProgram(argv: string[], index: number): boolean {
	const words = redirectionFreeIndexes(argv).filter((i) => i > index);
	for (let k = 0; k < words.length; k++) {
		const word = argv[words[k]];
		if (word === "-") return true;
		if (word === "--")
			return k + 1 >= words.length || argv[words[k + 1]] === "-" || STDIN_SCRIPT_PATHS.has(argv[words[k + 1]]);
		if (word.startsWith("--")) {
			if (PYTHON_VALUE_LONG_OPTIONS.has(word)) k += 1;
			continue;
		}
		if (!/^-[A-Za-z]/.test(word)) return STDIN_SCRIPT_PATHS.has(word);
		for (let c = 1; c < word.length; c++) {
			const letter = word[c];
			if (letter === "i") return true;
			if (letter === "c" || letter === "m") return false;
			if (letter === "W" || letter === "X") {
				if (c === word.length - 1) k += 1;
				break;
			}
		}
	}
	return true;
}

/**
 * The reader of each here-string that redirects a compound command rather than a command of
 * its own, keyed by the run carrying it. bash applies a redirection written after a group's
 * closer to the whole compound (`(bash) <<< '...'`, `{ bash; } <<< '...'`, `done <<< '...'`),
 * so its text reaches every command inside, and it is read the widest way any of them reads it
 * (`ownReader`). Parens arrive as group parts and every other compound as keywords in a run's
 * bare leading words, counted on one stack as the pipe-chain walk in `analyzeLexed` counts them.
 * A closer with nothing open closes everything read so far in the frame, and a `)` ending a
 * `case` arm closes the compound around it early: both widen what the text reaches, the
 * fail-closed direction.
 */
function compoundHereStringReaders(
	topLevel: readonly ShellTopLevelPart[],
	bareLeadingWords: ReadonlyMap<string[], number>,
	ownReader: (run: string[]) => HereStringReader,
): Map<string[], HereStringReader> {
	const readers = new Map<string[], HereStringReader>();
	const frames: HereStringReader[] = ["data"];
	const widenTop = (reader: HereStringReader): void => {
		frames[frames.length - 1] = widerReader(frames[frames.length - 1], reader);
	};
	const close = (): HereStringReader => {
		const closed = frames.length > 1 ? (frames.pop() as HereStringReader) : frames[0];
		widenTop(closed);
		return closed;
	};
	let justClosed: HereStringReader | undefined;
	for (const part of topLevel) {
		if (part.kind === "group") {
			if (part.boundary === "start") frames.push("data");
			justClosed = part.boundary === "end" ? close() : undefined;
			continue;
		}
		if (part.kind === "operator") {
			justClosed = undefined;
			continue;
		}
		const { argv } = part;
		let closed = justClosed;
		justClosed = undefined;
		let closers = 0;
		const bare = bareLeadingWords.get(argv) ?? 0;
		for (let k = 0; k < bare; k++) {
			if (COMPOUND_CLOSERS.has(argv[k])) {
				closed = close();
				closers += 1;
			} else if (COMPOUND_OPENERS.has(argv[k])) {
				frames.push("data");
				closed = undefined;
			} else break;
		}
		if (closed !== undefined && redirectionFreeWords(argv).length === closers) readers.set(argv, closed);
		widenTop(ownReader(argv));
	}
	return readers;
}

/**
 * The index of the word by which a run calls a name `defined` holds: a word in front of its
 * command position, since a quoted keyword (`'time'`, `\time`) arrives dequoted yet names a
 * command, else its command or one of its wrappers (`executableCommandIndexes`). The name a
 * `function NAME { ...; }` header defines is not one: that run defines it without calling it.
 * Undefined when the run calls none.
 */
function definedCallIndex(argv: string[], defined: { has(name: string): boolean }): number | undefined {
	const command = commandPositionIndex(argv);
	for (let k = 0; k < command; k++) {
		if (defined.has(argv[k]) && argv[k - 1] !== "function") return k;
	}
	return executableCommandIndexes(argv).find((index) => defined.has(argv[index]));
}

/**
 * Whether a run calls a name the source defines as a function or alias (`definedCommandNames`),
 * as `definedCallIndex` finds such a call.
 */
function namesDefinedCommand(argv: string[], definedNames: ReadonlySet<string>): boolean {
	return definedCallIndex(argv, definedNames) !== undefined;
}

/** How many defined-name calls in one run are followed one at a time before the rest is read at once. */
const MAX_DEFINED_CALLS = 4;

/**
 * The runs a call to a function or alias the source defines (`definedCommandNames`) may make
 * of its operands. The floor does not follow the body, which may run them as a command
 * (`f() { "$@"; }; f sed ...`, `alias f=command; f sed ...`), so the words after a defined name
 * in the run's command chain (`executableCommandIndexes`) are read as a run of their own, as a
 * wrapper's command operand is, and so on through each defined name that run's chain reaches
 * in turn (`f sudo g sed ...`). A run whose own command is again a defined name is not kept,
 * since the run after it covers the command it reaches. Operands naming no denied command stay
 * allowed (`log info started`). Past `MAX_DEFINED_CALLS` calls, the rest of the run is read
 * once more with every defined name dropped, so a long chain of calls stays linear yet still
 * exposes the command at its end. `argv` is the run's redirection-free words.
 */
function definedCallOperandRuns(argv: string[], definedNames: ReadonlySet<string>): string[][] {
	const runs: string[][] = [];
	let words = argv;
	for (let calls = 0; ; calls++) {
		const current = words;
		const chain = executableCommandIndexes(current);
		if (calls > 0 && chain.length > 0 && !definedNames.has(current[chain[0]])) runs.push(current);
		const index = chain.find((i) => definedNames.has(current[i]));
		if (index === undefined || index + 1 >= current.length) return runs;
		if (calls === MAX_DEFINED_CALLS) {
			const rest = current.slice(index + 1).filter((word) => !definedNames.has(word));
			if (rest.length > 0) runs.push(rest);
			return runs;
		}
		words = current.slice(index + 1);
	}
}

/** How many alias or function expansions deep one call is followed before it counts as unread. */
const MAX_DEFINITION_DEPTH = 8;

/** How many times over a function's scripts are read inside one another before it counts as read. */
const MAX_RECURSIVE_READS = 2;

/** Every `EXPANSION_SUPPRESSED` character in a word. */
const SUPPRESSED_CHARACTERS = new RegExp(EXPANSION_SUPPRESSED, "g");

/**
 * A positional-parameter reference in a function body's word, from `at` up to `end`, and the
 * call operands it names: a `list` (operands `from` up to `to`) for `$@`, `$*`, their slices, and
 * a form that may name any of them, `star` for the `$*` spellings; `one` operand for `$N`; or
 * `none` for the `${N+` opening and closing `}` of an alternate-value form, which leave the word
 * between them in its place.
 */
interface BodyReference {
	at: number;
	end: number;
	names: { kind: "list"; from: number; to: number; star: boolean } | { kind: "one"; index: number } | { kind: "none" };
}

/** The opening of an alternate-value form of a positional parameter: `${1+`, `${1:+`, `${@+`. */
const ALTERNATE_POSITIONAL_REFERENCE = /\$\{(?:[0-9]+|[@*]):?\+/y;

/**
 * A substring expansion of a numbered positional parameter, `${1:0}`, `${1: -3}`, `${1:0:9}`:
 * a colon not starting a default, assignment, error or alternate form.
 */
const SUBSTRING_POSITIONAL_REFERENCE = /\$\{([1-9][0-9]*):(?![-=?+])/y;

/** The opening of a default or assignment form of a positional parameter: `${1:-`, `${@=`. */
const DEFAULTED_POSITIONAL_REFERENCE = /\$\{(?:[0-9]+|[@*]):?[-=]/y;

/**
 * The positional-parameter references in `word`, in order, read as `readPositionalReference`
 * reads a script's: a default or assignment form names its parameter, and an operator whose
 * value is not the parameter's text (`${1%.x}`) is none. An alternate-value form (`${@+"$@"}`,
 * `${1:+--force}`) is read as its word, as if the parameter were set, the fail-closed direction; a
 * substring of a numbered parameter (`${1:0}`) is read as the whole parameter;
 * and a default or assignment form whose parameter the call leaves unset (or empty, for a colon
 * form) as its default word.
 * `$0` names the shell rather than an operand and `$$` is the shell's process id, so neither is
 * one. `operands` are the call's operands; a reference at or past one whose word count may vary
 * (`wordCountMayVary`: `$(true)`, `{a,b}`) may land on any operand from that one on, so it names
 * all of them, as `spliceShellParameters` reads a shell -c script's.
 */
function bodyReferences(word: string, operands: readonly string[]): BodyReference[] {
	const count = operands.length;
	const varies = operands.findIndex((_, j) => operandCountMayVary(operands, j));
	const shifted = (index: number): boolean => varies !== -1 && varies <= index;
	const found: BodyReference[] = [];
	const braceEnd = braceEndReader(word, () => {});
	for (let i = 0; i < word.length; i++) {
		if (word[i] !== "$") continue;
		if (word[i + 1] === "$") {
			i += 1;
			continue;
		}
		ALTERNATE_POSITIONAL_REFERENCE.lastIndex = i;
		const alternate = ALTERNATE_POSITIONAL_REFERENCE.exec(word);
		const close = alternate === null ? undefined : braceEnd(i);
		if (alternate !== null && close !== undefined) {
			found.push({ at: i, end: ALTERNATE_POSITIONAL_REFERENCE.lastIndex, names: { kind: "none" } });
			found.push({ at: close, end: close + 1, names: { kind: "none" } });
			i = ALTERNATE_POSITIONAL_REFERENCE.lastIndex - 1;
			continue;
		}
		SUBSTRING_POSITIONAL_REFERENCE.lastIndex = i;
		const substring = SUBSTRING_POSITIONAL_REFERENCE.exec(word);
		const substringEnd = substring === null ? undefined : braceEnd(i);
		if (substring !== null && substringEnd !== undefined) {
			const index = Number(substring[1]) - 1;
			found.push({
				at: i,
				end: substringEnd + 1,
				names: shifted(index) ? { kind: "list", from: varies, to: count, star: false } : { kind: "one", index },
			});
			i = substringEnd;
			continue;
		}
		const reference = readPositionalReference(word, i, braceEnd);
		if (reference === undefined) continue;
		const { target } = reference;
		const at = i;
		const unset =
			target.kind === "index"
				? (target.index > count && !shifted(count)) ||
					(reference.defaulted?.colon === true && operands[target.index - 1] === "")
				: target.kind === "all" && count === 0;
		DEFAULTED_POSITIONAL_REFERENCE.lastIndex = i;
		if (unset && reference.defaulted !== undefined && DEFAULTED_POSITIONAL_REFERENCE.test(word)) {
			found.push({ at, end: DEFAULTED_POSITIONAL_REFERENCE.lastIndex, names: { kind: "none" } });
			found.push({ at: reference.end - 1, end: reference.end, names: { kind: "none" } });
			i = DEFAULTED_POSITIONAL_REFERENCE.lastIndex - 1;
			continue;
		}
		i = reference.end - 1;
		if (target.kind === "index") {
			if (target.index === 0) continue;
			const index = target.index - 1;
			found.push({
				at,
				end: reference.end,
				names: shifted(index) ? { kind: "list", from: varies, to: count, star: false } : { kind: "one", index },
			});
			continue;
		}
		let from = target.kind === "slice" ? Math.max(target.from - 1, 0) : 0;
		let to = target.kind === "slice" && target.length !== undefined ? Math.min(from + target.length, count) : count;
		if (target.kind === "slice" && shifted(Math.max(from, to - 1))) {
			from = Math.min(varies, from);
			to = count;
		}
		found.push({ at, end: reference.end, names: { kind: "list", from, to: Math.max(from, to), star: target.star } });
	}
	return found.sort((a, b) => a.at - b.at);
}

/**
 * Whether the call operand at `index` of `words` may expand to no word or several
 * (`wordCountMayVary`). An operand that is one arithmetic expansion (`$((n-1))`) expands to one
 * number, so it counts as one word.
 */
function operandCountMayVary(words: readonly string[], index: number): boolean {
	const word = words[index];
	if (word.startsWith("$((") && isArithmetic(word, 0) && readSubstitution(word, 0).end === word.length) return false;
	return wordCountMayVary(words as string[], index);
}

/**
 * A run an alias or function call is read as: its `words` as the argv spells them, the same
 * words as the command receives them (`received`, see `RECEIVED_WORDS`), whether each came from
 * the call (`fromCall`: the words written around the defined name) rather than from the
 * definition's own text, and `expandNext`, the index of the word after an alias value that ends
 * in a blank, which bash alias-expands too (`alias sudo='sudo '; sudo g ...`), and `scripts`, the
 * texts of the body run's executed sources with the call's operands spliced in.
 */
interface FormedRun {
	words: string[];
	received: string[];
	fromCall: boolean[];
	expandNext?: number;
	scripts?: BodyScript[];
	/** The name of the definition whose expansion formed the run. */
	formedBy?: string;
}

/** A tokenized run's words as a formed run, each with the same `fromCall`. */
function formedFrom(words: string[], fromCall: boolean): FormedRun {
	return { words, received: [...(RECEIVED_WORDS.get(words) ?? words)], fromCall: words.map(() => fromCall) };
}

/**
 * What splicing a call's operands into a function body's run gives: `unreferenced` when the run
 * makes no positional-parameter reference, `spliced` with the run formed, or `over-budget` when
 * the run formed would outgrow the budget left, so it is never built.
 */
type SplicedRun = { kind: "unreferenced" } | { kind: "spliced"; run: FormedRun } | { kind: "over-budget" };

/**
 * `spelled` with each quote-suppressed `*` whose character in `received` (the same word as the
 * command receives it) is a `*` turned live again, as it is once an unquoted expansion hands it
 * on to pathname expansion; a tilde or brace stays suppressed, since bash expands neither in an
 * expansion's value.
 */
function globsLive(spelled: string, received: string): string {
	if (received.length !== spelled.length) return spelled;
	return spelled.replace(SUPPRESSED_CHARACTERS, (c, at: number) => (received[at] === "*" ? "*" : c));
}

/** A blank the shell splits an unquoted expansion's value at. */
const FIELD_BLANKS = /[ \t\n]+/;

/**
 * A function body's run with the call's `operands` spliced in for its positional-parameter
 * references (`bodyReferences`), as bash expands them, so `rm "$@"` called as `f -rf /` reads
 * as `rm -rf /`: `$@`, and `$*` outside quotes, give one field per operand, the text before the
 * reference joining the first and the text after it the last (`-$@` called as `f rf /` gives
 * `-rf /`); a double-quoted `$*` joins the operands into one field; `$N` gives that operand, or
 * nothing when the call has fewer; a slice (`${@:2}`) gives the operands it names. In a word
 * written with an unquoted expansion (`SPLITTING_WORDS`) each operand is split at blanks
 * (`git $1` called as `f 'push --force'`), the word's own text left whole, and a `*` the call
 * quoted turns live again, as bash globs an unquoted expansion's value (`rm -r $1` called as
 * `f '/*'`). Double quotes spell `*`, `{` and `}` as `EXPANSION_SUPPRESSED`, so references are
 * found in the word as the command receives it, while a `$` quotes suppress stays literal
 * (`'$@'`); the text around a reference keeps its own spelling. A field that is exactly one
 * operand keeps that operand's `fromCall`; any other with an operand in it counts as from the
 * call. Each word's size is weighed against `limit` characters before it is built, since every
 * reference repeats the operands.
 */
function spliceBodyRun(run: string[], operands: FormedRun, limit: number): SplicedRun {
	const words = redirectionFreeWords(run);
	const received = RECEIVED_WORDS.get(words);
	const splitting = SPLITTING_WORDS.get(words);
	const out: FormedRun = { words: [], received: [], fromCall: [] };
	const listText = operands.words.join(" ");
	let size = 0;
	let spliced = false;
	for (let k = 0; k < words.length; k++) {
		const spelled = words[k];
		const aligned = received?.[k] !== undefined && received[k].length === spelled.length;
		const heard = aligned ? received[k] : spelled;
		const probe = aligned
			? spelled.replace(SUPPRESSED_CHARACTERS, (c, at: number) => (heard[at] === "$" ? c : heard[at]))
			: spelled;
		const references = probe.includes("$") ? bodyReferences(probe, operands.words) : [];
		size += probe.length + 1 + references.length * (listText.length + operands.words.length);
		if (size > limit) return { kind: "over-budget" };
		if (references.length === 0) {
			out.words.push(spelled);
			out.received.push(received?.[k] ?? spelled);
			out.fromCall.push(false);
			continue;
		}
		spliced = true;
		const split = splitting?.has(k) === true;
		type Field = { spelled: string; heard: string; sole: number | undefined; mixed: boolean };
		const fields: Field[] = [];
		let field: Field = { spelled: "", heard: "", sole: undefined, mixed: false };
		const addText = (spelledText: string, heardText: string): void => {
			if (spelledText.length === 0) return;
			field.spelled += spelledText;
			field.heard += heardText;
			field.mixed = true;
		};
		const addOperand = (j: number): void => {
			const spelledPieces = split
				? globsLive(operands.words[j], operands.received[j]).split(FIELD_BLANKS)
				: [operands.words[j]];
			const heardPieces = !split
				? [operands.received[j]]
				: operands.received[j].length === operands.words[j].length
					? operands.received[j].split(FIELD_BLANKS)
					: spelledPieces;
			spelledPieces.forEach((piece, p) => {
				if (p > 0) {
					fields.push(field);
					field = { spelled: "", heard: "", sole: undefined, mixed: false };
				}
				if (field.spelled.length === 0 && field.sole === undefined && !field.mixed) field.sole = j;
				else field.mixed = true;
				field.spelled += piece;
				field.heard += heardPieces[p] ?? piece;
			});
		};
		let last = 0;
		let listOnly = true;
		let empty = true;
		for (const { at, end, names } of references) {
			addText(spelled.slice(last, at), heard.slice(last, at));
			if (at > last) listOnly = false;
			last = end;
			if (names.kind === "none") continue;
			if (names.kind === "one") {
				listOnly = false;
				if (names.index < operands.words.length) addOperand(names.index);
				continue;
			}
			if (names.star && !split) {
				listOnly = false;
				addText(
					operands.words.slice(names.from, names.to).join(" "),
					operands.received.slice(names.from, names.to).join(" "),
				);
				continue;
			}
			for (let j = names.from; j < names.to; j++) {
				if (j > names.from) {
					fields.push(field);
					field = { spelled: "", heard: "", sole: undefined, mixed: false };
				}
				addOperand(j);
				empty = false;
			}
		}
		addText(spelled.slice(last), heard.slice(last));
		if (last < spelled.length) listOnly = false;
		if (!(listOnly && empty)) fields.push(field);
		for (const { spelled: fieldSpelled, heard: fieldHeard, sole, mixed } of fields) {
			if (split && fieldSpelled.length === 0) continue;
			out.words.push(fieldSpelled);
			out.received.push(fieldHeard);
			out.fromCall.push(sole !== undefined && !mixed ? operands.fromCall[sole] : true);
		}
	}
	return spliced ? { kind: "spliced", run: out } : { kind: "unreferenced" };
}

/** An alias value whose last character is a blank, after which bash alias-expands the next word too. */
const BLANK_ENDED = /[ \t]$/;

/**
 * The runs a function `body` makes of a call with `operands`, each body run read with them
 * spliced in (`spliceBodyRun`) and so each script the run executes (`spliceShellParameters`, as
 * a shell -c script is: `f() { echo "$(rm "$@")"; }`), all of them together weighed against
 * `limit` characters as they are built. Undefined when they would outgrow it; otherwise the
 * runs formed and what is left of the limit.
 */
function functionRuns(
	body: readonly BodyRun[],
	operands: FormedRun,
	limit: number,
): { formed: FormedRun[]; left: number } | undefined {
	const parameters: ShellParameter[] = [
		{ text: "", spelled: "", wordCount: "one" },
		...operands.words.map(
			(spelled, j): ShellParameter => ({
				text: operands.received[j],
				spelled,
				wordCount: operandCountMayVary(operands.words, j) ? "varies" : "one",
			}),
		),
	];
	const formed: FormedRun[] = [];
	let left = limit;
	for (const { run, sources, calls } of body) {
		const spliced = spliceBodyRun(run, operands, left);
		if (spliced.kind === "over-budget") return undefined;
		const scripts: BodyScript[] = [];
		for (const { text, mode } of sources) {
			const script = spliceShellParameters(text, parameters, left);
			if (script.kind === "over-budget") return undefined;
			if (script.kind === "spliced") scripts.push(...script.texts.map((spliced) => ({ text: spliced, mode })));
		}
		if (spliced.kind === "unreferenced" && scripts.length === 0 && calls !== true) continue;
		const bodyFormed = spliced.kind === "spliced" ? spliced.run : formedFrom(redirectionFreeWords(run), false);
		formed.push(scripts.length === 0 ? bodyFormed : { ...bodyFormed, scripts });
		left -= bodyFormed.words.reduce((size, word) => size + word.length + 1, 0);
		left -= scripts.reduce((size, script) => size + script.text.length, 0);
		if (left <= 0) return undefined;
	}
	return { formed, left };
}

/**
 * The runs one `definition` makes of a call written with `before` in front of the defined name
 * and `operands` after it. An alias is text bash puts in place of the name, so the words before
 * it lead the value's first command and the operands trail its last one (`alias g=git; g push
 * --force` runs `git push --force`, `alias f='cd /; rm'; f -rf /` runs `rm -rf /`), with the first
 * operand marked for expansion when the value ends in a blank or holds no command
 * (`expandNext`). A value ending on an operator (`alias r='true;'`) leaves the operands a
 * command of their own, read as a run whose first word may name any definition. The value is lexed
 * once, charged to `budget`. A function runs its body with the operands (`functionRuns`), and
 * again without the operands whose word count may vary (`wordCountMayVary`), since each may
 * expand to nothing (`f $(true)` leaves `${9:-/}` its default). Undefined when the runs formed
 * would outgrow the budget.
 */
function definitionRuns(
	definition: CommandDefinition,
	before: FormedRun,
	operands: FormedRun,
	budget: { left: number },
): FormedRun[] | undefined {
	if (definition.kind === "function") {
		const varying = operands.words.map((_, j) => operandCountMayVary(operands.words, j));
		const readings = [operands];
		if (varying.includes(true)) {
			const kept = operands.words.flatMap((_, j) => (varying[j] ? [] : [j]));
			readings.push({
				words: kept.map((j) => operands.words[j]),
				received: kept.map((j) => operands.received[j]),
				fromCall: kept.map((j) => operands.fromCall[j]),
			});
		}
		const formed: FormedRun[] = [];
		let left = budget.left;
		for (const reading of readings) {
			const read = functionRuns(definition.body, reading, left);
			if (read === undefined) return undefined;
			formed.push(...read.formed);
			left = read.left;
		}
		return formed;
	}
	if (definition.lexed === undefined) {
		budget.left -= nestedSourceCost(definition.value);
		definition.lexed = lexSource(definition.value, budget, false);
	}
	const { topLevel } = definition.lexed;
	const commands = topLevel.flatMap((part) => (part.kind === "command" ? [redirectionFreeWords(part.argv)] : []));
	const hasOperands = operands.words.length > 0;
	if (commands.length === 0)
		return [{ ...joinFormed(before, operands), ...(hasOperands ? { expandNext: before.words.length } : {}) }];
	const endsOnCommand = topLevel.at(-1)?.kind === "command";
	const none: FormedRun = { words: [], received: [], fromCall: [] };
	const formedRuns = commands.map((words, k) => {
		const last = k === commands.length - 1 && endsOnCommand;
		const formed = joinFormed(k === 0 ? before : none, formedFrom(words, false));
		if (!last) return formed;
		const expandNext = BLANK_ENDED.test(definition.value) && hasOperands ? formed.words.length : undefined;
		return { ...joinFormed(formed, operands), ...(expandNext === undefined ? {} : { expandNext }) };
	});
	if (!endsOnCommand && hasOperands)
		formedRuns.push({ ...operands, fromCall: operands.fromCall.map((fromCall, j) => j > 0 && fromCall) });
	return formedRuns;
}

/** The formed runs `parts` laid end to end. */
function joinFormed(...parts: FormedRun[]): FormedRun {
	return {
		words: parts.flatMap((part) => part.words),
		received: parts.flatMap((part) => part.received),
		fromCall: parts.flatMap((part) => part.fromCall),
	};
}

/** The words of `run` from `start` up to `end`, with how each is received and where it came from. */
function sliceFormed(run: FormedRun, start: number, end?: number): FormedRun {
	return {
		words: run.words.slice(start, end),
		received: run.received.slice(start, end),
		fromCall: run.fromCall.slice(start, end),
	};
}

/**
 * The runs a call to an alias or function the source defines makes (`DefinedCommands`
 * definitions), read in place of the call so its operands meet the command the definition
 * names: `alias g=git; g push --force`, `f() { rm "$@"; }; f -rf /` (`definitionRuns`). The
 * word by which the run calls a definition (`definedCallIndex`: `\time -rf /` for a `time`
 * function) is expanded by every definition of that name, behind a wrapper too (`sudo g push
 * --force`, which bash would not expand: the fail-closed direction). Each run formed is
 * followed in turn when the word in its command position (`commandPositionIndex`) is a defined
 * name written in a definition, so an alias naming another alias or a body calling another
 * function is read through, and so is the word after an alias value ending in a blank
 * (`expandNext`), by its alias definitions. No other name behind a wrapper is followed there,
 * since no wrapper runs a function and `command ls` bypasses the `ls` function that calls it.
 * A command-position name the call's own words brought in is followed only as a function
 * other than the one whose run brought it in, past any repeats of that one (`run() { "$@"; };
 * g() { git "$@"; }; run run g push --force`): bash never alias-expands a word an expansion
 * produced, and `f() { "$@"; }; f f f sed ...` hands the command on to its operands, which
 * `definedCallOperandRuns` reads.
 * Nor is an alias inside its own expansion, as bash does not expand one there (`alias
 * ls='ls -F'`). A run already formed, with the same follow state, is not followed again, which
 * ends a function that calls itself unchanged. Every word formed is charged to `budget`.
 * Undefined when that runs out or a call is more than `MAX_DEFINITION_DEPTH` expansions deep,
 * so the caller counts the command unread -- unless the call at that depth is to a definition
 * already expanded on its way there. A recursive call is followed until its definition has been
 * expanded `MAX_RECURSIVE_READS` times on the way to it, by which point its body has been read
 * with the shapes of operands it passes itself, and stops there (`retry $((n-1)) "$@"`). A `name ()` header is not a call, but a run that
 * only looks like one, a call glued to an extended glob (`f -rf ~ @()`), is.
 */
function definitionCallRuns(
	argv: string[],
	definedNames: DefinedCommands,
	budget: { left: number },
): FormedRun[] | undefined {
	const { definitions } = definedNames;
	if (definitions.size === 0) return [];
	const out: FormedRun[] = [];
	const seen = new Set<string>();
	type Pending = {
		run: FormedRun;
		expanding: ReadonlySet<string>;
		formedBy?: string;
		path: ReadonlyMap<string, number>;
	};
	type Call = { index: number; reads: "any" | "alias" | "function" };
	let level: Pending[] = [{ run: formedFrom(argv, true), expanding: new Set(), path: new Map() }];
	for (let depth = 0; level.length > 0; depth++) {
		const next: Pending[] = [];
		for (const { run, expanding, formedBy, path } of level) {
			const { words, fromCall, expandNext } = run;
			const calls: Call[] = [];
			if (depth === 0) {
				const first = definedCallIndex(words, definitions);
				if (first !== undefined) calls.push({ index: first, reads: "any" });
			} else {
				let command = commandPositionIndex(words);
				if (!fromCall[command]) calls.push({ index: command, reads: "any" });
				else {
					while (fromCall[command] && words[command] === formedBy) command += 1;
					if (command < words.length) calls.push({ index: command, reads: "function" });
				}
				if (expandNext !== undefined) calls.push({ index: expandNext, reads: "alias" });
			}
			for (const { index, reads } of calls) {
				const name = words[index];
				const applicable = (definitions.get(name) ?? []).filter((definition) =>
					definition.kind === "function" ? reads !== "alias" : reads !== "function" && !expanding.has(name),
				);
				if (applicable.length === 0) continue;
				const expansions = path.get(name) ?? 0;
				if (expansions >= MAX_RECURSIVE_READS) continue;
				if (depth === MAX_DEFINITION_DEPTH) {
					if (expansions > 0) continue;
					return undefined;
				}
				const before = sliceFormed(run, 0, index);
				const operands = sliceFormed(run, index + 1);
				const onPath = new Map(path).set(name, expansions + 1);
				for (const definition of applicable) {
					const within = definition.kind === "alias" ? new Set([...expanding, name]) : new Set<string>();
					const formedRuns = definitionRuns(definition, before, operands, budget);
					if (formedRuns === undefined) return undefined;
					for (const formed of formedRuns) {
						const key = JSON.stringify([
							formed.words,
							formed.received,
							formed.scripts,
							formed.fromCall,
							formed.expandNext,
							name,
							[...within].sort(),
						]);
						budget.left -= key.length;
						if (budget.left <= 0) return undefined;
						if (seen.has(key)) continue;
						seen.add(key);
						const tagged = { ...formed, formedBy: name };
						out.push(tagged);
						next.push({ run: tagged, expanding: within, formedBy: name, path: onPath });
					}
				}
			}
		}
		level = next;
	}
	return out;
}

/**
 * A tokenization's runs less its own top-level ones, found by argv identity (`endRun` pushes the
 * same array to both `runs` and `topLevel`), so a prose reading keeps only the runs of what is
 * nested in it.
 */
function withoutOwnTopLevelRuns(scan: ScanResult): string[][] {
	const own = new Set<string[]>();
	for (const part of scan.topLevel) {
		if (part.kind === "command") own.add(part.argv);
	}
	return scan.runs.filter((run) => !own.has(run));
}

/**
 * The runs of the scripts that the runs an alias or function call forms (`definitionCallRuns`)
 * hand to a shell (`executableArgumentSources`, from the words as the command receives them),
 * each read as a script bash parses once the call's operands are spliced in: `f() { bash -c
 * "rm -rf $1"; }; f /` and `f() { bash -c 'rm -rf "$1"' _ "$@"; }; f /` both run `rm -rf /` -- and
 * of the scripts its body run executes (`scripts`: `f() { bash <<< "rm -rf $1"; }; f /`), a
 * double-quoted word among them read as prose, so only its substitutions' runs are kept.
 * Each script is charged to `budget`. A function whose scripts are already being read
 * `MAX_RECURSIVE_READS` times over (`activeFunctions`) calls itself through them, and has been
 * read with the shapes it passes itself, so its scripts are not read again (`fib() { ... $(fib
 * $(( $1 - 1 ))) ...; }`). Undefined when the budget runs out or such scripts nest more than
 * `MAX_DEFINITION_DEPTH` deep (`formedSources`) other than through a function already being read,
 * so the caller counts the command unread.
 */
function formedRunSources(
	formed: readonly FormedRun[],
	budget: NestBudget,
	definedNames: DefinedCommands,
): { runs: string[][]; complete: boolean; nestedUnread: boolean } | undefined {
	const result = { runs: [] as string[][], complete: true, nestedUnread: false };
	for (const run of formed) {
		const active = run.formedBy === undefined ? 0 : (budget.activeFunctions.get(run.formedBy) ?? 0);
		if (active >= MAX_RECURSIVE_READS) continue;
		const argumentScripts = executableArgumentSources(run.words, run.received, budget).map((found) => ({
			...found,
			mode: "gate" as const,
		}));
		const bodyScripts = (run.scripts ?? []).map(({ text, mode }) => ({ source: text, mode, unread: false }));
		for (const { source, unread, mode } of [...argumentScripts, ...bodyScripts]) {
			if (unread) {
				result.nestedUnread = true;
				continue;
			}
			if (source.length === 0) continue;
			if (budget.formedSources === MAX_DEFINITION_DEPTH) {
				if (active > 0) continue;
				return undefined;
			}
			budget.left -= nestedSourceCost(source);
			if (budget.left <= 0) return undefined;
			budget.formedSources += 1;
			if (run.formedBy !== undefined) budget.activeFunctions.set(run.formedBy, active + 1);
			try {
				const child = tokenizeInto(source, budget, mode, false, definedNames, false, true);
				result.runs.push(...(mode === "prose" ? withoutOwnTopLevelRuns(child) : child.runs));
				result.complete &&= child.complete;
				result.nestedUnread ||= child.nestedUnread;
			} finally {
				budget.formedSources -= 1;
				if (run.formedBy !== undefined) budget.activeFunctions.set(run.formedBy, active);
			}
		}
	}
	return result;
}

/**
 * The words by which a run reads what is piped into it as commands (`runsQuotedArguments`), or
 * undefined when no reading does: the full run first, when it names the interpreter or one of
 * its process substitutions -- among `runSources`, the run's nested sources -- is one
 * (`processSubstitutionsRunInterpreter`: `tee >(sh)`, and `cat > >(sh)`, where a redirection's
 * own target is the interpreter); then `commandWords`, its redirection-free words as the
 * tokenizer recorded them, since a redirection may stand in front of the command
 * (`2>/dev/null sh`); then its unfolded `env -S` strings (`envSplitSinkWords`). Bodies are lexed
 * ahead of their analysis, charged to `lookahead`.
 */
function pipeReaderWords(
	argv: string[],
	commandWords: string[],
	runSources: readonly NestedSource[],
	lookahead: { left: number },
): string[] | undefined {
	if (runsQuotedArguments(argv) || processSubstitutionsRunInterpreter(runSources, lookahead)) return argv;
	if (commandWords !== argv && runsQuotedArguments(commandWords)) return commandWords;
	return envSplitSinkWords(commandWords);
}

/**
 * How `substitutionsReadPipe` reads a source's text: whether it is the text of a double-quoted
 * word, where its own words are prose, a process substitution is plain text, and a `'` is a
 * literal character.
 */
interface SubstitutionReading {
	doubleQuoted: boolean;
}

/** A pipe sink run's own words, whose substitutions all run with the pipe as their input. */
const SINK_WORDS: SubstitutionReading = { doubleQuoted: false };

/**
 * Whether any of `sources` -- the nested sources of a pipe sink run, or of a text inside one --
 * runs a command that can execute what the pipe feeds: one whose name is rebound
 * (`rebindsCommandName`) or one that reads its input as commands (`pipeReaderWords`). Every
 * substitution in the sink's words runs with the pipe as its standard input, a process
 * substitution (`tee >(/tmp/cat)`, `tee > >(cat)` once `cat` is defined) and a command or
 * backtick substitution alike (`cat $(sh)`, `tee "$(/tmp/cat)"`), and so do
 * the substitutions nested in them, those written inside a double-quoted word included
 * (`grep "$(/tmp/cat)"`), at any depth. Each text is read from its lex (`lexedNestedSource`), so
 * quoting, line continuations and redirections are honored as bash reads them: `grep 'x;/tmp/cat'`
 * runs only `grep`, and `grep x $(which node)` runs only `grep` and `which`. Every run of a
 * substitution body counts, including one whose input a pipe or redirection inside the body
 * replaces, and an awk counts whatever its program: both only over-mark, the fail-closed
 * direction. Each text lexed here is charged to `lookahead`, a budget of its own so reading ahead
 * never starves the analysis of the sources before it; when it has nothing left, the text counts
 * as reading the pipe, the fail-closed direction.
 */
function substitutionsReadPipe(
	sources: readonly NestedSource[],
	reading: SubstitutionReading,
	definedNames: ReadonlySet<string>,
	lookahead: { left: number },
): boolean {
	for (const source of sources) {
		const inner = nestedReading(source, reading);
		if (inner !== undefined && textReadsPipe(source, inner, definedNames, lookahead)) return true;
	}
	return false;
}

/**
 * How a source found in text read as `reading` has its own text read, or undefined when it runs
 * nothing there: a command or backtick substitution runs anywhere, a process substitution only
 * outside a double-quoted word, and a quoted word is read for the substitutions in it when it is
 * double-quoted or sits inside a double-quoted word, where a `'` is a literal character.
 */
function nestedReading(source: NestedSource, reading: SubstitutionReading): SubstitutionReading | undefined {
	switch (source.kind) {
		case "process-substitution":
			return reading.doubleQuoted ? undefined : { doubleQuoted: false };
		case "command-substitution":
		case "backtick":
			return { doubleQuoted: false };
		case "quoted-potential":
			return source.quote === '"' || (reading.doubleQuoted && source.quote === "'")
				? { doubleQuoted: true }
				: undefined;
		case "argument-source":
		case "heredoc":
		case "here-string":
			return undefined;
	}
}

/**
 * Whether a run hands what it writes to a command that can execute it through one of its own
 * output process substitutions, read as a pipe sink's are (`substitutionsReadPipe`): `echo '...'
 * > >(cat)` once `cat` is defined, or `> >(/tmp/cat)`, runs the words echo prints exactly as
 * `echo '...' | cat` does. Every output process substitution counts whatever file descriptor or
 * argument slot it fills, which over-marks: the fail-closed direction. An input one (`<(...)`)
 * counts only as a writing redirection's target (`writeTarget`: `echo '...' > <(cat)`); as an
 * argument (`grep '...' <(cat)`) or a reading redirection's target its body never sees what the
 * run writes.
 */
function outputSubstitutionsReadRun(
	sources: readonly NestedSource[],
	definedNames: ReadonlySet<string>,
	lookahead: { left: number },
): boolean {
	const outputs = sources.filter(
		(source) =>
			source.kind === "process-substitution" && (source.direction === "output" || source.writeTarget === true),
	);
	return outputs.length > 0 && substitutionsReadPipe(outputs, SINK_WORDS, definedNames, lookahead);
}

/**
 * Whether a run may be an `exec` whose redirections outlive it: a command-less `exec` applies
 * its redirections to the shell itself, so every command the shell runs afterwards writes
 * through them (`exec > >(sh); echo '...'` runs what echo prints). A run counts when a command
 * of its chain (`executableCommandIndexes`, behind any wrapper and inside any `env -S` string)
 * is `exec`, or when its name may not mean the program it usually does (`rebindsCommandName`:
 * `$x`, an alias of `exec`). An `exec` that names a command replaces the shell, so nothing
 * runs after it; it still counts, which only over-marks: the fail-closed direction.
 */
function mayPersistRedirections(commandWords: string[], definedNames: ReadonlySet<string>): boolean {
	if (rebindsCommandName(commandWords, definedNames)) return true;
	const argv = unfoldEnvSplits(commandWords) ?? commandWords;
	return executableCommandIndexes(argv).some((index) => headBase(argv[index]) === "exec");
}

/**
 * Whether one nested source's text runs a command that can execute the pipe, read as `reading`
 * says (see `substitutionsReadPipe`). The verdict is kept on the source (`pipeVerdicts`), so a
 * deeply nested text read ahead from every level above it is walked once rather than once per
 * level. It stays valid while `definedNames` keeps its size: one analysis shares a single set of
 * defined names and only ever adds to it.
 */
function textReadsPipe(
	inner: NestedSource,
	reading: SubstitutionReading,
	definedNames: ReadonlySet<string>,
	lookahead: { left: number },
): boolean {
	const slot = reading.doubleQuoted ? "doubleQuoted" : "unquoted";
	const cached = inner.pipeVerdicts?.[slot];
	if (cached !== undefined && cached.definedNames === definedNames.size) return cached.readsPipe;
	const readsPipe = readTextForPipe(inner, reading, definedNames, lookahead);
	inner.pipeVerdicts ??= {};
	inner.pipeVerdicts[slot] = { definedNames: definedNames.size, readsPipe };
	return readsPipe;
}

/** `textReadsPipe` without its kept verdict: lex the text and read its commands and substitutions. */
function readTextForPipe(
	inner: NestedSource,
	reading: SubstitutionReading,
	definedNames: ReadonlySet<string>,
	lookahead: { left: number },
): boolean {
	const lexed = lexedAhead(inner, lookahead);
	if (lexed === undefined) return true;
	if (!reading.doubleQuoted) {
		const sourcesByRun = nestedSourcesByRun(lexed.nestedSources);
		for (const part of lexed.topLevel) {
			if (part.kind !== "command") continue;
			const commandWords = redirectionFreeWords(part.argv);
			if (rebindsCommandName(commandWords, definedNames)) return true;
			if (pipeReaderWords(part.argv, commandWords, sourcesByRun.get(part.argv) ?? [], lookahead) !== undefined)
				return true;
		}
	}
	return substitutionsReadPipe(lexed.nestedSources, reading, definedNames, lookahead);
}

/**
 * A nested source's lex taken ahead of its analysis (`lexedNestedSource`), its text charged to
 * `lookahead` the first time; undefined when the source is not lexed yet and `lookahead` has
 * nothing left.
 */
function lexedAhead(inner: NestedSource, lookahead: { left: number }): LexedSource | undefined {
	if (inner.lexed === undefined) {
		if (lookahead.left <= 0) return undefined;
		lookahead.left -= nestedSourceCost(inner.source);
	}
	return lexedNestedSource(inner, lookahead);
}

/** `nestedSources` grouped by the run each was found in; a source found outside a run is left out. */
function nestedSourcesByRun(nestedSources: readonly NestedSource[]): Map<string[], NestedSource[]> {
	const byRun = new Map<string[], NestedSource[]>();
	for (const inner of nestedSources) {
		if (inner.run === undefined) continue;
		const found = byRun.get(inner.run);
		if (found === undefined) byRun.set(inner.run, [inner]);
		else found.push(inner);
	}
	return byRun;
}

/**
 * Whether one of `sources` -- a run's nested sources -- is a process substitution that is itself
 * an interpreter the run feeds: `echo 'rm -rf /' | tee >(sh)` executes what tee writes, exactly
 * like `| sh`, and `cat > >(sh)` hands sh what cat prints. It is when a run of its body, or of a
 * command, backtick or process substitution nested in it, names an interpreter-like command
 * (`namesInterpreter`) at an index its command chain executes (`executableCommandIndexes`), a
 * wrapper included (`>(timeout 5 sh)`, `>(env -S sh)`), with no arming flag required
 * (`>(node)`): over-marking there only makes the run read its input as commands, the
 * fail-closed direction.
 *
 * Each body is read from its lex (`lexedNestedSource`), as a pipe sink's substitutions are
 * (`substitutionsReadPipe`), so a name quoted or escaped mid-word still counts (`>(s'h')`,
 * `>(s\h)`, `>($'\x73h')`) while an operand does not (`>(grep 'sh')`, `>(grep x $(which
 * node))`), and a process substitution written inside a double-quoted word is plain text. Each
 * text lexed here is charged to `lookahead`; when it has nothing left, the text counts as an
 * interpreter, the fail-closed direction.
 */
function processSubstitutionsRunInterpreter(sources: readonly NestedSource[], lookahead: { left: number }): boolean {
	return sources.some(
		(source) => source.kind === "process-substitution" && textRunsInterpreter(source, SINK_WORDS, lookahead),
	);
}

/**
 * Whether one nested source's text runs an interpreter-like command, read as `reading` says (see
 * `processSubstitutionsRunInterpreter`). The verdict is kept on the source (`interpreterVerdicts`),
 * so a deeply nested text read from every level above it is walked once rather than once per
 * level.
 */
function textRunsInterpreter(inner: NestedSource, reading: SubstitutionReading, lookahead: { left: number }): boolean {
	const slot = reading.doubleQuoted ? "doubleQuoted" : "unquoted";
	const cached = inner.interpreterVerdicts?.[slot];
	if (cached !== undefined) return cached;
	const runsInterpreter = readTextForInterpreter(inner, reading, lookahead);
	inner.interpreterVerdicts ??= {};
	inner.interpreterVerdicts[slot] = runsInterpreter;
	return runsInterpreter;
}

/** `textRunsInterpreter` without its kept verdict: lex the text and read its commands and substitutions. */
function readTextForInterpreter(
	inner: NestedSource,
	reading: SubstitutionReading,
	lookahead: { left: number },
): boolean {
	const lexed = lexedAhead(inner, lookahead);
	if (lexed === undefined) return true;
	if (!reading.doubleQuoted) {
		for (const part of lexed.topLevel) {
			if (part.kind !== "command") continue;
			const words = redirectionFreeWords(part.argv);
			if (executableCommandIndexes(words).some((index) => namesInterpreter(words[index]))) return true;
		}
	}
	return lexed.nestedSources.some((source) => {
		const nested = nestedReading(source, reading);
		return nested !== undefined && textRunsInterpreter(source, nested, lookahead);
	});
}

/**
 * Whether a command word names an interpreter or exec wrapper (`INTERPRETER_LIKE_HEADS`) or a
 * script interpreter (`EVAL_FLAG_BY_HEAD`, `PYTHON_HEAD`), by basename.
 */
function namesInterpreter(word: string): boolean {
	const base = headBase(word);
	return INTERPRETER_LIKE_HEADS.has(base) || EVAL_FLAG_BY_HEAD.has(base) || PYTHON_HEAD.test(base);
}

/**
 * Raw argv indexes of the commands a run's wrappers invoke. The chain is walked over the
 * redirection-free view, since a redirection after a wrapper (`timeout 1 >/dev/null bash`)
 * is not the command it runs.
 */
function executableArgumentPositions(view: RedirectionFreeView): Set<number> {
	return new Set(
		executableCommandIndexes(view.words)
			.slice(1)
			.map((index) => view.indexes[index]),
	);
}

/** Find predicates whose following words are data, not other actions in the expression. */
const FIND_VALUE_ARITY = new Map<string, number>(
	[
		"-Bmin",
		"-Bnewer",
		"-Btime",
		"-amin",
		"-anewer",
		"-atime",
		"-cmin",
		"-cnewer",
		"-context",
		"-ctime",
		"-f",
		"-flags",
		"-fprint",
		"-fprint0",
		"-fstype",
		"-gid",
		"-group",
		"-ilname",
		"-iname",
		"-inum",
		"-ipath",
		"-iregex",
		"-iwholename",
		"-links",
		"-lname",
		"-maxdepth",
		"-mindepth",
		"-mmin",
		"-mnewer",
		"-mtime",
		"-name",
		"-newer",
		"-path",
		"-perm",
		"-printf",
		"-regex",
		"-samefile",
		"-size",
		"-type",
		"-uid",
		"-used",
		"-user",
		"-wholename",
		"-xattrname",
		"-xtype",
	].map((option): [string, number] => [option, 1]),
);
FIND_VALUE_ARITY.set("-fprintf", 2);

/** The `[start, end)` argv spans of the commands a find expression's -exec family runs. */
function findExecSpans(argv: string[], start: number): [number, number][] {
	const spans: [number, number][] = [];
	for (let i = start; i < argv.length; i++) {
		const valueArity = FIND_VALUE_ARITY.get(argv[i]) ?? (/^-newer[A-Za-z]{2}$/.test(argv[i]) ? 1 : 0);
		if (valueArity > 0) {
			i += valueArity;
			continue;
		}
		if (!["-exec", "-execdir", "-ok", "-okdir"].includes(argv[i])) continue;
		let end = i + 1;
		while (end < argv.length && argv[end] !== ";" && argv[end] !== "+") end += 1;
		spans.push([i + 1, end]);
		i = end;
	}
	return spans;
}

export function findExecCommands(argv: string[], start: number = 0): string[][] {
	return findExecSpans(argv, start).map(([from, to]) => argv.slice(from, to));
}

function proxyCommandSource(token: string): string | null {
	const match = /^(?:-o)?proxycommand(?:=|\s+)(.+)$/i.exec(token);
	return match?.[1] ?? null;
}

function gitAliasSource(token: string): string | null {
	const match = /^alias\.[^=]+=!(.+)$/i.exec(token);
	return match?.[1] ?? null;
}

const GIT_CONFIG_QUERY_OPTIONS =
	/^(?:--get(?:-all|-regexp|-urlmatch)?|--get-color(?:bool)?|--list|--show-origin|--show-scope|--name-only|-l)$/;
const GIT_CONFIG_VALUE_OPTIONS = new Set(["--blob", "--comment", "--default", "--file", "--type", "-f"]);

/** The argv indexes of the `!`-prefixed shell alias values a `git config` invocation sets. */
function gitConfigAliasValueIndexes(argv: string[], start: number): number[] {
	for (let i = start; i < argv.length; i++) if (GIT_CONFIG_QUERY_OPTIONS.test(argv[i])) return [];
	const indexes: number[] = [];
	for (let i = start; i < argv.length; i++) {
		if (GIT_CONFIG_VALUE_OPTIONS.has(argv[i])) {
			i += 1;
			continue;
		}
		if (!/^alias\.[-A-Za-z0-9_.]+$/i.test(argv[i])) continue;
		if (argv[i + 1]?.startsWith("!")) indexes.push(i + 1);
	}
	return indexes;
}

/**
 * A source a run hands to a shell. `argIndex` is set only when the source is exactly one whole
 * word of the run's argv, so the caller can pair it with that word's quoted text by position.
 */
interface ArgumentSource {
	source: string;
	argIndex?: number;
	/** The source would outgrow the nesting budget, so it stands for text left unread. */
	unread?: boolean;
}

/**
 * The sources `argv` hands to a shell. `argv` decides where they are; their text is taken from
 * `received`, the same words as the program receives them, since the shell that reads a source
 * parses those characters afresh and a quoted `{`, `~` or `$` is live there, where `argv`
 * spells it as `EXPANSION_SUPPRESSED`. A source cut from a word (`alias.x=!...`, `-S...`) is
 * cut from the received word when it reads the same way there, and from `argv` otherwise.
 *
 * A shell script handed positional parameters is also taken with them spliced in
 * (`parameterSplicedSource`), its text charged to `budget` as it is built.
 */
function executableArgumentSources(
	argv: string[],
	received: readonly string[],
	budget: { left: number },
): ArgumentSource[] {
	const sources: ArgumentSource[] = [];
	const queue: { words: string[]; offset: number }[] = [{ words: argv, offset: 0 }];
	let cursor = 0;
	let work = 0;
	while (cursor < queue.length && work < 100_000) {
		const { words: current, offset } = queue[cursor++];
		work += current.length;
		const wordsFrom = (from: number, to: number = from + 1): ArgumentSource => {
			const source = received.slice(offset + from, offset + to).join(" ");
			return to - from === 1 ? { source, argIndex: offset + from } : { source };
		};
		const splicedScripts = new Set<number>();
		const pushSpliced = (script: number): void => {
			if (splicedScripts.has(script)) return;
			splicedScripts.add(script);
			const receivedWords = received.slice(offset, offset + current.length);
			const spliced = parameterSplicedSource(current, receivedWords, script, budget.left);
			if (spliced.kind === "over-budget") sources.push({ source: "", unread: true });
			else if (spliced.kind === "spliced")
				for (const text of spliced.texts) {
					budget.left -= text.length;
					sources.push({ source: text });
				}
		};
		const cut = (at: number, read: (word: string) => string | null): string | null => {
			const spelled = read(current[at]);
			return spelled === null ? null : (read(received[offset + at]) ?? spelled);
		};
		// fish takes each command option with a value, so every one it is given runs. `skip` is a
		// word already taken as a source.
		const pushFishSources = (index: number, skip?: number): void => {
			for (let i = index + 1; i < current.length; i++) {
				const option = readFishCommandOption(current[i]);
				if (option?.kind === "inline") sources.push({ source: cut(i, fishInlineCommand) ?? option.source });
				else if (option?.kind === "value-next" && i + 1 < current.length && i + 1 !== skip)
					sources.push(wordsFrom(i + 1));
			}
		};
		for (const index of executableCommandIndexes(current)) {
			const base = headBase(current[index]);
			if (namesUnknownCommand(argv, offset + index)) {
				// The word may name a POSIX-style shell or fish, so both readings' sources are taken.
				const script = shellScriptIndex(current, index);
				if (script < current.length) {
					sources.push(wordsFrom(script));
					pushSpliced(script);
				}
				pushFishSources(index, script);
				if (SHELL_SOURCE_HEADS.has(base)) break;
			}
			if (base === "fish") {
				pushFishSources(index);
				break;
			} else if (SHELL_SOURCE_HEADS.has(base)) {
				// The script is the program; its commands are read from its own analysis, and the
				// words after it are $0, $1, ... rather than further sources of this run.
				const target = wrapperTargetIndex(current, index);
				if (target < current.length) {
					sources.push(wordsFrom(target));
					pushSpliced(target);
				}
				break;
			} else if (base === "eval") {
				const source = wordsFrom(wrapperTargetIndex(current, index), current.length);
				if (source.source.length > 0) sources.push(source);
				break;
			} else if (base === "trap") {
				const target = wrapperTargetIndex(current, index);
				if (target < current.length) sources.push(wordsFrom(target));
			} else if (base === "git") {
				for (let i = index + 1; i < current.length; i++) {
					const inline = cut(i, gitAliasSource);
					if (inline !== null) sources.push({ source: inline });
					if (current[i] === "config")
						for (const value of gitConfigAliasValueIndexes(current, i + 1))
							sources.push({ source: received[offset + value].slice(1) });
				}
			} else if (base === "find") {
				for (const [from, to] of findExecSpans(current, index + 1))
					queue.push({ words: current.slice(from, to), offset: offset + from });
			} else if (["env", "flock", "script", "su"].includes(base)) {
				for (let i = index + 1; i < current.length; i++) {
					if (base === "env") {
						const option = readEnvOption(current[i]);
						if (option.kind === "split-next") {
							if (current[i + 1] !== undefined)
								sources.push({ source: envSplitShellSource(received[offset + i + 1]) });
							break;
						}
						if (option.kind === "split") {
							const split = cut(i, (word) => {
								const read = readEnvOption(word);
								return read.kind === "split" ? read.source : null;
							});
							sources.push({ source: envSplitShellSource(split ?? option.source) });
							break;
						}
					} else if (commandStringOptions(base).has(spelledWrapperOption(base, current[i]))) {
						if (current[i + 1] !== undefined) sources.push(wordsFrom(i + 1));
						break;
					} else {
						const source = cut(i, (word) =>
							attachedCommandStringSource(spelledWrapperOption(base, word), commandStringOptions(base)),
						);
						if (source !== null) {
							sources.push({ source });
							break;
						}
					}
				}
			} else if (base === "watch") {
				const target = wrapperTargetIndex(current, index);
				if (target < current.length) sources.push(wordsFrom(target, current.length));
			}
			if (base !== "ssh") continue;
			const target = wrapperTargetIndex(current, index);
			if (target < current.length) sources.push(wordsFrom(target, current.length));
			for (let i = index + 1; i < current.length; i++) {
				if (current[i] === "-o" && current[i + 1] !== undefined) {
					const source = cut(i + 1, proxyCommandSource);
					if (source !== null) sources.push({ source });
					i += 1;
					continue;
				}
				const source = cut(i, proxyCommandSource);
				if (source !== null) sources.push({ source });
			}
		}
	}
	return sources;
}

const SEPARATORS = new Set([";", "&", "|", "\n", "(", ")"]);
const WHITESPACE = new Set([" ", "\t", "\r", "\f", "\v"]);

/**
 * The `WHITESPACE` characters bash does NOT break words on: to bash they are word text
 * (`-F <CR>` passes a carriage return to `-F`), so where one appears the scanned word
 * positions may not be the ones bash runs.
 */
export const NON_BASH_BLANK = /[\r\f\v]/;

export interface Scanned {
	/** The content with its delimiters and escapes removed. */
	text: string;
	/** The literal source span, delimiters included. */
	raw: string;
	/** Index just past the construct. */
	end: number;
	complete: boolean;
}

/**
 * Read a `$'...'` run starting at `start` (the `$`), its escapes decoded as bash decodes them.
 * An unterminated one runs to the end of the input.
 */
export function readAnsiCQuoted(source: string, start: number): Scanned {
	let text = "";
	let i = start + 2;
	const named: Record<string, string> = {
		a: "\x07",
		b: "\b",
		e: "\x1b",
		E: "\x1b",
		f: "\f",
		n: "\n",
		r: "\r",
		t: "\t",
		v: "\v",
		"\\": "\\",
		"'": "'",
		'"': '"',
	};
	// bash ends a `$'...'` segment's value at its first NUL (`$'-F\0x'` is `-F`), so the
	// decoded text is cut there; the scan still runs on to the closing quote.
	const beforeNul = (decoded: string): string => decoded.split("\u0000", 1)[0];
	while (i < source.length) {
		const c = source[i];
		if (c === "'") return { text: beforeNul(text), raw: source.slice(start, i + 1), end: i + 1, complete: true };
		if (c !== "\\" || i + 1 >= source.length) {
			text += c;
			i += 1;
			continue;
		}
		const code = source[i + 1];
		if (code === "\n") {
			i += 2;
			continue;
		}
		if (code === "c" && i + 2 < source.length) {
			text += String.fromCharCode(source.charCodeAt(i + 2) & 31);
			i += 3;
			continue;
		}
		const width = code === "x" ? 2 : code === "u" ? 4 : code === "U" ? 8 : 0;
		if (width > 0) {
			const digits = source.slice(i + 2).match(new RegExp(`^[0-9A-Fa-f]{1,${width}}`))?.[0] ?? "";
			if (digits.length > 0) {
				text += String.fromCodePoint(Math.min(Number.parseInt(digits, 16), 0x10ffff));
				i += 2 + digits.length;
				continue;
			}
		}
		if (/[0-7]/.test(code)) {
			const digits = source.slice(i + 1).match(/^[0-7]{1,3}/)?.[0] ?? code;
			text += String.fromCharCode(Number.parseInt(digits, 8) & 0xff);
			i += 1 + digits.length;
			continue;
		}
		text += named[code] ?? `\\${code}`;
		i += 2;
	}
	return { text: beforeNul(text), raw: source.slice(start), end: source.length, complete: false };
}

/**
 * Read a single- or double-quoted run starting at `start` (the opening quote).
 *
 * An UNTERMINATED quote runs to the end of the input rather than failing: an apostrophe in
 * `echo it's fine && rm -rf /` would otherwise swallow the rest of the command silently, and
 * the floor must stay fail-closed there. Inside double quotes a backslash only escapes the
 * four characters bash treats specially, plus a newline (a line continuation, which bash
 * removes entirely); elsewhere it stays literal, so a Windows path or a regex in a quoted
 * argument survives intact. An escaped `$` or backtick becomes `EXPANSION_SUPPRESSED` rather
 * than itself: `"\$HOME"` is the literal four-character path, not the home directory.
 *
 * A `$(...)` or backtick substitution inside double quotes opens a fresh quoting context, as
 * in bash, so a `"` inside it does not end the run: the substitution is read as one unit by
 * `readSubstitution` or `readBackticks`, and its raw text joins the run's text. So
 * `"$(: "'"; rm -rf /; : "'")"` is ONE word whose substitution runs `rm -rf /`, not the quoted
 * text `$(: ` followed by more words. A backtick substitution joins it with the `\"` escapes of
 * its body resolved, as bash resolves them inside double quotes, so read again outside quotes
 * it gives the body bash parses (see `readBackticks`).
 *
 * `received` is the content as the command receives it: the same text with an escaped `$` or
 * backtick as itself, so a shell handed the word (`bash -c "rm -rf \$HOME"`) reads the live
 * `$HOME` it expands.
 */
export function readQuoted(source: string, start: number, quote: string): QuotedScan {
	let text = "";
	let received = "";
	let i = start + 1;
	while (i < source.length) {
		const c = source[i];
		if (c === quote) return { text, received, raw: source.slice(start, i + 1), end: i + 1, complete: true };
		if (quote === '"' && c === "\\" && i + 1 < source.length) {
			const next = source[i + 1];
			if (next === "$" || next === "`") {
				text += EXPANSION_SUPPRESSED;
				received += next;
			} else if (next !== "\n") {
				const kept = next === '"' || next === "\\" ? next : c + next;
				text += kept;
				received += kept;
			}
			i += 2;
			continue;
		}
		if (quote === '"' && ((c === "$" && source[i + 1] === "(") || c === "`")) {
			const substitution = c === "`" ? readBackticks(source, i) : readSubstitution(source, i);
			const kept =
				c === "`" ? substitution.raw.replace(DOUBLE_QUOTED_BACKTICK_ESCAPE, unescapeQuote) : substitution.raw;
			text += kept;
			received += kept;
			i = substitution.end;
			continue;
		}
		text += c;
		received += c;
		i += 1;
	}
	return { text, received, raw: source.slice(start), end: source.length, complete: false };
}

/** A quoted run read by `readQuoted`, with its content as the command receives it. */
export interface QuotedScan extends Scanned {
	received: string;
}

/** A backslash pair in a backtick body whose backslash double quotes remove only before `"`. */
const DOUBLE_QUOTED_BACKTICK_ESCAPE = /\\[\\"]/g;

/** `DOUBLE_QUOTED_BACKTICK_ESCAPE`'s replacement: `\"` loses its backslash, `\\` stays. */
function unescapeQuote(pair: string): string {
	return pair === '\\"' ? '"' : pair;
}

/** The unquoted characters that end a word inside a substitution body. */
const WORD_BREAKS = new Set([" ", "\t", "\n", ";", "&", "|", "<", ">", ")"]);

/**
 * A parenthesized group a substitution body has open -- the body itself, a subshell, or a
 * substitution nested in it -- with the word state of its container, restored when it closes.
 */
interface OpenGroup {
	kind: "group";
	commandPosition: boolean;
	word: string;
	previousWord: string | undefined;
	/** Anything but whitespace was read inside it, so an empty `()` reads as a function header. */
	hasContent: boolean;
	/** It was opened by `$(`, so a `(` directly behind it makes it `$((`, an arithmetic expansion. */
	dollar: boolean;
	/** It is arithmetic, or a parenthesis inside arithmetic, where no word is a reserved word. */
	arithmetic: boolean;
	/**
	 * It is a substitution -- the body itself, or a `$(`, `<(` or `>(` nested in it -- which bash
	 * parses on its own, heredocs included: a heredoc opened in it takes its body from the
	 * substitution's next line end, not from one inside a substitution nested deeper.
	 */
	substitution: boolean;
}

/** Whether a substitution body holds commands (`$(`, `<(`, `>(`) or arithmetic (`$((`). */
type SubstitutionContent = "commands" | "arithmetic";

/**
 * A `case` command a substitution body has open. `subject` awaits the word matched, `in` the
 * `in` behind it, `patterns` reads a pattern list up to its closing `)`, and `arm` reads the
 * commands of one arm up to `;;`, `;&` or `;;&`.
 */
interface OpenCase {
	kind: "case";
	phase: "subject" | "in" | "patterns" | "arm";
	/** Parentheses opened inside the current pattern (`@(a|b)`, `$(cmd)`), which close before it does. */
	patternDepth: number;
	/** A pattern word, or the optional `(` in front of the list, has been read in this pattern list. */
	patternStarted: boolean;
}

/**
 * A `${...}` parameter expansion a substitution body has open, read as bash reads it: all word
 * text up to the first unquoted `}`, where only a nested `${` or `$(` opens anything. A `{`
 * alone does not nest, and a `)`, `;`, `#` or blank is text.
 */
interface OpenBrace {
	kind: "brace";
}

/**
 * The command structure of a substitution body, read one unquoted character at a time, to find
 * the `)` that closes it. Counting parentheses alone is not enough: the `)` ending a `case`
 * pattern is unbalanced, so `$(case x in x) cmd;; esac)` would otherwise close at that `)` and
 * leave `cmd` outside, read as text of the containing word. `case` is recognized only as an
 * unquoted word in command position, as bash recognizes reserved words, and nested groups are
 * an explicit stack, so the scan stays linear with no recursion however deeply they nest.
 *
 * Quoted and escaped text, and a backtick substitution, is not read here; the caller skips it
 * with its own scanner and hands over its raw text, which keeps a `)` inside it from closing the
 * body and the word it belongs to from being a reserved word. A `#` that
 * starts a word opens a comment through the end of the line, as in bash, so its `)`, `;;` and
 * `esac` are not structure; while `inComment` holds, the caller hands every character over as
 * it is, quotes and backslashes included.
 *
 * A `${` opens a parameter expansion (see `OpenBrace`) whose text joins the word being read, so
 * a `)` in a pattern (`${x%)}`) or a default (`${x:-)}`) does not close the body. As in bash, the
 * second `$` of a `$$` opens none: `$${` is the parameter `$$` followed by a plain `{`. The
 * caller still skips quoted spans and backtick substitutions inside it, which bash also reads
 * there.
 *
 * A heredoc opened by an unquoted `<<` or `<<-` has its body skipped whole from the next line
 * end on (see `readHeredocBody`), so a `)`, quote, `;;` or `esac` on a body line is data, as in
 * bash. Heredocs belong to the substitution they are opened in: one still pending when its
 * substitution closes takes its body from the enclosing one's next line end, as bash reads it.
 * A `<<` is taken for a heredoc only where every character before it in the body was read as
 * bash reads it (see `HeredocGuard`); from any other on, no heredoc is recognized and body
 * lines are read as structure.
 */
class SubstitutionBody {
	private readonly frames: (OpenGroup | OpenCase | OpenBrace)[];
	/** The heredocs awaiting their bodies, in the order they were opened. */
	private readonly heredocs: HeredocDelimiter[] = [];
	/**
	 * Where each open substitution's own heredocs start in `heredocs`, innermost last. Closing
	 * one drops its entry, which hands its pending heredocs to the enclosing substitution.
	 */
	private readonly heredocScopes: number[] = [0];
	private guardAt: HeredocGuard | undefined;
	private commandPosition = true;
	private word = "";
	private previousWord: string | undefined;
	private previousChar = "";
	/** The previous character is an unquoted `$` that can open an expansion: not the second of a `$$`. */
	private expansionDollar = false;
	private comment = false;
	private justOpened = false;
	private done = false;
	private skipped: readonly { heredoc: HeredocDelimiter; read: Scanned }[] = [];

	/**
	 * A body of `content` in `source`, whose first character is at `start`. A `"top-level"`
	 * `scope` reads a whole script instead: a `)` never closes it, and a heredoc opened outside
	 * any substitution ends only at its exact delimiter line, as bash reads a script.
	 */
	constructor(
		content: SubstitutionContent,
		private readonly source: string,
		private readonly start: number,
		private readonly scope: HeredocContext = "substitution",
	) {
		this.frames = [
			{
				kind: "group",
				commandPosition: true,
				word: "",
				previousWord: undefined,
				hasContent: false,
				dollar: false,
				arithmetic: content === "arithmetic",
				substitution: true,
			},
		];
	}

	/** Whether the `)` that closes the body has been read. */
	get closed(): boolean {
		return this.done;
	}

	/** The body's `HeredocGuard`, made when a `<<` first needs it. */
	private get guard(): HeredocGuard {
		this.guardAt ??= new HeredocGuard(this.source, this.start, "followed");
		return this.guardAt;
	}

	/** Whether the body is inside a comment, where quotes and backslashes are plain text. */
	get inComment(): boolean {
		return this.comment;
	}

	/**
	 * The heredoc bodies the latest `read` skipped, in order, each with its delimiter; empty
	 * when that `read` skipped none.
	 */
	get skippedBodies(): readonly { heredoc: HeredocDelimiter; read: Scanned }[] {
		return this.skipped;
	}

	/**
	 * Add quoted or escaped source text to the word being read. Only its first character joins
	 * the word: a quote or backslash already makes the word neither a reserved word nor an
	 * assignment's name, and the span can hold a whole nested substitution, which the word need
	 * not carry. A double-quoted span holding a `$(`, which this body does not follow, refuses
	 * heredocs (see `refuseHeredocs`).
	 */
	quoted(raw: string): void {
		const top = this.frames.at(-1);
		if (top?.kind === "group") top.hasContent = true;
		this.word += raw.slice(0, 1);
		this.previousChar = "";
		this.expansionDollar = false;
		if (raw.startsWith('"') && raw.includes("$(")) this.refuseHeredocs();
	}

	/**
	 * Recognize no further heredoc in the body and drop the pending ones, whose lines are then
	 * read as structure: called where what comes next may not be read as bash reads it -- after
	 * a span the body does not follow, or a `<<` it cannot place.
	 */
	refuseHeredocs(): void {
		this.guard.markAmbiguous();
		if (this.heredocs.length > 0) this.heredocs.length = 0;
	}

	/**
	 * Read the unquoted character at `at` in the source and return where reading goes on: past
	 * the bodies of the heredocs a line end starts, else at the next character. Once it is the
	 * `)` that closes the body, `closed` holds.
	 */
	read(at: number): number {
		const c = this.source[at];
		if (this.skipped.length > 0) this.skipped = [];
		if (this.closes(c, at)) {
			this.done = true;
			return at + 1;
		}
		return c === "\n" ? this.readHeredocBodies(at + 1) : at + 1;
	}

	/** Read one unquoted character at `at`; true when it is the `)` that closes the body. */
	private closes(c: string, at: number): boolean {
		const previous = this.previousChar;
		const justOpened = this.justOpened;
		const expansionDollar = this.expansionDollar;
		this.previousChar = c;
		this.justOpened = false;
		this.expansionDollar = c === "$" && !expansionDollar;
		if (this.comment) {
			if (c !== "\n") return false;
			this.comment = false;
		}
		const current = this.frames.at(-1);
		if (current === undefined) return false;
		if (current.kind === "brace") return this.readInBrace(c, previous, justOpened, current);
		if (current.kind === "group" && !WORD_BREAKS.has(c)) current.hasContent = true;
		if (c === "{" && expansionDollar) {
			this.frames.push({ kind: "brace" });
			this.word += c;
			return false;
		}
		if (current.kind === "case" && current.phase === "patterns" && current.patternDepth > 0) {
			if (c === "(" && previous === "$") return this.open(current, previous, justOpened);
			if (c === "(") current.patternDepth += 1;
			else if (c === ")") current.patternDepth -= 1;
			this.word += c;
			return false;
		}
		if (c === "#" && this.word === "") {
			this.comment = true;
			return false;
		}
		if (c === "(") return this.open(current, previous, justOpened);
		if (!WORD_BREAKS.has(c)) {
			this.word += c;
			return false;
		}
		// Ending the word can open or close a `case`, so the frame is read again after it.
		this.endWord();
		const top = this.frames.at(-1);
		if (top === undefined || top.kind === "brace") return false;
		switch (c) {
			case "\n":
				if (top.kind === "group" || top.phase === "arm") this.separate();
				return false;
			case ";":
				if (top.kind === "case" && top.phase === "arm" && previous === ";") this.nextPatternList(top);
				else this.separate();
				return false;
			case "&":
				if (previous === ";") {
					if (top.kind === "case" && top.phase === "arm") this.nextPatternList(top);
				} else if (previous !== "<" && previous !== ">") this.separate();
				return false;
			case "|":
				if (previous !== ">" && !(top.kind === "case" && top.phase === "patterns")) this.separate();
				return false;
			case "<":
				this.commandPosition = false;
				this.noteHeredoc(at, previous, top);
				return false;
			case ">":
				this.commandPosition = false;
				return false;
			case ")":
				return this.close(top);
			default:
				return false;
		}
	}

	/**
	 * Open a group at a `(`. Inside a case pattern list only a `$(` is a group of its own -- a
	 * command substitution, whose own `case` patterns must not close the list -- and any other
	 * `(` (the optional one in front of the list, or an extglob's) is counted as pattern text.
	 */
	private open(top: OpenGroup | OpenCase | OpenBrace, previous: string, justOpened: boolean): false {
		if (top.kind === "case" && top.phase === "patterns" && previous !== "$") {
			if (top.patternStarted || this.word !== "") top.patternDepth += 1;
			else top.patternStarted = true;
			this.word += "(";
			return false;
		}
		if (top.kind === "group" && top.dollar && justOpened) top.arithmetic = true;
		const dollar = previous === "$";
		const substitution = dollar || previous === "<" || previous === ">";
		if (substitution) this.heredocScopes.push(this.heredocs.length);
		this.frames.push({
			kind: "group",
			commandPosition: this.commandPosition,
			word: this.word,
			previousWord: this.previousWord,
			hasContent: false,
			dollar,
			arithmetic: !dollar && top.kind === "group" && top.arithmetic,
			substitution,
		});
		this.word = "";
		this.justOpened = true;
		this.separate();
		return false;
	}

	/**
	 * Read a character of an open `${...}` as word text. A `}` closes it, and a `$` directly
	 * before `{` or `(` opens a nested expansion or a command substitution, as bash's
	 * matched-pair scan reads them there -- a `$$` included.
	 */
	private readInBrace(c: string, previous: string, justOpened: boolean, top: OpenBrace): false {
		if (c === "(" && previous === "$") return this.open(top, previous, justOpened);
		if (c === "{" && previous === "$") this.frames.push({ kind: "brace" });
		else if (c === "}") this.frames.pop();
		this.word += c;
		return false;
	}

	private close(top: OpenGroup | OpenCase): boolean {
		if (top.kind === "case") {
			// Outside a pattern list a `case` has no `)` of its own, so this one is a syntax
			// error; reading on keeps the body open, which over-reads rather than under-reads.
			if (top.phase === "patterns") {
				top.phase = "arm";
				top.patternStarted = false;
				this.separate();
			}
			return false;
		}
		if (this.frames.length === 1 && this.scope === "top-level") return false;
		this.frames.pop();
		if (top.substitution) this.heredocScopes.pop();
		if (this.frames.length === 0) return true;
		if (top.hasContent) {
			this.commandPosition = top.commandPosition;
			this.word = `${top.word}()`;
			this.previousWord = top.previousWord;
		} else this.separate();
		return false;
	}

	private endWord(): void {
		if (this.word === "") return;
		const word = this.word;
		this.word = "";
		const top = this.frames.at(-1);
		if (top?.kind === "group" && top.arithmetic) return;
		if (top?.kind === "case" && top.phase !== "arm") {
			if (top.phase === "subject") top.phase = "in";
			else if (top.phase === "in") top.phase = "patterns";
			else if (word === "esac" && !top.patternStarted) this.closeCase();
			else top.patternStarted = true;
			return;
		}
		if (!this.commandPosition) return;
		if (word === "case") {
			this.frames.push({ kind: "case", phase: "subject", patternDepth: 0, patternStarted: false });
			this.commandPosition = false;
			return;
		}
		if (word === "esac" && top?.kind === "case") {
			this.closeCase();
			return;
		}
		this.commandPosition = precedesCommand(word, this.previousWord);
		this.previousWord = word;
	}

	/**
	 * Note the heredoc a `<` at `at` opens, when it starts a `<<` or `<<-` operator (not a `<<<`
	 * here-string) outside arithmetic. One the guard refuses, or whose delimiter cannot be
	 * spelled as bash spells it, leaves every later body unplaceable -- bash may read a body
	 * this scan takes for structure -- so no further heredoc is recognized.
	 */
	private noteHeredoc(at: number, previous: string, top: OpenGroup | OpenCase): void {
		const source = this.source;
		if (previous === "<" || source[at + 1] !== "<" || source[at + 2] === "<") return;
		if (top.kind === "group" && top.arithmetic) return;
		const heredoc = this.guard.possibleAt(at) ? readHeredocDelimiter(source, at + 2) : null;
		if (heredoc !== null) this.heredocs.push(heredoc);
		else this.refuseHeredocs();
	}

	/** Skip the bodies of the current substitution's pending heredocs, which start at `start`. */
	private readHeredocBodies(start: number): number {
		const first = this.heredocScopes.at(-1) ?? 0;
		if (this.heredocs.length <= first) return start;
		const pending = this.heredocs.splice(first);
		if (!this.guard.possibleAt(start)) {
			this.refuseHeredocs();
			return start;
		}
		let end = start;
		const context = this.scope === "top-level" && this.heredocScopes.length === 1 ? "top-level" : "substitution";
		const skipped: { heredoc: HeredocDelimiter; read: Scanned }[] = [];
		for (const heredoc of pending) {
			const read = readHeredocBody(this.source, end, heredoc, context);
			skipped.push({ heredoc, read });
			end = read.end;
		}
		this.skipped = skipped;
		this.guard.skipTo(end);
		return end;
	}

	private nextPatternList(top: OpenCase): void {
		top.phase = "patterns";
		top.patternStarted = false;
	}

	private closeCase(): void {
		this.frames.pop();
		this.commandPosition = false;
		this.previousWord = undefined;
	}

	private separate(): void {
		this.commandPosition = true;
		this.previousWord = undefined;
	}
}

/**
 * Read a `( ... )` group introduced at `start` by `$`, `<` or `>` -- a command substitution or a
 * process substitution -- following its command structure (see `SubstitutionBody`) and skipping
 * quoted and backslash-escaped regions so a `)` that is argument text or ends a `case` pattern
 * does not close it early. As with quotes, an unterminated group consumes the rest of the input.
 *
 * Process substitution matters as much as `$( )` here: `cat <(git push --force)` RUNS that push,
 * and the raw-text scan this replaces caught it only incidentally, by seeing the words go by.
 */
export function readSubstitution(source: string, start: number): Scanned {
	const end = substitutionEnd(source, start);
	if (end === undefined)
		return { text: source.slice(start + 2), raw: source.slice(start), end: source.length, complete: false };
	return { text: source.slice(start + 2, end - 1), raw: source.slice(start, end), end, complete: true };
}

/**
 * A context `substitutionEnd` has open: a substitution's body, or a double-quoted span opened at
 * `start` inside the `enclosing` one.
 */
type SubstitutionFrame =
	| { kind: "body"; body: SubstitutionBody }
	| { kind: "double"; start: number; enclosing: SubstitutionBody };

/**
 * The index just past the `)` that closes the substitution opened at `start` (see
 * `readSubstitution`), or undefined when it never closes. A double-quoted span in a body is
 * read as bash reads it, and a substitution inside that span opens a body of its own, so a `"`
 * inside that body does not end the span. The open bodies and spans are an explicit stack, so
 * the scan stays linear with no recursion however deeply they alternate.
 */
function substitutionEnd(source: string, start: number): number | undefined {
	const opened = (at: number): SubstitutionFrame => ({
		kind: "body",
		body: new SubstitutionBody(isArithmetic(source, at) ? "arithmetic" : "commands", source, at + 2),
	});
	const frames: SubstitutionFrame[] = [opened(start)];
	let i = start + 2;
	while (i < source.length) {
		const frame = frames[frames.length - 1];
		const c = source[i];
		if (frame.kind === "double") {
			if (c === "\\") i += 2;
			else if (c === "`") i = readBackticks(source, i).end;
			else if (c === "$" && source[i + 1] === "(") {
				frames.push(opened(i));
				i += 2;
			} else {
				if (c === '"') {
					frames.pop();
					frame.enclosing.quoted(source.slice(frame.start, i + 1));
				}
				i += 1;
			}
			continue;
		}
		const body = frame.body;
		const commented = body.inComment;
		if (c === "\\" && !commented) {
			if (source[i + 1] !== "\n") body.quoted(source.slice(i, i + 2));
			i += 2;
		} else if (c === "'" && !commented) {
			const quoted = readQuoted(source, i, c);
			body.quoted(quoted.raw);
			i = quoted.end;
		} else if (c === '"' && !commented) {
			frames.push({ kind: "double", start: i, enclosing: body });
			i += 1;
		} else if (c === "`" && !commented) {
			const backticks = readBackticks(source, i);
			body.quoted(backticks.raw);
			i = backticks.end;
		} else {
			i = body.read(i);
			if (body.closed) {
				frames.pop();
				if (frames.length === 0) return i;
			}
		}
	}
	return undefined;
}

/**
 * Where a backtick substitution sits: bash removes a body's backslash before `"` as well only
 * inside double quotes.
 */
type BacktickContext = "unquoted" | "double-quoted";

const BACKTICK_ESCAPE: Record<BacktickContext, RegExp> = {
	unquoted: /\\([\\`$])/g,
	"double-quoted": /\\([\\`$"])/g,
};

const BACKTICK_ESCAPED: Record<BacktickContext, RegExp> = {
	unquoted: /[\\`$]/g,
	"double-quoted": /[\\`$"]/g,
};

/**
 * Read a backtick substitution starting at `start`. Unterminated runs to the end.
 *
 * `text` is the body as bash parses it: a backslash before `$`, a backtick or a backslash is
 * removed first, and one before `"` too when the substitution sits in double quotes (`context`),
 * so `` `rm -rf \$1` `` runs `rm -rf $1`. Any other backslash stays for the body's own parse.
 */
export function readBackticks(source: string, start: number, context: BacktickContext = "unquoted"): Scanned {
	const body = (end: number): string => source.slice(start + 1, end).replace(BACKTICK_ESCAPE[context], "$1");
	let i = start + 1;
	while (i < source.length) {
		if (source[i] === "\\") {
			i += 2;
			continue;
		}
		if (source[i] === "`") return { text: body(i), raw: source.slice(start, i + 1), end: i + 1, complete: true };
		i += 1;
	}
	return { text: body(source.length), raw: source.slice(start), end: source.length, complete: false };
}

/** A backtick body as it is written in `context`, the inverse of the escapes `readBackticks` removes. */
function escapeBacktickBody(body: string, context: BacktickContext): string {
	return body.replace(BACKTICK_ESCAPED[context], "\\$&");
}

/**
 * True when the `$(` at `start` opens `$((`, an ARITHMETIC expansion.
 *
 * Arithmetic contributes a number, and its own words are not a command: `r$((1))m` is the
 * command `r1m`, and `$((rm -rf /))` runs nothing. So it is neither descended into as a command
 * nor treated as an expansion that could contribute no text -- though a substitution written
 * INSIDE it does execute, and is pulled out separately. `$( (subshell) )` is a command
 * substitution and needs the parentheses adjacent to qualify.
 */
function isArithmetic(source: string, start: number): boolean {
	return source[start] === "$" && source[start + 1] === "(" && source[start + 2] === "(";
}

/** Read a `${ ... }` expansion starting at `start` (the `$`), balancing nested braces. */
function readBraced(source: string, start: number): Scanned {
	let depth = 0;
	let i = start + 1;
	while (i < source.length) {
		const c = source[i];
		if (c === "\\") {
			i += 2;
			continue;
		}
		if (c === "{") depth += 1;
		if (c === "}") {
			depth -= 1;
			if (depth === 0)
				return { text: source.slice(start + 2, i), raw: source.slice(start, i + 1), end: i + 1, complete: true };
		}
		i += 1;
	}
	return { text: source.slice(start + 2), raw: source.slice(start), end: source.length, complete: false };
}

/**
 * The bodies of the substitutions inside `text` that bash executes.
 *
 * Arithmetic is not itself a command, but it is not inert either: bash evaluates
 * `$(( $(git push --force) ))` by RUNNING that push first. So an arithmetic span is not handed
 * to the tokenizer as a command, and instead the executable substitutions written inside it are
 * pulled out -- through further arithmetic nesting as well.
 *
 * Nesting is walked with an explicit work list rather than by recursion, and charged to the same
 * budget as every other descent. An arithmetic layer costs about four characters to write, so
 * recursing per layer would let a small input drive the call stack to its limit -- and this runs
 * inside the floor, which must return a verdict rather than throw.
 */
export type ShellNestedKind =
	| "argument-source"
	| "command-substitution"
	| "process-substitution"
	| "backtick"
	| "heredoc"
	| "here-string"
	| "quoted-potential";

/**
 * Which way a process substitution's data flows: an `"output"` one (`>(...)`) reads what its
 * run writes to it, an `"input"` one (`<(...)`) is read by its run.
 */
type ProcessSubstitutionDirection = "output" | "input";

/** The direction of the substitution `opener` (`$`, `<` or `>`) starts; undefined for a command substitution. */
function processSubstitutionDirection(opener: string): ProcessSubstitutionDirection | undefined {
	if (opener === ">") return "output";
	if (opener === "<") return "input";
	return undefined;
}

/**
 * A live `$` or backtick in a word's spelling (a quoted one is `EXPANSION_SUPPRESSED` there): an
 * expansion the outer shell performs, whose output can change how the receiving shell quotes the
 * rest of the word, as `bash -c "echo '$(printf %b \\047)\$(cmd)$(printf %b \\047)'"` runs `cmd`.
 */
const OUTER_EXPANSION = /[$`]/;

interface NestedSource {
	source: string;
	kind: ShellNestedKind;
	complete: boolean;
	/**
	 * The source is a word as the program it is handed to receives it, its escaped `$` and
	 * backticks live (`bash -c "rm -rf \$HOME"` reads `rm -rf $HOME`, as does `bash <<< "rm -rf
	 * \$HOME"`), and the word's spelling holds no expansion of the outer shell's own
	 * (`OUTER_EXPANSION`), so the text is exactly what the receiving shell parses and is not taken
	 * for text the outer shell expanded: a single-quoted `'\$(cmd)'` in it stays inert.
	 */
	receivedText?: true;
	/** A process substitution's direction (`processSubstitutionDirection`). */
	direction?: ProcessSubstitutionDirection;
	/**
	 * The process substitution fills the target of a redirection that opens it for writing (`>
	 * <(...)`, `2>><(...)`). On Linux, opening the `/dev/fd` path of an input one for writing
	 * reopens its pipe, so its body reads what the run writes just as an output one's does.
	 */
	writeTarget?: boolean;
	/**
	 * The argv of the run the source was found in. Captured by reference while the run
	 * is still being assembled and read only after the scan, when the array is full --
	 * the same object lands in `runs`/`topLevel`, so it always ends up populated.
	 */
	run?: string[];
	/**
	 * The quoted-potential or substitution source's containing word IS its run's command --
	 * the word that names what runs, which is not always index 0: a reserved word can stand
	 * in front of it (`for i in 1; do 'rm -rf /'; done`), and comparing against 0 read the
	 * payload there as an ordinary operand.
	 */
	commandPosition?: boolean;
	/** The quoted or substitution source occupies an argument position that a wrapper or interpreter executes. */
	executablePosition?: boolean;
	/**
	 * The variable a command or backtick substitution's output is stored in: the substitution
	 * starts the value of a bare assignment in an assignment position (`x=$(...)`, `x+=$(...)`,
	 * `export x=$(...)`). Its body is read as a payload when the source runs that variable as a
	 * command (`variablesRunAsCommands`).
	 */
	assignedName?: string;
	/** Its index in the containing run, used to assign executable provenance after tokenization. */
	argIndex?: number;
	/** An unquoted `=` preceded the quoted region inside its word (`alias.nuke='!...'`). */
	assignment?: boolean;
	/**
	 * The source's quote delimiter, when it came from one quoted region. A heredoc body
	 * carries `'` when its delimiter word was quoted, which makes the body literal.
	 */
	quote?: "'" | '"';
	/** The quoted run never closed, so the quoting structure itself is untrusted. */
	unterminated?: boolean;
	/** The source's own lex, once taken (`lexedNestedSource`). */
	lexed?: LexedSource;
	/** `textReadsPipe`'s verdicts on the source's text, one per reading. */
	pipeVerdicts?: Partial<Record<"doubleQuoted" | "unquoted", PipeVerdict>>;
	/** `textRunsInterpreter`'s verdicts on the source's text, one per reading. */
	interpreterVerdicts?: Partial<Record<"doubleQuoted" | "unquoted", boolean>>;
}

/** A kept `textReadsPipe` verdict and the size `definedNames` had when it was taken. */
interface PipeVerdict {
	definedNames: number;
	readsPipe: boolean;
}

/**
 * The substitutions an arithmetic expansion's `text` runs, reading nested arithmetic as far as
 * `budget` allows. `unread` is true when the budget ran out with arithmetic text still unread,
 * so a substitution in it may be missing from `spans`.
 */
function executableSpansIn(
	text: string,
	budget: { left: number },
): { spans: NestedSource[]; complete: boolean; unread: boolean } {
	const spans: NestedSource[] = [];
	const pending = [text];
	let complete = true;
	while (pending.length > 0 && budget.left > 0) {
		const body = pending.pop() as string;
		budget.left -= body.length;
		let i = 0;
		while (i < body.length) {
			const c = body[i];
			if ((c === "$" || c === "<" || c === ">") && body[i + 1] === "(") {
				const span = readSubstitution(body, i);
				complete &&= span.complete;
				if (isArithmetic(body, i)) pending.push(span.text);
				else
					spans.push({
						source: span.text,
						kind: c === "$" ? "command-substitution" : "process-substitution",
						direction: processSubstitutionDirection(c),
						complete: span.complete,
					});
				i = span.end;
				continue;
			}
			if (c === "`") {
				const span = readBackticks(body, i);
				complete &&= span.complete;
				spans.push({ source: span.text, kind: "backtick", complete: span.complete });
				i = span.end;
				continue;
			}
			i += 1;
		}
	}
	const unread = pending.length > 0;
	if (unread) complete = false;
	return { spans, complete, unread };
}

/**
 * A word with every no-text expansion removed, so what is left is the text the word contributes
 * on its own -- `r$($())m` is `rm`, and `git pu$(x)sh` is `git push`.
 *
 * PROCESS substitution and ARITHMETIC expansion are left in place, unlike the rest: `<(cmd)`
 * always expands to a `/dev/fd/N` path and `$((1))` to a number, so `r<(true)m` and `r$((1))m`
 * never run `rm`, and erasing either span would invent a command bash will not execute.
 *
 * Scanned with the same balanced readers the tokenizer uses rather than with a pattern, because
 * a pattern for this is nesting-blind: `\$\([^()]*\)` removes only the innermost `$()` of
 * `$($())` and leaves a second one behind, with the word still unrecognized. One linear pass
 * here removes them all, however they nest.
 */
export function stripExpansions(word: string): string {
	let out = "";
	let i = 0;
	while (i < word.length) {
		const c = word[i];
		if (c === "$" && word[i + 1] === "(") {
			const span = readSubstitution(word, i);
			if (isArithmetic(word, i)) out += span.raw;
			i = span.end;
			continue;
		}
		if (c === "$" && word[i + 1] === "{") {
			i = readBraced(word, i).end;
			continue;
		}
		if (c === "`") {
			i = readBackticks(word, i).end;
			continue;
		}
		out += c;
		i += 1;
	}
	return out;
}

/** A parameter expansion written without braces: `$name`, `$1`, or a special parameter (`$@`). */
const UNBRACED_PARAMETER = /\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/g;
const UNBRACED_PARAMETER_AT = new RegExp(UNBRACED_PARAMETER.source, "y");

/**
 * Whether the text of a double-quoted run always gives its word at least one character: some of
 * it is not an expansion, since any expansion but arithmetic may give none (`"$v"`, `"${v}"`,
 * `"$(true)"`).
 */
function doubleQuotedTextIsLiteral(text: string): boolean {
	return /^[^$`]/.test(text) || stripExpansions(text).replace(UNBRACED_PARAMETER, "").length > 0;
}

/**
 * The index just past the unquoted text the `$` at `start` opens that may give its word no
 * characters: a parameter expansion (`$v`, `$1`, `${v}`) or the `$` of a `$"..."` locale string,
 * which bash drops. `start` itself when the `$` is a literal character.
 */
function mayGiveNoTextEnd(source: string, start: number): number {
	const next = source[start + 1];
	if (next === "{") return readBraced(source, start).end;
	if (next === '"') return start + 1;
	UNBRACED_PARAMETER_AT.lastIndex = start;
	const parameter = UNBRACED_PARAMETER_AT.exec(source);
	return parameter === null ? start : start + parameter[0].length;
}

/**
 * Split a command string into one dequoted argv array per command run.
 *
 * Runs are separated by unquoted `&&`, `||`, `;`, `|`, `&`, subshell parentheses and newlines,
 * so a rule is scoped to one command BY CONSTRUCTION rather than by a hand-written character
 * bound -- which is what keeps `git push origin main && tail -f server.log` from reading as a
 * force push while `git push origin 'feature;stuff' -f` still does read as one.
 *
 * An `&` or `|` that belongs to a REDIRECTION (`2>&1`, `>&2`, `&>log`, `>|log`) is not a
 * separator: splitting there would end the run before the rest of its own arguments, leaving
 * `git push 2>&1 --force` and `rm -rf >| log /` looking like a plain push and a plain delete.
 * What counts is a LIVE `<`/`>` -- one written as syntax, not one quoting or a backslash made
 * literal -- so the pipe in `rm -rf ./build\>|echo /` still separates two ordinary commands.
 *
 * A `#` that STARTS a word begins a comment, and the rest of the line is not executed at all --
 * so `rm -rf ./build # /` deletes `./build` and nothing else. Mid-word it is ordinary text
 * (`file#1`).
 *
 * Outside quotes a `\` escapes the next character, and `\` before a newline is a line
 * continuation that bash removes outright -- so `rm -rf \<newline>/` is the same command as
 * `rm -rf /` and is tokenized as one.
 *
 * A redirection may be written ATTACHED to the word before it, and it still redirects rather
 * than becoming part of that word: `git push>log --force` is a force push, and `rm -rf>log /`
 * deletes root. A live `<`/`>` therefore starts a new word unless what precedes it in the word
 * can be part of the operator (an fd number, `{name}`, or the `&` of `&>`).
 *
 * The result also carries the runs found inside quoted arguments, command substitutions, and
 * executable source arguments (`bash -c`, `eval`, `trap`, `env -S`, command-string wrappers),
 * as deep as `budget` allows (see `MAX_NEST_WORK`). Substitution and source bodies always
 * contribute because the caller executes them. A QUOTED word's own commands contribute only
 * when the word occupies an executable position: it is its run's own command,
 * its run carries an interpreter-like head, it is an assignment value, its run pipes into an
 * interpreter, or its quote never closed. A quoted
 * word elsewhere is a prose operand -- a commit message, a grep pattern -- and re-reading it
 * as a command made the terminal floor fire on text that documents a dangerous shape.
 * Suppressed words still recurse: their substitution descendants contribute, and the
 * `nested` inventory is unchanged either way (scratch-dir provenance reads it, failing closed
 * on every substitution kind).
 * Pass `0` to tokenize only what is written at the top level.
 *
 * Quotes are removed, but the characters whose EXPANSION they suppressed are replaced by
 * `EXPANSION_SUPPRESSED` rather than passed through as themselves -- see that constant. Never
 * throws.
 */
export type ShellControlOperator = "&&" | "||" | ";" | "|" | "&" | "\n";

export type ShellTopLevelPart =
	| { kind: "command"; argv: string[] }
	| { kind: "operator"; operator: ShellControlOperator }
	| { kind: "group"; boundary: "start" | "end" };

export interface ShellNestedRun {
	kind: ShellNestedKind;
	argv: string[];
}

export interface ShellCommandAnalysis {
	complete: boolean;
	topLevel: ShellTopLevelPart[];
	nested: ShellNestedRun[];
}

export interface ExecutableShellAnalysis {
	analysis: ShellCommandAnalysis;
	/**
	 * Whether what the source's commands print reaches a command that may execute it: the run
	 * carrying the source is piped into one, or its own output redirections reach one
	 * (`SinkVerdicts.outputExecutedRuns`: `bash -c '...' > >(sh)`, `exec > >(sh); bash -c '...'`).
	 */
	piped: boolean;
	/** The frame's pipeline walk verdicts on its top-level runs (`SinkVerdicts`). */
	sinkVerdicts: SinkVerdicts;
	/** The source text the analysis read, as the shell parses it. */
	source: string;
}

/**
 * What a frame's pipeline walk (`analyzeLexed`) judged of its top-level runs, by argv identity.
 * `executingSinks` are the runs right of a `|` that may execute what reaches them: an
 * interpreter reading its input as commands (`pipeReaderWords`), a name that may not mean the
 * program it usually does (`rebindsCommandName`: `$SHELL`, `s?`, `/tmp/cat`, a defined `cat`),
 * or a run whose substitution runs such a command (`substitutionsReadPipe`: `cat "$(sh)"`);
 * every such run when an `eval` or `trap` operand could not be read for its definitions.
 * `outputExecutedRuns` are the runs whose own output redirections reach such a command: an
 * output process substitution running one (`outputSubstitutionsReadRun`: `> >(sh)`), and every
 * run of a frame whose redirections an `exec` may have sent to one (`mayPersistRedirections`).
 */
export interface SinkVerdicts {
	executingSinks: ReadonlySet<string[]>;
	outputExecutedRuns: ReadonlySet<string[]>;
}

interface ScanResult extends ShellCommandAnalysis {
	runs: string[][];
	sinkVerdicts: SinkVerdicts;
	shellAnalyses: ExecutableShellAnalysis[];
	/** Heredoc recognition was requested but the command is not heredoc data writing as a whole. */
	heredocsRejected?: boolean;
	/**
	 * The nesting budget ran out while a nested source that would have been read was still
	 * unread, so a command in it is missing from `runs` (see `MAX_NEST_WORK`).
	 */
	nestedUnread: boolean;
}

/**
 * Commands whose standard input is data, never shell: a heredoc fed to one is text being written
 * or parsed (`cat > notes.md`, `tee`, `jq`). Membership is the ONLY way a body counts as text
 * data. Recognizing shell consumers instead failed open on every spelling left out -- a group
 * (`(bash) <<EOF`), an option layout (`bash -s -- -c`), a redirect ahead of the command
 * (`<<'' bash`) -- while an unlisted consumer here only keeps the body read as shell, the
 * fail-closed direction. `git` is deliberately absent: any subcommand may be a shell alias
 * (`!bash`) that inherits the heredoc as its stdin.
 */
const HEREDOC_TEXT_CONSUMERS = new Set(["cat", "tee", "jq", "yq"]);

/** A data consumer named by a path is trusted only in a system binary directory. */
const SYSTEM_BIN_PATH = /^\/(?:usr\/(?:local\/)?)?bin\/[^/]+$/;

/** A heredoc operator word: `<<` or `<<-`, delimiter attached or next -- not a `<<<` here-string. */
const HEREDOC_OPERATOR_WORD = /^<<(?!<)/;

/** A write of stdout or stderr to a file: `>`, `>>`, `>|`, `1>`, `2>`, `&>`, `&>>`, target attached or next. */
const DATA_WRITE_REDIRECTION = /^(?:[12]?(?:>>|>\||>)|&>>?)(.*)$/s;

/**
 * A character that makes a word more than its literal text: an expansion, a glob or brace list,
 * or a redirection or substitution character (`&` included: `>&x` names a file too). Quoted ones
 * never reach here -- the tokenizer replaces them with `EXPANSION_SUPPRESSED`, a NUL, which is
 * itself refused: an ANSI-C `$'x\0y'` spells a real NUL, where bash truncates the word.
 */
const NON_LITERAL = /[$`{}*?[\]<>()&\u0000]/;

/**
 * What a heredoc-fed run's stdin reaches: `text` for a command that only reads it (`cat`, `tee`,
 * `jq`, `yq`), or `program` for Python reading its program from it (`python3 -`). Python alone:
 * a Ruby, Perl or PHP program runs backticks as shell, which the inline-program reading of the
 * body does not treat as executable.
 */
type HeredocConsumer = "text" | "program";

/**
 * The consumer this run hands its heredoc to, when every word of the run is provably inert
 * around it; undefined otherwise, which keeps the command's shell reading.
 *
 * The run is read word by word rather than through the general command walkers, which are built
 * to over-match for detection and so misplace a receiver when a word shifts (`<<<'' bash ...
 * cat`, `env --argv0 cat /bin/bash`). The head must BE the consumer -- no wrapper, assignment
 * or redirection in front -- and every later word must be a heredoc operator, a stdout or stderr
 * write to a literal file, or a literal operand; an interpreter takes nothing but `-`.
 */
function heredocConsumer(argv: string[]): HeredocConsumer | undefined {
	const name = trustedCommandName(argv[0] ?? "");
	const kind: HeredocConsumer | undefined = HEREDOC_TEXT_CONSUMERS.has(name)
		? "text"
		: PYTHON_HEAD.test(name)
			? "program"
			: undefined;
	if (kind === undefined) return undefined;
	for (let i = 1; i < argv.length; i++) {
		const word = argv[i];
		if (HEREDOC_OPERATOR_WORD.test(word)) {
			if (word === "<<" || word === "<<-") i += 1;
			continue;
		}
		const write = DATA_WRITE_REDIRECTION.exec(word);
		let operand = word;
		if (write !== null) {
			operand = write[1].length > 0 ? write[1] : (argv[++i] ?? "");
			if (operand.length === 0) return undefined;
		} else if (kind === "program" && word !== "-") return undefined;
		if (NON_LITERAL.test(operand)) return undefined;
	}
	return kind;
}

/**
 * An expansion in unquoted heredoc body text that can run code: a substitution (`$(`, a
 * backtick, `<(`, `>(`), or `$[` / `${`, whose arithmetic (a subscript, an offset) can
 * evaluate a substitution assembled from parameter values bash builds at run time.
 */
const BODY_SUBSTITUTION = /\$[([{]|`|[<>]\(/;

/** A descriptor prefix on a heredoc operator (`3<<`, `{fd}<<`): not the consumer's stdin. */
const HEREDOC_FD_PREFIX = /^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})$/;

/**
 * The command name a word runs, exactly as spelled, when it can be trusted to name that
 * program: bare, or a path in a system binary directory. Anything else (`/tmp/env`, a
 * symlink to a shell) yields the empty string, which matches no trusted set.
 */
function trustedCommandName(word: string): string {
	if (word.includes("/") && !SYSTEM_BIN_PATH.test(word)) return "";
	return word.slice(word.lastIndexOf("/") + 1);
}

/**
 * Whether a command word is a path outside the system binary directories (`/tmp/cat`,
 * `./cat`, `bin/cat`), whose basename says nothing about the program it runs: it may be a
 * symlink to a shell.
 */
function namedByUntrustedPath(word: string): boolean {
	return word.includes("/") && trustedCommandName(word) === "";
}

/** The test builtin and keyword spelled as brackets. */
const TEST_BRACKETS = new Set(["[", "[["]);

/**
 * Whether the command word at `index` of `argv` says nothing about the program it runs, so it
 * may be a shell: a path outside the system binary directories (`namedByUntrustedPath`), or a
 * word that can expand into another name (`wordMayExpand`: `$SHELL`, `"$x"`, `${SH}`, `s?`).
 * A lone `[` or `[[` is neither: an unclosed bracket never globs, so it names only the test
 * builtin or keyword, whose `-c` is a file test (`[ -c /dev/tty ]`). Such a command's shell
 * sources are read in both a POSIX-style shell's and fish's reading, so the `-c` value a
 * non-shell takes (`$CC -c foo.c`, `$EDITOR -c 'set nu' notes.txt`, `$PYTHON -c 'print(1)'`)
 * is read as a script too, and is denied only where `bash -c` given the same text is
 * (`$PYTHON -c "print('rm -rf /')"` is).
 */
function namesUnknownCommand(argv: string[], index: number): boolean {
	return namedByUntrustedPath(argv[index]) || (!TEST_BRACKETS.has(argv[index]) && wordMayExpand(argv, index));
}

/**
 * The variables the runs of `topLevel` execute: one whose value is expanded in a word the shell
 * or a wrapper runs as a command (`executableCommandIndexes`) -- `$x`, `"$x"`, `${x}`,
 * `${x:+$x}`, `sudo $x`, `eval "$x"`, `bash -c "$x"` -- in any word of a run of
 * `executingRuns`, whose words reach an interpreter (`echo "$x" | sh`), or in a text of
 * `scripts`, the here-strings a shell reads as its script (`bash <<< "$x"`).
 */
function variablesRunAsCommands(
	topLevel: ShellTopLevelPart[],
	executingRuns: ReadonlySet<string[]>,
	scripts: readonly string[],
): Set<string> {
	const names = new Set<string>();
	for (const script of scripts) for (const match of script.matchAll(VALUE_EXPANSIONS)) names.add(match[1] ?? match[2]);
	for (const part of topLevel) {
		if (part.kind !== "command") continue;
		const words = redirectionFreeWords(part.argv);
		const runWords = executingRuns.has(part.argv)
			? words
			: executableCommandIndexes(words).map((index) => words[index]);
		for (const word of runWords) for (const match of word.matchAll(VALUE_EXPANSIONS)) names.add(match[1] ?? match[2]);
	}
	return names;
}

/**
 * The text of an unquoted heredoc body as bash expands it: a backslash-newline pair is removed
 * first, so `$\` + newline + `(cmd)` is a command substitution. An escaped backslash stays, and
 * the newline after it is kept.
 */
function joinHeredocContinuations(body: string): string {
	let out = "";
	let i = 0;
	while (i < body.length) {
		if (body[i] === "\\" && i + 1 < body.length) {
			if (body[i + 1] !== "\n") out += body.slice(i, i + 2);
			i += 2;
			continue;
		}
		out += body[i];
		i += 1;
	}
	return out;
}

interface PendingHeredoc {
	delimiter: string;
	/** `<<-`: leading tabs are stripped before a line is compared with the delimiter. */
	stripTabs: boolean;
	/** Any part of the delimiter word was quoted or escaped, so bash expands nothing in the body. */
	quoted: boolean;
	run: string[];
}

/** A heredoc's delimiter as its body is matched against, apart from the run it feeds. */
type HeredocDelimiter = Omit<PendingHeredoc, "run">;

/**
 * Where a heredoc is read: at the top level, or inside a `$(...)`, `<(...)` or `>(...)` body,
 * where bash also ends it at a line that starts with the delimiter and holds a `)`.
 */
type HeredocContext = "top-level" | "substitution";

/**
 * Read the delimiter word of a heredoc whose `<<` ends just before `start`, with bash's quote
 * removal. The word ends only at a bash metacharacter -- a carriage return, form feed or
 * vertical tab is part of it. Returns null for a spelling whose terminator bash might compute
 * differently -- an expansion in the word, or an unterminated quote -- which leaves the lines
 * after it to be read as shell rather than risk ending the body later than bash does.
 */
function readHeredocDelimiter(source: string, start: number): HeredocDelimiter | null {
	let i = start;
	const stripTabs = source[i] === "-";
	if (stripTabs) i += 1;
	while (source[i] === " " || source[i] === "\t") i += 1;
	const expands = (at: number): boolean =>
		source[at] === "`" || (source[at] === "$" && "'\"({[".includes(source[at + 1] ?? ""));
	let delimiter = "";
	let quoted = false;
	while (i < source.length) {
		const c = source[i];
		if (c === " " || c === "\t" || SEPARATORS.has(c) || c === "<" || c === ">") break;
		if (expands(i)) return null;
		if (c === "\\") {
			if (i + 1 >= source.length) return null;
			if (source[i + 1] !== "\n") {
				delimiter += source[i + 1];
				quoted = true;
			}
			i += 2;
			continue;
		}
		if (c === "'") {
			const end = source.indexOf("'", i + 1);
			if (end === -1) return null;
			delimiter += source.slice(i + 1, end);
			quoted = true;
			i = end + 1;
			continue;
		}
		if (c === '"') {
			let j = i + 1;
			while (j < source.length && source[j] !== '"') {
				if (expands(j)) return null;
				if (source[j] === "\\" && '$`"\\\n'.includes(source[j + 1] ?? "")) {
					if (source[j + 1] !== "\n") delimiter += source[j + 1];
					j += 2;
					continue;
				}
				delimiter += source[j];
				j += 1;
			}
			if (j >= source.length) return null;
			quoted = true;
			i = j + 1;
			continue;
		}
		delimiter += c;
		i += 1;
	}
	return delimiter.length > 0 || quoted ? { delimiter, stripTabs, quoted } : null;
}

/**
 * The body of a heredoc starting at `start`, up to the first line bash accepts as its
 * terminator: exactly the delimiter, after stripping the line's leading tabs for `<<-`.
 *
 * A quoted delimiter compares physical lines, and for `<<-` a line equal to the delimiter
 * BEFORE stripping also ends the body -- a quoted delimiter may itself start with a tab
 * (`<<-'<tab>EOF'`), which bash never strips. In an unquoted body bash first joins a line ending
 * in an odd run of backslashes with the next one (`EO\` + `F` is a terminator, while a physical
 * `EOF` continuing `x\` is not), stripping tabs only at the start of the joined line. Matching
 * must be exact in BOTH directions: ending later hides the commands after the real terminator,
 * and ending earlier can open a heredoc bash never sees, whose body then hides them instead.
 * Unterminated, the body runs to the end of the source, as bash reads it.
 *
 * In a `"substitution"` context bash also ends the body at a line that starts with the
 * delimiter and holds a `)` anywhere after it (`EOF)`, `EOF cmd)`), and reads the rest of that
 * line, from just past the delimiter, as shell again: `end` is then that point, not the line's
 * end. That line is taken after `<<-` strips its tabs, never before, and in an unquoted body it
 * is the joined one, so the `)` may sit on a later physical line (`EOFx\` + `y)`).
 */
function readHeredocBody(
	source: string,
	start: number,
	heredoc: HeredocDelimiter,
	context: HeredocContext = "top-level",
): Scanned {
	const { delimiter } = heredoc;
	const strip = (text: string): string => (heredoc.stripTabs ? text.replace(/^\t+/, "") : text);
	const extend = (prefix: string, text: string): string => (prefix === "" ? strip(text) : prefix + text);
	// The continued logical line so far, tabs already stripped; null once longer than the
	// delimiter, since it can then never match. Bounding it keeps the scan linear.
	let joined: string | null = "";
	// The index just past the delimiter, once the logical line read so far starts with it.
	let pastDelimiter: number | undefined;
	const delimiterEnd = (line: string, lineStart: number): number | undefined => {
		const stripped = strip(line);
		const tabs = line.length - stripped.length;
		if (heredoc.quoted || joined === "")
			return stripped.startsWith(delimiter) ? lineStart + tabs + delimiter.length : undefined;
		return joined !== null && (joined + line).startsWith(delimiter)
			? lineStart - joined.length + delimiter.length
			: undefined;
	};
	let i = start;
	while (i < source.length) {
		const newline = source.indexOf("\n", i);
		const lineEnd = newline === -1 ? source.length : newline;
		const line = source.slice(i, lineEnd);
		const terminates = heredoc.quoted
			? line === delimiter || strip(line) === delimiter
			: joined !== null && extend(joined, line) === delimiter;
		if (terminates) {
			const end = Math.min(lineEnd + 1, source.length);
			return { text: source.slice(start, i), raw: source.slice(start, end), end, complete: true };
		}
		let backslashes = 0;
		while (backslashes < line.length && line[line.length - 1 - backslashes] === "\\") backslashes += 1;
		if (context === "substitution") {
			pastDelimiter ??= delimiterEnd(line, i);
			if (pastDelimiter !== undefined && source.slice(Math.max(pastDelimiter, i), lineEnd).includes(")"))
				return {
					text: source.slice(start, i),
					raw: source.slice(start, pastDelimiter),
					end: pastDelimiter,
					complete: true,
				};
			if (heredoc.quoted || backslashes % 2 === 0) pastDelimiter = undefined;
		}
		if (backslashes % 2 === 0) joined = "";
		else if (joined !== null) {
			const next = extend(joined, line.slice(0, -1));
			joined = next.length > delimiter.length ? null : next;
		}
		i = lineEnd + 1;
	}
	return { text: source.slice(start), raw: source.slice(start), end: source.length, complete: false };
}

/**
 * A `${NAME}` expansion that closes where it starts. Any other `${`, a `$[`, or a `((` makes
 * a later `<<` ambiguous: bash reads a shift or literal text there, not a heredoc (`((x<<2))`,
 * `${x:-"}"<<2}`), and taking one for a heredoc would hide the lines after it as body text.
 * An open `[` does the same until its `]` -- an array subscript is arithmetic, with or without
 * a name in front (`a[1<<2]=x`, `a=(cat [1<<2]=x)`) -- as does a compound assignment `=(`, and
 * any backslash-newline: bash removes it before parsing, so it can split one of those openers
 * (`$\` + newline + `{v:-<<EOF}`) where a character scan no longer sees it.
 */
const SIMPLE_PARAMETER = /\$\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9#?$!@*-])\}/y;

/**
 * How a `HeredocGuard` takes a `$(`, `<(` or `>(`: as an opener it cannot see past (`opaque`),
 * or as one its caller follows itself (`followed`), as a substitution body's scanner does. A
 * `followed` caller reads `$'...'` as a plain single-quoted span, so there a `$'` is an opener
 * it cannot see past.
 */
type SubstitutionOpeners = "opaque" | "followed";

/**
 * Whether a `<<` at a given point of a source may be read as a heredoc: only where nothing
 * before it opens a context in which bash reads `<<` as something else (see
 * `SIMPLE_PARAMETER`), or which a scanner here may end early -- a backtick, a
 * backslash-newline, and a `$(`, `<(` or `>(` unless its caller follows it. An open `[` holds
 * recognition off until its `]`. Scanned incrementally and never reset, so the check stays
 * linear however many `<<` the source holds; once ambiguous, it stays so.
 */
class HeredocGuard {
	private scanned: number;
	private openSubscripts = 0;
	private ambiguous = false;

	constructor(
		private readonly source: string,
		start: number,
		private readonly substitutions: SubstitutionOpeners,
	) {
		this.scanned = start;
	}

	possibleAt(end: number): boolean {
		const source = this.source;
		while (!this.ambiguous && this.scanned < end) {
			const k = this.scanned;
			if (source[k] === "$" && source[k + 1] === "{") {
				SIMPLE_PARAMETER.lastIndex = k;
				if (SIMPLE_PARAMETER.test(source)) {
					this.scanned = SIMPLE_PARAMETER.lastIndex;
					continue;
				}
				this.ambiguous = true;
			} else if (
				this.substitutions === "followed" &&
				(source[k] === "$" || source[k] === "<" || source[k] === ">") &&
				source[k + 1] === "("
			) {
				this.scanned = k + 2;
				continue;
			} else if (
				(this.substitutions === "followed" && source[k] === "$" && source[k + 1] === "'") ||
				(source[k] === "$" && (source[k + 1] === "[" || source[k + 1] === "(")) ||
				((source[k] === "<" || source[k] === ">") && source[k + 1] === "(") ||
				(source[k] === "(" && source[k + 1] === "(") ||
				(source[k] === "=" && source[k + 1] === "(") ||
				(source[k] === "\\" && source[k + 1] === "\n") ||
				source[k] === "`"
			)
				this.ambiguous = true;
			else if (source[k] === "[") this.openSubscripts += 1;
			else if (source[k] === "]" && this.openSubscripts > 0) this.openSubscripts -= 1;
			this.scanned = k + 1;
		}
		return !this.ambiguous && this.openSubscripts === 0;
	}

	/** Take the source up to `end` as read -- a heredoc body, whose text opens nothing. */
	skipTo(end: number): void {
		this.scanned = Math.max(this.scanned, end);
	}

	/** Recognize no further heredoc: a `<<` was met that cannot be read as bash reads it. */
	markAmbiguous(): void {
		this.ambiguous = true;
	}
}

const UNSUPPORTED_HEADS = new Set([
	"!",
	"[[",
	"]]",
	"{",
	"}",
	"case",
	"coproc",
	"do",
	"done",
	"elif",
	"else",
	"esac",
	"fi",
	"for",
	"function",
	"if",
	"in",
	"select",
	"then",
	"time",
	"until",
	"while",
]);

/**
 * Tokenize a whole tool-call command.
 *
 * A heredoc body is read as data only when the ENTIRE command is one data consumer fed its
 * own recognized, terminated heredocs (`cat > notes.md <<'EOF' ... EOF`). Anything else -- a
 * pipe, a group, or any other command beside it -- is tokenized again with heredocs not
 * recognized at all, which reads the bodies as shell exactly as before heredoc support. Each
 * command that runs alongside a heredoc can route its body into a shell (a later `bash x.sh`,
 * `| find . -exec sh \;`, a `trap` that redefines `cat`, a write that replaces the next
 * consumer's binary through a symlink), and no enumeration of those routes has held up; with
 * no other command present, there is none. In that fallback reading an unquoted body still
 * expands a substitution written inside single quotes, which `analyzeLexed` catches from the
 * `<<` operator in the frame's source (`singleQuotesLive`).
 */
function tokenizeCommand(source: string, budget: number): ScanResult {
	if (source.includes("<<")) {
		const withHeredocs = tokenizeInto(source, nestBudget(budget), "gate", true);
		if (!withHeredocs.heredocsRejected) return withHeredocs;
	}
	return tokenizeInto(source, nestBudget(budget));
}

export function tokenizeCommandRuns(source: string, budget: number = MAX_NEST_WORK): string[][] {
	return tokenizeCommandForFloor(source, budget).runs;
}

/**
 * Which part of a command the floor's tokenization left unread: `none`; `nested`, when the
 * nesting budget ran out with a nested source that would have been read still unread, so a
 * command in it is missing from the runs; or `all`, when the tokenizer threw and no run was read.
 */
export type FloorUnread = "none" | "nested" | "all";

/**
 * Tokenize a whole tool-call command into its runs (`tokenizeCommandRuns`), and report which
 * part of it was left unread (`FloorUnread`). Never throws.
 */
export function tokenizeCommandForFloor(
	source: string,
	budget: number = MAX_NEST_WORK,
): { runs: string[][]; unread: FloorUnread } {
	try {
		const { runs, nestedUnread } = tokenizeCommand(source, budget);
		return { runs, unread: nestedUnread ? "nested" : "none" };
	} catch {
		return { runs: [], unread: "all" };
	}
}

export function analyzeShellCommand(source: string, budget: number = MAX_NEST_WORK): ShellCommandAnalysis {
	try {
		const { complete, topLevel, nested } = tokenizeCommand(source, budget);
		return { complete, topLevel, nested };
	} catch {
		return { complete: false, topLevel: [], nested: [] };
	}
}

/**
 * Analyze the shell-executed nested sources without reparsing their descendants. The first entry
 * is always the command itself, so an empty result means the analysis threw and nothing was read.
 */
export function analyzeExecutableShellSources(
	source: string,
	budget: number = MAX_NEST_WORK,
): ExecutableShellAnalysis[] {
	try {
		const { complete, topLevel, nested, sinkVerdicts, shellAnalyses } = tokenizeCommand(source, budget);
		return [{ analysis: { complete, topLevel, nested }, piped: false, sinkVerdicts, source }, ...shellAnalyses];
	} catch {
		return [];
	}
}

/**
 * How the quoted-word gating treats this tokenization's content.
 *
 * `gate` is a fresh command line (the top level, a substitution body, or a script a shell
 * runs from an argument -- `bash -c '...'`, `eval`, `trap` -- each of which bash parses as
 * one): quoted words surface only from executable positions, since inside the script a
 * quoted operand is as much data as at the top level. `payload` is text whose quoted words
 * may themselves run -- an emitted quoted word (`node -e '...'`'s program, a word piped
 * into a shell) or the body of a substitution whose output runs as a command: everything
 * in it is script, so gating is off. `prose` is the inside of a SUPPRESSED quoted word:
 * nothing at any depth of it is a command in its own right, so no quoted word surfaces
 * -- without this, the positional predicates would re-fire one frame down
 * (`git commit -m 'restructure;"rm -rf /" was removed'` puts the inner quote in command
 * position of its child frame; an apostrophe in a message makes the tail an unterminated
 * quote) and re-create the terminal prose false positive. A substitution written inside
 * prose still recurses as `gate`: bash executes it wherever it appears. `prose-single` is
 * the inside of a suppressed SINGLE-quoted word (or `$'...'`), where bash expands nothing:
 * a substitution in it is literal text, so it is inventoried but contributes no runs.
 */
type TokenizeMode = "gate" | "payload" | "prose" | "prose-single";

/**
 * The nesting work one tokenization may still spend, in characters read: `left` for analyzing
 * nested sources, and `lookahead` for lexing pipe-sink substitution bodies and `eval`/`trap`
 * operands ahead of that analysis (`substitutionsReadPipe`, `collectDefinedNames`).
 * `formedSources` counts the shell sources of alias or function calls being read inside one
 * another (`formedRunSources`), whose nesting the call data drives rather than the text, and
 * `activeFunctions` how many of them each function's expansion formed.
 */
interface NestBudget {
	left: number;
	lookahead: { left: number };
	formedSources: number;
	activeFunctions: Map<string, number>;
}

function nestBudget(work: number): NestBudget {
	return { left: work, lookahead: { left: work }, formedSources: 0, activeFunctions: new Map() };
}

/** One source read by `lexSource`: its own runs and parts, with its nested sources not yet read. */
interface LexedSource {
	source: string;
	runs: string[][];
	complete: boolean;
	topLevel: ShellTopLevelPart[];
	nestedSources: NestedSource[];
	/** How many leading words of each run arrived bare, so a reserved word in them is one. */
	bareLeadingWords: Map<string[], number>;
	/** Runs of an interpreter fed its program by a heredoc the source reads as data. */
	programRuns: Set<string[]>;
	/** Heredoc recognition was requested but the command is not heredoc data writing as a whole. */
	heredocsRejected: boolean;
	/** The budget ran out inside an arithmetic expansion, so a substitution in it was never collected. */
	nestedUnread: boolean;
	/**
	 * The set of defined names this source's definitions were added to, and whether every
	 * `eval`/`trap` operand under it was read (`collectDefinedNames`).
	 */
	definitionsRead?: { into: Set<string>; read: boolean };
}

/**
 * Tokenize `source` in `mode`, descending into its nested sources.
 *
 * With `recognizeHeredocs`, heredoc bodies are captured and read as data, or the result is
 * marked `heredocsRejected` when the command is not heredoc data writing as a whole (see
 * `tokenizeCommand`, the only caller that passes it). Nested sources never recognize heredocs.
 * `definedNames` collects the command names every source in this tokenization defines
 * (`definedCommandNames`), shared with the nested sources so a substitution sees the functions
 * its enclosing shell defined; the names an `eval` or `trap` operand defines are read before the
 * frame's pipeline walk (`collectDefinedNames`), since that operand runs in the frame's own
 * shell. Names only accumulate, so a definition in one nested source also
 * reaches the ones read after it: over-marking, the fail-closed direction. A prose frame, and
 * every frame nested under one (`underProse`) short of a substitution, reads them but adds none,
 * since text that only spells a definition (`printf '%s' 'cat() { sh; }'`, or a `bash -c '...'` inside
 * it) defines nothing, while bash runs a substitution wherever it appears.
 */
function tokenizeInto(
	source: string,
	budget: NestBudget,
	mode: TokenizeMode = "gate",
	recognizeHeredocs = false,
	definedNames: DefinedCommands = new DefinedCommands(),
	underProse = false,
	expandedByOuterShell = false,
): ScanResult {
	const lexed = lexSource(source, budget, recognizeHeredocs);
	if (lexed.heredocsRejected) {
		const { runs, complete, topLevel, nestedUnread } = lexed;
		return {
			runs,
			complete,
			topLevel,
			nested: [],
			sinkVerdicts: { executingSinks: new Set(), outputExecutedRuns: new Set() },
			shellAnalyses: [],
			heredocsRejected: true,
			nestedUnread,
		};
	}
	return analyzeLexed(lexed, budget, mode, definedNames, underProse, expandedByOuterShell);
}

/**
 * Read `source`'s own words, runs, top-level parts and nested sources, without descending into
 * the nested sources. Nothing here depends on the mode the source is later analyzed in, so a
 * nested source can be lexed ahead of its analysis and the lex reused (`lexedNestedSource`).
 * With `recognizeHeredocs`, heredoc bodies are captured as nested sources, and the result is
 * marked `heredocsRejected` when the command is not heredoc data writing as a whole.
 */
function lexSource(source: string, budget: { left: number }, recognizeHeredocs: boolean): LexedSource {
	const runs: string[][] = [];
	const nestedSources: NestedSource[] = [];
	const topLevel: ShellTopLevelPart[] = [];
	const pendingHeredocs: PendingHeredoc[] = [];
	const heredocRuns = new Set<string[]>();
	const programRuns = new Set<string[]>();
	const untrustedHeredocRuns = new Set<string[]>();
	// Reading a body as data HIDES its lines, so a heredoc is only recognized where every
	// character before it was read the way bash reads it (see `HeredocGuard`). The quote and
	// backtick readers do not know heredocs (a `"` or backtick inside one ends them early), and
	// a substitution's extent is judged by its own scanner, so any `$(`, backtick or `<(`/`>(`
	// before a `<<` disables recognition too, alongside the openers under which bash opens no
	// heredoc at all. Once ambiguous, the command is rejected as heredoc data and read as shell
	// (see `tokenizeCommand`).
	const heredocGuard = new HeredocGuard(source, 0, "opaque");
	if (!recognizeHeredocs) heredocGuard.markAmbiguous();
	let complete = true;
	let nestedUnread = false;
	let groupDepth = 0;
	let argv: string[] = [];
	let token = "";
	// The word being read as the command receives it: `token` with its quoted characters as
	// themselves rather than `EXPANSION_SUPPRESSED`, so a source handed on to a shell can be read
	// the way that shell parses it (`executableArgumentSources`). Null while it equals `token`.
	let received = null as string | null;
	let receivedArgv: string[] = [];
	let started = false;
	// Whether the word read so far holds text that always gives it a character. Until it does
	// -- while it holds only empty quotes and expansions that may give nothing (`''`, `"$v"`,
	// `$(true)`) -- bash may still hand the command what a substitution next prints.
	let wordLiteral = false;
	// The index up to which unquoted source text is an expansion that may give nothing
	// (`mayGiveNoTextEnd`), so its characters and any quotes inside it add no literal text.
	let noTextUntil = 0;
	let dequoted = false;
	let bareGlob = false;
	let bareExpansion = false;
	let soleQuotedRun = false;
	let unquotedEq = false;
	// The variable the word being read assigns, once a bare `NAME=` or `NAME+=` has started it.
	let wordAssigns: string | undefined;
	let priorWordsAllAssignments = true;
	let sawConfigWord = false;
	let liveOperator = "";
	const quotedInToken: { text: string; quote: "'" | '"'; assignment: boolean; unterminated: boolean }[] = [];
	const bareLeadingWords = new Map<string[], number>();
	let runRedirections = new Set<number>();
	let runGluedArguments = new Map<number, string>();
	let runGluedReceived = new Map<number, string>();
	let runGlobWords = new Set<number>();
	let runSplittingWords = new Set<number>();
	let redirection: RedirectionInWord | undefined;
	let redirectionTargetNext = false;
	let hereStringTargetNext = false;
	let bareLeading = 0;
	let leadingPrefix = 0;
	// Where the run's builtin sits (see `builtinIndex`), read one word at a time: command
	// position, stepped past each `BUILTIN_RUNNERS` link and its options, or -1 once an option
	// ends the runner without running anything (`command -v`). `builtinRunner` is the runner
	// whose options are being read, and `runnerOptionsEnded` records its `--`.
	let builtinSlot = 0;
	let builtinRunner: string | undefined;
	let runnerOptionsEnded = false;
	let runNestedStart = 0;

	// Kept whatever the run turns out to be; `analyzeLexed` reads the text as a script only when
	// the run's command reads its stdin as one (`hereStringReader`). A live `&` ending the
	// word is not its text but the start of the `&>` after it (`'rm -rf ~'&>/dev/null`).
	const pushHereString = (spelled: string, receivedText: string): void => {
		const text =
			liveOperator === "&"
				? hereStringText(spelled.slice(0, -1), receivedText.slice(0, -1))
				: hereStringText(spelled, receivedText);
		if (text.length > 0)
			nestedSources.push({
				source: text,
				kind: "here-string",
				complete: true,
				run: argv,
				...(OUTER_EXPANSION.test(spelled) ? {} : { receivedText: true }),
			});
	};
	// Quoted or escaped text joins the word: `spelled` is how `token` spells it, `text` what
	// the command receives.
	const appendQuoted = (spelled: string, text: string): void => {
		if (received !== null) received += text;
		else if (spelled !== text) received = token + text;
		token += spelled;
	};
	const endToken = (): void => {
		if (started) {
			argv.push(token);
			receivedArgv.push(received ?? token);
			const argIndex = argv.length - 1;
			// A redirection and its target are not part of the command they stand beside.
			// Recorded from the characters as read, since the assembled word loses it:
			// `<<<''` assembles to a bare `<<<` and `<<''-` to a bare `<<-`, yet both carry
			// their operand, and `'1'>x` assembles to `1>x` yet its `1` is an argument. A
			// word whose operator ends it bare (`2>`, `>&`, `<<-`, nothing quoted after the
			// operator) takes the next word as its target -- and a target can carry an operator
			// of its own (`2> '1'> sh` redirects to `1` and to `sh`).
			const isTarget = redirectionTargetNext;
			redirectionTargetNext = false;
			const hereStringTarget = isTarget && hereStringTargetNext;
			hereStringTargetNext = false;
			if (isTarget) runRedirections.add(argIndex);
			if (bareGlob) runGlobWords.add(argIndex);
			if (bareExpansion) runSplittingWords.add(argIndex);
			if (redirection !== undefined) {
				if (!isTarget) {
					if (redirection.gluedArgument === undefined) runRedirections.add(argIndex);
					else {
						runGluedArguments.set(argIndex, redirection.gluedArgument);
						runGluedReceived.set(argIndex, redirection.gluedReceived ?? redirection.gluedArgument);
					}
				}
				redirectionTargetNext =
					quotedInToken.length === redirection.quotedRunsBefore &&
					(REDIRECTION_OPERATOR_CHARS.has(liveOperator) ||
						(liveOperator === "-" && TAB_STRIPPING_HEREDOC.test(token)));
			}
			// A here-string feeding the command's stdin, whose text is either the next word
			// (`<<< 'text'`) or glued to the operator (`<<<'text'`). Only a word the operator
			// starts counts: quoted text in front of it is an argument (`'0'<<<x`).
			if (hereStringTarget) pushHereString(token, received ?? token);
			else if (redirection !== undefined && !isTarget && redirection.gluedArgument === undefined) {
				const operator = STDIN_HERE_STRING.exec(token)?.[0];
				if (operator === token && redirectionTargetNext) hereStringTargetNext = true;
				else if (operator !== undefined)
					pushHereString(token.slice(operator.length), (received ?? token).slice(operator.length));
			}
			// How many LEADING words of the run arrived bare. A reserved word is only
			// reserved when written that way -- `'for'`, `"for"` and `\for` are ordinary
			// command names that open no block, and `dequoted` covers all three spellings --
			// and several can share one run, since bash needs no separator between a
			// compound's closer and the group's own (`fi }`). The chain walk reads keywords
			// from this prefix, so it can tell them from words that merely spell one.
			if (!dequoted && bareLeading === argIndex) bareLeading = argIndex + 1;
			// A reserved word a command may sit directly behind does not break the run's
			// assignment prefix either: `for i in 1; do export X='rm -rf /'; done` is one
			// run, and `do` standing in front of `export` must not hide it.
			if (argIndex === leadingPrefix && precedesCommand(token, argv[argIndex - 1])) leadingPrefix = argIndex + 1;
			if (argIndex < leadingPrefix) builtinSlot = leadingPrefix;
			else if (argIndex === builtinSlot) {
				const base = headBase(token);
				if (builtinRunner !== undefined && !runnerOptionsEnded && token.startsWith("-")) {
					if (terminatesWrapper(builtinRunner, token)) builtinSlot = -1;
					else builtinSlot += 1;
					if (token === "--") runnerOptionsEnded = true;
				} else if (BUILTIN_RUNNERS.has(base)) {
					builtinRunner = base;
					runnerOptionsEnded = false;
					builtinSlot += 1;
				}
			}
			// An assignment only takes effect from an assignment POSITION: the run's
			// leading assignment prefix (`VAR='cmd'`, `A=1 B='cmd' prog`) or a GIT `-c`
			// value (`git -c alias.nuke='!rm -rf /'`) -- git specifically, because git
			// runs `alias.*` values, while an arbitrary tool's `-c key=value` is a plain
			// config operand (`mytool -c note='...'`). A `NAME="..."` word handed to an
			// arbitrary command (`echo NOTE="... rm -rf / ..."`) is a plain operand
			// either way.
			// The run's head is read from command position, not from index 0: a reserved
			// word can stand in front of it (`while true; do git config alias.nuke
			// '!rm -rf /'; break; done`), and reading `argv[0]` there found `do` and let
			// the alias value through.
			const assignmentPosition =
				priorWordsAllAssignments ||
				(argIndex > leadingPrefix && argv[argIndex - 1] === "-c" && isGitHead(argv[leadingPrefix] ?? ""));
			// The two-argument `git config section.key '<value>'` spelling (see
			// `DOTTED_CONFIG_KEY`) makes the quoted word an assignment VALUE too.
			const configValue =
				argIndex > leadingPrefix &&
				sawConfigWord &&
				DOTTED_CONFIG_KEY.test(argv[argIndex - 1]) &&
				isGitHead(argv[leadingPrefix] ?? "");
			if (dequoted && !soleQuotedRun && CARRIES_A_COMMAND.test(token))
				nestedSources.push({
					source: token,
					kind: "quoted-potential",
					complete: true,
					run: argv,
					commandPosition: argIndex === leadingPrefix,
					argIndex,
					assignment: (unquotedEq && assignmentPosition) || configValue,
				});
			for (const quoted of quotedInToken) {
				if (CARRIES_A_COMMAND.test(quoted.text))
					nestedSources.push({
						source: quoted.text,
						kind: "quoted-potential",
						complete: true,
						run: argv,
						commandPosition: argIndex === leadingPrefix,
						argIndex,
						assignment: (quoted.assignment && assignmentPosition) || configValue,
						quote: quoted.quote,
						unterminated: quoted.unterminated,
					});
			}
			priorWordsAllAssignments &&=
				(ASSIGNMENT_WORD.test(token) && argIndex !== builtinSlot) ||
				argIndex < leadingPrefix ||
				argIndex < builtinSlot ||
				(argIndex === builtinSlot && ASSIGNMENT_PREFIX_HEADS.has(headBase(token)));
			if (token === "config") sawConfigWord = true;
		}
		token = "";
		received = null;
		started = false;
		wordLiteral = false;
		dequoted = false;
		bareGlob = false;
		bareExpansion = false;
		soleQuotedRun = false;
		unquotedEq = false;
		wordAssigns = undefined;
		redirection = undefined;
		quotedInToken.length = 0;
	};
	// Where a command or backtick substitution being read sits in its run, when it starts a word
	// that is not a redirection target: the index that word takes, and whether it names what
	// the run executes. Only what may give no text can stand in front of it (`''$(...)`,
	// `"$v"$(...)`, `$()$(...)`), since bash joins the word before running it. A substitution
	// glued behind literal text (`x$(...)`), including an assignment's `=` (`x=$(...)`), gets no
	// position, so its body keeps the gated reading.
	const substitutionPosition = (): Pick<NestedSource, "argIndex" | "commandPosition"> =>
		wordLiteral || redirectionTargetNext
			? {}
			: { argIndex: argv.length, commandPosition: argv.length === leadingPrefix };
	// The variable a substitution read here stores its output in: the word is the value of a bare
	// `NAME=` or `NAME+=` standing in an assignment position, wherever in the value it sits
	// (`x=$(...)`, `x=" "$(...)`, `x=$(true)$(...)`).
	const substitutionAssignment = (): Pick<NestedSource, "assignedName"> =>
		wordAssigns === undefined || !priorWordsAllAssignments ? {} : { assignedName: wordAssigns };
	// Whether a substitution starting here is the whole target of a writing redirection: the word
	// after a bare operator (`> <(...)`), whose operator word is the run's last, or glued straight
	// behind one with nothing quoted since it started (`><(...)`, `2>><(...)`).
	const fillsWritingRedirection = (): boolean =>
		started
			? redirection !== undefined &&
				REDIRECTION_OPERATOR_CHARS.has(liveOperator) &&
				quotedInToken.length === redirection.quotedRunsBefore &&
				WRITING_REDIRECTION_END.test(token)
			: redirectionTargetNext && WRITING_REDIRECTION_END.test(argv[argv.length - 1]);
	const endRun = (): void => {
		endToken();
		if (argv.length > 0) {
			const indexes = argv.flatMap((_, k) => (runRedirections.has(k) ? [] : [k]));
			const view: RedirectionFreeView =
				runRedirections.size === 0 && runGluedArguments.size === 0
					? { words: argv, indexes }
					: { words: indexes.map((k) => runGluedArguments.get(k) ?? argv[k]), indexes };
			// Paired by position, never by text: suppression maps distinct characters to one
			// sentinel, so two words can share a spelling while only one of them is executed.
			// A quoted source stands for its word only when it spells the whole word, and then
			// it carries the raw text the shell re-parses.
			const quotedWords = new Map<number, number>();
			for (let i = runNestedStart; i < nestedSources.length; i++) {
				const { kind, source, quote, argIndex } = nestedSources[i];
				if (kind !== "quoted-potential" || argIndex === undefined) continue;
				const spelled = quote === undefined ? source : suppressQuotedMetacharacters(source, quote);
				if (spelled === argv[argIndex]) quotedWords.set(argIndex, i);
			}
			GLOB_WORDS.set(argv, runGlobWords);
			SPLITTING_WORDS.set(argv, runSplittingWords);
			if (view.words !== argv) {
				GLOB_WORDS.set(view.words, new Set(view.indexes.flatMap((k, j) => (runGlobWords.has(k) ? [j] : []))));
				SPLITTING_WORDS.set(
					view.words,
					new Set(view.indexes.flatMap((k, j) => (runSplittingWords.has(k) ? [j] : []))),
				);
			}
			// Sources are found over the redirection-free view; their positions index its words.
			const receivedWords = indexes.map((k) => runGluedReceived.get(k) ?? receivedArgv[k]);
			if (receivedArgv.some((word, k) => word !== argv[k])) RECEIVED_WORDS.set(argv, receivedArgv);
			if (receivedWords.some((word, j) => word !== view.words[j])) RECEIVED_WORDS.set(view.words, receivedWords);
			for (const { source, argIndex, unread } of executableArgumentSources(view.words, receivedWords, budget)) {
				if (unread) {
					nestedUnread = true;
					continue;
				}
				const quoted = argIndex === undefined ? undefined : quotedWords.get(view.indexes[argIndex]);
				if (argIndex === undefined || quoted === undefined)
					nestedSources.push({ source, kind: "argument-source", complete: true, run: argv });
				else {
					nestedSources[quoted].kind = "argument-source";
					if (nestedSources[quoted].source !== source)
						nestedSources.push({
							source,
							kind: "argument-source",
							complete: true,
							run: argv,
							...(OUTER_EXPANSION.test(view.words[argIndex]) ? {} : { receivedText: true }),
						});
				}
			}
			const executablePositions = executableArgumentPositions(view);
			for (let i = runNestedStart; i < nestedSources.length; i++) {
				const nested = nestedSources[i];
				if (nested.run === argv && nested.argIndex !== undefined)
					nested.executablePosition = executablePositions.has(nested.argIndex);
			}
			runNestedStart = nestedSources.length;
			runs.push(argv);
			topLevel.push({ kind: "command", argv });
			bareLeadingWords.set(argv, bareLeading);
			REDIRECTION_FREE_VIEWS.set(argv, view);
			if (UNSUPPORTED_HEADS.has(argv[0])) complete = false;
		}
		argv = [];
		receivedArgv = [];
		runRedirections = new Set();
		runGluedArguments = new Map();
		runGluedReceived = new Map();
		runGlobWords = new Set();
		runSplittingWords = new Set();
		redirectionTargetNext = false;
		hereStringTargetNext = false;
		priorWordsAllAssignments = true;
		sawConfigWord = false;
		bareLeading = 0;
		leadingPrefix = 0;
		builtinSlot = 0;
		builtinRunner = undefined;
		runnerOptionsEnded = false;
	};
	// Whether this command is heredoc data writing as a whole (see `tokenizeCommand`): the
	// source parsed with no ambiguity anywhere, every heredoc was terminated and none holds
	// code bash runs before the consumer starts (an unquoted body's substitution), and the
	// source is ONE command -- a data consumer fed its own heredocs -- with nothing but line
	// ends after it.
	const isHeredocData = (): boolean => {
		if (heredocRuns.size === 0 || pendingHeredocs.length > 0 || !heredocGuard.possibleAt(source.length)) return false;
		const bodiesAreInert = nestedSources.every(
			(inner) =>
				inner.kind !== "heredoc" ||
				(inner.complete &&
					(inner.quote !== undefined || !BODY_SUBSTITUTION.test(joinHeredocContinuations(inner.source)))),
		);
		if (!bodiesAreInert) return false;
		const [command, ...rest] = topLevel;
		if (command?.kind !== "command" || !rest.every((part) => part.kind === "operator" && part.operator === "\n"))
			return false;
		const consumer = heredocConsumer(command.argv);
		if (consumer === undefined || !heredocRuns.has(command.argv) || untrustedHeredocRuns.has(command.argv))
			return false;
		if (consumer === "program") programRuns.add(command.argv);
		return true;
	};
	const readPendingHeredocs = (start: number): number => {
		if (!heredocGuard.possibleAt(start)) {
			pendingHeredocs.length = 0;
			return start;
		}
		let end = start;
		for (const heredoc of pendingHeredocs) {
			const body = readHeredocBody(source, end, heredoc);
			nestedSources.push({
				source: body.text,
				kind: "heredoc",
				complete: body.complete,
				run: heredoc.run,
				quote: heredoc.quoted ? "'" : undefined,
			});
			heredocRuns.add(heredoc.run);
			end = body.end;
		}
		pendingHeredocs.length = 0;
		heredocGuard.skipTo(end);
		return end;
	};

	let i = 0;
	while (i < source.length) {
		const c = source[i];
		if (c === "\\" && i + 1 < source.length) {
			const escaped = source[i + 1];
			if (escaped !== "\n") {
				appendQuoted(
					"{},".includes(escaped)
						? EXPANSION_SUPPRESSED
						: escaped.replace(SUPPRESSED_BY_SINGLE_QUOTES, EXPANSION_SUPPRESSED),
					escaped,
				);
				started = true;
				wordLiteral ||= i >= noTextUntil;
				dequoted = true;
				soleQuotedRun = false;
				liveOperator = "";
			}
			i += 2;
			continue;
		}
		if (c === "\\") complete = false;
		if (c === "$" && source[i + 1] === "'") {
			const quoted = readAnsiCQuoted(source, i);
			complete &&= quoted.complete;
			soleQuotedRun = !started;
			quotedInToken.push({ text: quoted.text, quote: "'", assignment: unquotedEq, unterminated: !quoted.complete });
			appendQuoted(suppressQuotedMetacharacters(quoted.text, "'"), quoted.text);
			started = true;
			wordLiteral ||= i >= noTextUntil && quoted.text.length > 0;
			dequoted = true;
			liveOperator = "";
			i = quoted.end;
			continue;
		}
		if (c === "'" || c === '"') {
			const quoted = readQuoted(source, i, c);
			complete &&= quoted.complete;
			soleQuotedRun = !started;
			// The assignment fact is read BEFORE the quoted text joins the token: it asks
			// whether an unquoted `=` led up to this quote (`alias.nuke='...'`), not
			// whether one appears anywhere in the word.
			quotedInToken.push({
				text: quoted.text,
				quote: c as '"',
				assignment: unquotedEq,
				unterminated: !quoted.complete,
			});
			appendQuoted(suppressQuotedMetacharacters(quoted.text, c), quoted.received);
			started = true;
			wordLiteral ||=
				i >= noTextUntil && (c === "'" ? quoted.text.length > 0 : doubleQuotedTextIsLiteral(quoted.text));
			dequoted = true;
			liveOperator = "";
			i = quoted.end;
			continue;
		}
		if ((c === "$" || c === "<" || c === ">") && source[i + 1] === "(") {
			if (c === "$") bareExpansion = true;
			const sub = readSubstitution(source, i);
			complete &&= sub.complete;
			const position = c === "$" ? { ...substitutionPosition(), ...substitutionAssignment() } : {};
			const writeTarget = c !== "$" && fillsWritingRedirection();
			token += sub.raw;
			if (received !== null) received += sub.raw;
			started = true;
			// A process substitution gives a `/dev/fd/N` path and arithmetic a number, never nothing.
			wordLiteral ||= i >= noTextUntil && (c !== "$" || isArithmetic(source, i));
			liveOperator = "";
			if (isArithmetic(source, i)) {
				const executable = executableSpansIn(sub.text, budget);
				complete &&= executable.complete;
				nestedUnread ||= executable.unread;
				for (const span of executable.spans) nestedSources.push({ ...span, run: argv });
			} else {
				nestedSources.push({
					source: sub.text,
					kind: c === "$" ? "command-substitution" : "process-substitution",
					direction: processSubstitutionDirection(c),
					complete: sub.complete,
					run: argv,
					...position,
					...(writeTarget ? { writeTarget } : {}),
				});
			}
			i = sub.end;
			continue;
		}
		if (c === "`") {
			bareExpansion = true;
			const sub = readBackticks(source, i);
			complete &&= sub.complete;
			const position = { ...substitutionPosition(), ...substitutionAssignment() };
			token += sub.raw;
			if (received !== null) received += sub.raw;
			started = true;
			liveOperator = "";
			nestedSources.push({
				source: sub.text,
				kind: "backtick",
				complete: sub.complete,
				run: argv,
				...position,
			});
			i = sub.end;
			continue;
		}
		if (
			(c === "&" && (source[i + 1] === ">" || liveOperator === ">" || liveOperator === "<")) ||
			(c === "|" && liveOperator === ">")
		) {
			// Unless it continues `>&`/`<&`, the `&` opens an `&>` of its own, which takes no
			// descriptor: bash reads `timeout 1&>x` as the argument `1` and `&>x`, and
			// `>/dev/null&> sh` as `>/dev/null` and `&> sh`.
			if (c === "&" && liveOperator !== ">" && liveOperator !== "<")
				redirection = {
					gluedArgument: redirection === undefined ? (started ? token : undefined) : redirection.gluedArgument,
					gluedReceived:
						redirection === undefined ? (started ? (received ?? token) : undefined) : redirection.gluedReceived,
					quotedRunsBefore: quotedInToken.length,
				};
			token += c;
			if (received !== null) received += c;
			started = true;
			wordLiteral ||= i >= noTextUntil;
			liveOperator = c;
			i += 1;
			continue;
		}
		if (c === "#" && !started) {
			endRun();
			while (i < source.length && source[i] !== "\n") i += 1;
			continue;
		}
		if (SEPARATORS.has(c)) {
			endRun();
			liveOperator = "";
			if (c === "(") {
				groupDepth++;
				topLevel.push({ kind: "group", boundary: "start" });
				i += 1;
				continue;
			}
			if (c === ")") {
				if (groupDepth === 0) complete = false;
				else groupDepth--;
				topLevel.push({ kind: "group", boundary: "end" });
				i += 1;
				continue;
			}
			if ((c === ";" && (source[i + 1] === ";" || source[i + 1] === "&")) || (c === "|" && source[i + 1] === "&"))
				complete = false;
			if (c === "&" && source[i + 1] === "&") {
				topLevel.push({ kind: "operator", operator: "&&" });
				i += 2;
				continue;
			}
			if (c === "|" && source[i + 1] === "|") {
				topLevel.push({ kind: "operator", operator: "||" });
				i += 2;
				continue;
			}
			topLevel.push({ kind: "operator", operator: c as ShellControlOperator });
			i += 1;
			if (c === "\n" && pendingHeredocs.length > 0) i = readPendingHeredocs(i);
			continue;
		}
		if (WHITESPACE.has(c)) {
			endToken();
			liveOperator = "";
			i += 1;
			continue;
		}
		if (c === "<" && source[i + 1] === "<" && source[i + 2] !== "<") {
			complete = false;
			// A `<<` bash may read as a heredoc but this scan does not -- skipped by the guard or
			// with a delimiter it cannot spell -- would leave its body among the lines matched
			// against the next heredoc, so any such `<<` rejects the command as heredoc data.
			if (!token.endsWith("<") && !heredocGuard.possibleAt(i)) heredocGuard.markAmbiguous();
			else if (!token.endsWith("<")) {
				const heredoc = readHeredocDelimiter(source, i + 2);
				if (heredoc !== null) {
					pendingHeredocs.push({ ...heredoc, run: argv });
					// An empty or `-` delimiter (`<<''`, `<<'-'`) assembles into a bare `<<` or
					// `<<-` word, which reads as taking the NEXT word as its delimiter and so
					// hides the command behind it; a descriptor prefix (`3<<`) feeds something
					// other than the consumer's stdin (`os.dup2(3, 0)` then a shell).
					if (heredoc.delimiter === "" || heredoc.delimiter === "-" || HEREDOC_FD_PREFIX.test(token))
						untrustedHeredocRuns.add(argv);
				} else {
					heredocGuard.markAmbiguous();
					pendingHeredocs.length = 0;
				}
			}
		}
		if (c === "$" && source[i + 1] === "{") {
			complete = false;
		}
		if (c === "<" || c === ">") {
			if (!REDIRECT_PREFIX.test(token)) {
				// A word such as `build&` ends here, before the `>` completing its `&>`, so the
				// operator carries on into the next word and the ended one takes no target.
				const completesAmpersand = liveOperator === "&";
				endToken();
				if (completesAmpersand) redirectionTargetNext = false;
			}
			// A quoted or escaped prefix is not a descriptor: bash reads `timeout '1'>x` as the
			// argument `1` followed by the redirection `>x`.
			if (redirection === undefined)
				redirection = {
					gluedArgument: dequoted ? token : undefined,
					gluedReceived: dequoted ? (received ?? token) : undefined,
					quotedRunsBefore: quotedInToken.length,
				};
			// An operator character not continuing an operator starts one of its own inside the
			// same word (`2>'&'> sh` redirects to `&` and to `sh`), so only quoting after it counts.
			else if (!REDIRECTION_OPERATOR_CHARS.has(liveOperator)) redirection.quotedRunsBefore = quotedInToken.length;
		}
		if (c === "=" && !unquotedEq && ASSIGNMENT_NAME.test(token)) unquotedEq = true;
		if (c === "=" && !dequoted && wordAssigns === undefined && !token.includes("=")) {
			wordAssigns = ASSIGNED_NAME.exec(token)?.[1];
		}
		if (c === "?" || c === "[") bareGlob = true;
		if (c === "$" && PARAMETER_START.test(source[i + 1] ?? "")) bareExpansion = true;
		// An expansion inside one already passed over ends within it, so it is not read again.
		if (c === "$" && i >= noTextUntil) noTextUntil = mayGiveNoTextEnd(source, i);
		token += c;
		if (received !== null) received += c;
		started = true;
		wordLiteral ||= i >= noTextUntil;
		liveOperator = c;
		i += 1;
	}
	endRun();
	if (groupDepth !== 0) complete = false;
	const heredocsRejected = recognizeHeredocs && !isHeredocData();
	return {
		source,
		runs,
		complete,
		topLevel,
		nestedSources,
		bareLeadingWords,
		programRuns,
		heredocsRejected,
		nestedUnread,
	};
}

/**
 * The lex of a nested source, taken once and kept on the source, so reading it ahead of its
 * analysis (`substitutionsReadPipe`) and analyzing it later cost one lex between
 * them. `budget` pays for the arithmetic spans read while taking it.
 */
function lexedNestedSource(inner: NestedSource, budget: { left: number }): LexedSource {
	inner.lexed ??= lexSource(inner.source, budget, false);
	return inner.lexed;
}

/**
 * Analyze a lexed source in `mode`: find the runs whose quoted words are executed, then
 * tokenize its nested sources in the mode that gives each one (see `tokenizeInto`).
 *
 * `expandedByOuterShell` marks a source that an enclosing shell expanded before a shell parses
 * it as a script -- a double-quoted or unquoted word handed to `bash -c` or piped to `sh`, or an
 * unquoted heredoc program body -- and every source nested under one. A substitution in such text
 * ran in the outer shell whatever quote the inner script puts around it (`bash -c "echo '$(cmd)'"`),
 * so a single-quoted word there is read as double-quoted prose, not as `prose-single`. The other
 * contexts where single quotes do not protect a substitution (`SINGLE_QUOTES_LIVE_CONTEXT`) are
 * recognized from the frame's own source (`singleQuotesLive`), so they need no flag threaded from
 * the caller.
 */
function analyzeLexed(
	lexed: LexedSource,
	budget: NestBudget,
	mode: TokenizeMode,
	definedNames: DefinedCommands,
	underProse: boolean,
	expandedByOuterShell: boolean,
): ScanResult {
	const { source, topLevel, nestedSources, bareLeadingWords, programRuns } = lexed;
	const runs = [...lexed.runs];
	let complete = lexed.complete;
	let nestedUnread = lexed.nestedUnread;
	const nested: ShellNestedRun[] = [];
	const shellAnalyses: ExecutableShellAnalysis[] = [];

	// Runs whose quoted words keep being read as commands: a run carrying an
	// interpreter-like token executes its arguments, as does a run calling a function or alias
	// the source defines (`namesDefinedCommand`), whose body the floor does not follow and may
	// hand them to a shell (`f() { sh -c "$1"; }; f '...'`), and a run whose stdout a `|`-chain
	// delivers to one has what it PRINTS executed (`echo 'rm -rf /' | sh`). Walked right
	// to left, marking everything to the LEFT of an interpreter in its chain; only the
	// non-pipe operators reset the chain, and group boundaries deliberately do not, so
	// `(echo 'rm -rf /') | sh` stays covered -- over-marking a grouped neighbor merely
	// re-reads its quoted words, the fail-closed direction. An awk whose program cannot run
	// its input (`awkLeavesInputAsData`) reads the chain like `cat` does and does not arm
	// it, though its own program is still read as commands. Collected as one Set in one
	// pass (each run inspected once) because a single run can carry thousands of nested
	// sources: an interpreter test per source would go quadratic, and the floor runs
	// synchronously on every tool call.
	// A separator INSIDE a compound command does not end the chain: `{ echo 'rm -rf /'; ls;
	// } | sh`, `(echo 'rm -rf /'; ls) | sh` and `for i in 1; do echo 'rm -rf /'; done | sh`
	// all pipe the compound's COMBINED output into sh, so every command in it feeds the
	// interpreter. Depth is counted right to left, so a closer opens and an opener closes.
	// Parens arrive as group parts; every other compound is ordinary argv words to the
	// scanner (its keywords are in `UNSUPPORTED_HEADS`, which only marks `complete`), so
	// the walk counts those itself from the keyword in command position. An unbalanced
	// closer -- a `)` ending a `case` arm, say -- only keeps the chain alive too long,
	// which over-marks: the fail-closed direction.
	// A sink's name alone vouches for nothing when the source rebinds it or it is a path
	// outside the system binary directories (`cat() { sh; }; ... | cat`, `... | /tmp/cat`):
	// such a run arms the chain whatever it is called (`rebindsCommandName`), as does one with a
	// substitution that runs such a command or an interpreter, since every substitution in a run
	// reads the run's input (`substitutionsReadPipe`: `tee >(/tmp/cat)`, `cat $(sh)`). Every
	// sink counts as rebound when an `eval` or `trap` operand could not be read ahead for its
	// definitions (`collectDefinedNames`), the fail-closed direction.
	// Only a run with a `|` somewhere to its left has anything upstream for that to mark, so no
	// other run is checked. A run's own output process substitution reads what the run itself
	// writes, so one running such a command executes that run's words wherever it stands
	// (`outputSubstitutionsReadRun`: `echo '...' > >(/tmp/cat)`), and arms the chain as an
	// interpreter sink does, since a redirection after a compound's closer hangs on the
	// compound's last run yet takes the whole compound's output (`{ echo '...'; true; } > >(/tmp/cat)`).
	// When that run may be an `exec` (`mayPersistRedirections`), its redirections outlive it and
	// every later command writes through them (`exec > >(sh); echo '...'`), so every run in the
	// frame is marked: the earlier ones too, since a loop or a function defined above can run
	// them after the `exec` (`f() { echo '...'; }; exec > >(sh); f`). A file descriptor other
	// than stdout still counts (`exec 3> >(sh); ... >&3`), which only over-marks.
	// The sinks judged executing and the runs whose own output reaches one are kept as the
	// frame's `SinkVerdicts`, which the download rules read with a chain reach of their own.
	const wordBreaksMatchBash = !NON_BASH_BLANK.test(source);
	const inert = underProse || mode === "prose" || mode === "prose-single";
	// Whether bash expands a `$(...)` or backtick written even inside single quotes in this frame:
	// because an outer shell already expanded the text before this shell re-parses it as a script
	// (`expandedByOuterShell`), or because the frame's own source carries a construct that expands
	// single-quoted text -- arithmetic, an array subscript, a `${...}`, a heredoc, or an ANSI-C
	// quote (`SINGLE_QUOTES_LIVE_CONTEXT`). In any of these a single-quoted word is read as
	// double-quoted prose, not `prose-single`. The source is de-continued first, since bash removes
	// `\`-newline before it tokenizes, so a split operator (`<\`-newline-`<`) is still seen; and it
	// is judged on this frame's own text, so a nested `bash -c` script or substitution body -- and
	// a `$'...'` word's decoded text, which arrives as its child frame's source -- is covered.
	const singleQuotesLive =
		expandedByOuterShell || SINGLE_QUOTES_LIVE_CONTEXT.test(source.replace(LINE_CONTINUATION, ""));
	const definitionsUnread = !inert && !collectDefinedNames(lexed, definedNames, budget.lookahead);
	if (definitionsUnread) complete = false;
	const firstPipe = topLevel.findIndex((part) => part.kind === "operator" && part.operator === "|");
	const sourcesByRun = nestedSourcesByRun(nestedSources);
	const executingRuns = new Set<string[]>();
	const hereStringReaders = new Map<string[], HereStringReader>();
	let compoundReaders: Map<string[], HereStringReader> | undefined;
	const shellCarrierRuns = new Map<string[], boolean>();
	const readCompoundReaders = (): Map<string[], HereStringReader> =>
		compoundHereStringReaders(topLevel, bareLeadingWords, (run) =>
			hereStringReader(redirectionFreeWords(run), definedNames, definitionsUnread),
		);
	// What `run` hands its here-strings to; `compounds` supplies the readers a compound's closer
	// hands on to the commands inside it (`compoundHereStringReaders`).
	const readerOfHereStrings = (run: string[], compounds: () => Map<string[], HereStringReader>): HereStringReader => {
		const runWords = redirectionFreeWords(run);
		const reader = hereStringReader(runWords, definedNames, definitionsUnread);
		if (runWords.length > 0 && !COMPOUND_CLOSERS.has(runWords[0])) return reader;
		return widerReader(reader, compounds().get(run) ?? "data");
	};
	// The variables this frame runs as a command, collected on the first assignment substitution.
	let variablesRun: Set<string> | undefined;
	const runsVariable = (name: string): boolean => {
		if (variablesRun === undefined) {
			let compounds: Map<string[], HereStringReader> | undefined;
			const scriptCompounds = (): Map<string[], HereStringReader> => {
				compounds ??= readCompoundReaders();
				return compounds;
			};
			variablesRun = variablesRunAsCommands(
				topLevel,
				executingRuns,
				nestedSources.flatMap((inner) =>
					inner.kind === "here-string" &&
					inner.run !== undefined &&
					readerOfHereStrings(inner.run, scriptCompounds) === "script"
						? [inner.source]
						: [],
				),
			);
		}
		return variablesRun.has(name);
	};
	const pipedRuns = new Set<string[]>();
	// A call this frame has already read, by its words as spelled and received: its runs are in.
	let callsRead: Set<string> | undefined;
	const executingSinks = new Set<string[]>();
	const outputExecutedRuns = new Set<string[]>();
	let reachesInterpreter = false;
	let frameRedirected = false;
	let chainGroupDepth = 0;
	let newlinePending = false;
	for (let p = topLevel.length - 1; p >= 0; p--) {
		const part = topLevel[p];
		if (part.kind === "operator") {
			if (part.operator === "|") newlinePending = false;
			else if (part.operator === "\n") newlinePending = true;
			else if (chainGroupDepth === 0) reachesInterpreter = false;
			if (part.operator !== "\n") newlinePending = false;
		} else if (part.kind === "group") {
			if (part.boundary === "end") chainGroupDepth++;
			else if (chainGroupDepth > 0) chainGroupDepth--;
		} else if (part.kind === "command") {
			if (newlinePending && chainGroupDepth === 0) reachesInterpreter = false;
			newlinePending = false;
			// Every keyword in the run's leading BARE prefix counts, not just its head:
			// bash needs no separator between a compound's closer and the group's own, so
			// `fi }` is one run carrying two closers, and reading only the head under-counted
			// the depth -- the direction that lets a separator reset the chain early and the
			// payload through. The prefix stops at the first word that is not a keyword
			// (`grep done file` counts nothing) or that was quoted or escaped, since
			// `'for'` names an ordinary command and pairs with nothing.
			const bareWords = bareLeadingWords.get(part.argv) ?? 0;
			for (let k = 0; k < bareWords; k++) {
				const word = part.argv[k];
				if (COMPOUND_CLOSERS.has(word)) chainGroupDepth++;
				else if (COMPOUND_OPENERS.has(word)) {
					if (chainGroupDepth > 0) chainGroupDepth--;
				} else break;
			}
			if (reachesInterpreter) {
				executingRuns.add(part.argv);
				pipedRuns.add(part.argv);
			}
			const commandWords = redirectionFreeWords(part.argv);
			if (definedNames.size > 0) {
				const unfolded = unfoldEnvSplits(commandWords);
				if (unfolded === undefined || namesDefinedCommand(unfolded, definedNames)) executingRuns.add(part.argv);
				if (unfolded !== undefined && !inert) {
					runs.push(...definedCallOperandRuns(unfolded, definedNames));
					const header = isFunctionHeader(topLevel, p) && commandPositionIndex(unfolded) >= unfolded.length - 1;
					const reads = !header && definedNames.definitions.size > 0 && !definedNames.bodyRuns.has(part.argv);
					const callKey = reads ? JSON.stringify([unfolded, RECEIVED_WORDS.get(unfolded) ?? null]) : "";
					callsRead ??= reads ? new Set() : undefined;
					const repeated = callsRead?.has(callKey) === true;
					if (reads) callsRead?.add(callKey);
					const called = !reads || repeated ? [] : definitionCallRuns(unfolded, definedNames, budget);
					const sources = called === undefined ? undefined : formedRunSources(called, budget, definedNames);
					if (called === undefined || sources === undefined) {
						complete = false;
						nestedUnread = true;
					} else {
						runs.push(...called.map((run) => run.words), ...sources.runs);
						complete &&= sources.complete;
						nestedUnread ||= sources.nestedUnread;
					}
				}
			}
			const runSources = sourcesByRun.get(part.argv) ?? [];
			if (
				!(reachesInterpreter && frameRedirected) &&
				outputSubstitutionsReadRun(runSources, definedNames, budget.lookahead)
			) {
				executingRuns.add(part.argv);
				outputExecutedRuns.add(part.argv);
				reachesInterpreter = true;
				if (definitionsUnread || mayPersistRedirections(commandWords, definedNames)) frameRedirected = true;
			}
			if (
				firstPipe !== -1 &&
				p > firstPipe &&
				(definitionsUnread ||
					rebindsCommandName(commandWords, definedNames) ||
					substitutionsReadPipe(runSources, SINK_WORDS, definedNames, budget.lookahead))
			) {
				executingSinks.add(part.argv);
				reachesInterpreter = true;
			}
			const sinkWords = pipeReaderWords(part.argv, commandWords, runSources, budget.lookahead);
			if (sinkWords !== undefined) {
				// A `(` straight after a run's last word, with no operator between, is an
				// extended glob (`awk +(*)`) or a function definition, never a plain group, so
				// the run's words are not the ones bash runs.
				const next = topLevel[p + 1];
				const gluedToParen = next?.kind === "group" && next.boundary === "start";
				// The redirection-free reading drops redirection targets, and a process
				// substitution there can still hand awk's output to an interpreter
				// (`awk 1 > >(s'h')`), so the full run keeps that veto.
				const handsOutputOn = part.argv.some((token) => PROCESS_SUBSTITUTION.test(token));
				if (!(wordBreaksMatchBash && !gluedToParen && !handsOutputOn && awkLeavesInputAsData(sinkWords))) {
					executingSinks.add(part.argv);
					reachesInterpreter = true;
				}
				const shell = executableCommandIndexes(sinkWords).find((i) =>
					SHELL_SOURCE_HEADS.has(headBase(sinkWords[i])),
				);
				if (shell === undefined || shellReadsDynamicScript(sinkWords, shell)) executingRuns.add(part.argv);
			}
		}
	}
	if (frameRedirected) {
		for (const part of topLevel) {
			if (part.kind !== "command") continue;
			executingRuns.add(part.argv);
			outputExecutedRuns.add(part.argv);
		}
	}

	for (const [index, inner] of nestedSources.entries()) {
		complete &&= inner.complete;
		if (budget.left <= 0) {
			complete = false;
			nestedUnread ||= nestedSources.slice(index).some((rest) => wouldRead(rest, programRuns));
			break;
		}
		if (inner.source.length === 0) continue;
		// Only a heredoc-data command reaches here, whose bodies hold no substitution. A text
		// consumer's body is data. An interpreter's body is its program, read exactly as the
		// same program passed inline (`python3 -c '<body>'`) is: an executing payload whose
		// runs are emitted, so `os.system('git push --force')` still blocks while prose in a
		// string literal does not.
		if (inner.kind === "heredoc") {
			if (inner.run !== undefined && programRuns.has(inner.run)) {
				budget.left -= nestedSourceCost(inner.source);
				const program = tokenizeInto(
					inner.source,
					budget,
					"payload",
					false,
					definedNames,
					inert,
					expandedByOuterShell || inner.quote !== "'",
				);
				complete &&= program.complete;
				nestedUnread ||= program.nestedUnread;
				runs.push(...program.runs);
				for (const part of program.topLevel) {
					if (part.kind === "command") nested.push({ kind: inner.kind, argv: part.argv });
				}
				nested.push(...program.nested);
			}
			continue;
		}
		const runWords = inner.run === undefined ? undefined : redirectionFreeWords(inner.run);
		// A here-string is its reader's stdin. Fed to a shell it is a script bash parses as a
		// fresh command line, like `bash -c '...'`; fed to Python reading its program from stdin
		// it is that program, read as a Python heredoc body is; fed to anything else it is data,
		// which the quoted words of its word already stand for. One written after a compound's
		// closer feeds every command inside it (`compoundHereStringReaders`). Inside prose the
		// run is not a command. Decided once per run, since one run can carry thousands of
		// here-strings.
		let hereStringScript = false;
		let hereStringProgram = false;
		if (inner.kind === "here-string") {
			if (mode === "prose" || mode === "prose-single" || inner.run === undefined || runWords === undefined) continue;
			let reader = hereStringReaders.get(inner.run);
			if (reader === undefined) {
				reader = readerOfHereStrings(inner.run, () => {
					compoundReaders ??= readCompoundReaders();
					return compoundReaders;
				});
				hereStringReaders.set(inner.run, reader);
			}
			if (reader === "data") continue;
			hereStringScript = reader === "script";
			hereStringProgram = reader === "program";
		}
		// Inside prose the containing run is quoted text, not a command, so a script it names
		// is read like any other prose word: only the substitutions within it still surface.
		// It keeps the frame's own mode, since its inner quotes are literal characters of the
		// enclosing quoted word and cannot make a substitution in it inert.
		const proseArgument = inner.kind === "argument-source" && (mode === "prose" || mode === "prose-single");
		// A single-quoted word makes its substitutions inert only where bash leaves single quotes
		// intact: not inside double-quoted prose (the `'` is a literal there), and not in a frame an
		// outer shell already expanded or that carries a construct which expands single-quoted text
		// (`singleQuotesLive`, see `SINGLE_QUOTES_LIVE_CONTEXT`).
		const singleQuoted = inner.quote === "'" && mode !== "prose" && !singleQuotesLive;
		// Double quotes keep `$(...)` and backticks live but make `<(...)`/`>(...)` plain text, so
		// such a word is read as prose too: only the command substitutions within it surface.
		const proseProcess = inner.kind === "process-substitution" && mode === "prose";
		// Decided once per run, since one run can carry thousands of sources (`fish -C a -C b ...`).
		let isShellArgument = false;
		if (
			mode !== "prose" &&
			mode !== "prose-single" &&
			inner.kind === "argument-source" &&
			inner.run !== undefined &&
			runWords !== undefined
		) {
			isShellArgument =
				shellCarrierRuns.get(inner.run) ??
				executableCommandIndexes(runWords).some(
					(index) => SHELL_SOURCE_CARRIERS.has(headBase(runWords[index])) || namesUnknownCommand(runWords, index),
				);
			shellCarrierRuns.set(inner.run, isShellArgument);
		}
		const isShellSource =
			(mode !== "prose-single" &&
				(inner.kind === "command-substitution" ||
					(inner.kind === "process-substitution" && !proseProcess) ||
					inner.kind === "backtick")) ||
			isShellArgument ||
			hereStringScript ||
			(inner.kind === "quoted-potential" && inner.run !== undefined && pipedRuns.has(inner.run));
		budget.left -= nestedSourceCost(inner.source);
		// The containing run vouches for execution when it carries an interpreter-like
		// token or pipes into one; a payload context vouches for everything inside it.
		// Substitution bodies inherit this (`bash <(echo 'rm -rf /')` runs the delete),
		// and always contribute their own runs regardless -- bash executes them wherever
		// they appear, commit-message operands included (`git commit -m "$(rm -rf ~)"`).
		const runContext = mode === "payload" || (inner.run !== undefined && executingRuns.has(inner.run));
		// A command or backtick substitution in command position, or in a position a wrapper
		// executes, hands its OUTPUT to be run as a command (`$(echo 'rm -rf /')`, `sudo $(...)`),
		// so its body is read as a payload too -- as is one whose output is stored in a variable
		// the frame runs as a command (`x=$(echo 'rm -rf /'); $x`), while one whose variable is
		// only read as data (`out=$(grep -n 'rm -rf /' notes.md)`) keeps the gated reading.
		// Inside prose that position is a fragment of quoted text, not a command.
		const outputRuns =
			(inner.kind === "command-substitution" || inner.kind === "backtick") &&
			(inner.commandPosition === true ||
				inner.executablePosition === true ||
				(inner.assignedName !== undefined && runsVariable(inner.assignedName))) &&
			mode !== "prose" &&
			mode !== "prose-single";
		// A quoted word's own commands are emitted only from an executable position:
		// command position (the word that names what runs), an executing context, an assignment value
		// (`git -c alias.nuke='!rm -rf /'`), or an unterminated quote, where the quoting
		// structure itself is untrusted and the floor stays fail-closed. Everything else
		// is a prose operand whose reading belongs to the judge, not the terminal floor
		// -- and inside prose (see `TokenizeMode`) NO quoted word is emitted, so the
		// positional predicates cannot re-fire against fragments of suppressed text.
		// Inside single-quoted prose nothing is emitted at all: a substitution there is literal
		// text (`echo '$(rm -rf /)'`), so it stays in the inventory but contributes no runs.
		const emit =
			(mode !== "prose-single" && inner.kind !== "quoted-potential" && !proseArgument && !proseProcess) ||
			(mode !== "prose" &&
				mode !== "prose-single" &&
				(runContext ||
					inner.commandPosition === true ||
					inner.executablePosition === true ||
					inner.assignment === true ||
					inner.unterminated === true));
		const childMode: TokenizeMode =
			mode === "prose-single"
				? "prose-single"
				: proseProcess
					? "prose"
					: inner.kind === "argument-source"
						? proseArgument
							? mode
							: "gate"
						: hereStringScript
							? "gate"
							: hereStringProgram
								? "payload"
								: inner.kind === "quoted-potential"
									? emit
										? "payload"
										: singleQuoted
											? "prose-single"
											: "prose"
									: runContext || outputRuns
										? "payload"
										: "gate";
		// bash runs a substitution wherever it appears, prose included, so its definitions are live
		// -- except a process substitution inside double quotes, which is plain text there.
		const executesAnywhere =
			inner.kind === "command-substitution" ||
			(inner.kind === "process-substitution" && !proseProcess) ||
			inner.kind === "backtick";
		// A script re-parsed from a word that was not single-quoted was expanded first.
		const reparsedAfterExpansion =
			!executesAnywhere &&
			(childMode === "gate" || childMode === "payload") &&
			inner.quote !== "'" &&
			inner.receivedText !== true;
		const child = analyzeLexed(
			lexedNestedSource(inner, budget),
			budget,
			childMode,
			definedNames,
			inert && !executesAnywhere,
			expandedByOuterShell || reparsedAfterExpansion,
		);
		complete &&= child.complete;
		nestedUnread ||= child.nestedUnread;
		const childAnalysis = {
			analysis: { complete: child.complete, topLevel: child.topLevel, nested: child.nested },
			piped: inner.run !== undefined && (pipedRuns.has(inner.run) || outputExecutedRuns.has(inner.run)),
			sinkVerdicts: child.sinkVerdicts,
			source: inner.source,
		};
		if (isShellSource) shellAnalyses.push(childAnalysis, ...child.shellAnalyses);
		else if (
			inner.kind === "argument-source"
				? proseArgument && mode === "prose"
				: !(inner.kind === "quoted-potential" && singleQuoted)
		)
			shellAnalyses.push(...child.shellAnalyses);
		if (emit) {
			runs.push(...child.runs);
		} else {
			// A suppressed word still recurses so `nested` stays a complete inventory
			// (scratch-dir provenance fails closed on every substitution kind in it) and so its
			// substitution descendants still surface. Only the word's OWN top-level
			// prose runs are withheld -- identified by array identity, since endRun
			// pushes the same argv object to both `runs` and `topLevel`.
			runs.push(...withoutOwnTopLevelRuns(child));
		}
		for (const part of child.topLevel) {
			if (part.kind === "command") nested.push({ kind: inner.kind, argv: part.argv });
		}
		nested.push(...child.nested);
	}
	return {
		runs,
		complete,
		topLevel,
		nested,
		sinkVerdicts: { executingSinks, outputExecutedRuns },
		shellAnalyses,
		nestedUnread,
	};
}

/**
 * Whether `analyzeLexed` would read `inner` given the budget: every non-empty source except a
 * heredoc body fed to a data consumer, which is data and never read.
 */
function wouldRead(inner: NestedSource, programRuns: Set<string[]>): boolean {
	if (inner.source.length === 0) return false;
	return inner.kind !== "heredoc" || (inner.run !== undefined && programRuns.has(inner.run));
}
