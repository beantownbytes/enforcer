import {
	awkInlineProgram,
	EXPANSION_SUPPRESSED,
	executableCommandIndexes,
	NON_BASH_BLANK,
	REDIRECTION_FD,
	readAnsiCQuoted,
	readBackticks,
	readQuoted,
	readRedirectionOperator,
	readSubstitution,
	staticWordMatches,
	withoutShellParameters,
} from "./shell-tokens.js";

/**
 * A narrow, additive floor for the awk-NATIVE escape hatches the general program scan cannot see:
 * an in-program file write (`print $1 > "/etc/passwd"`), a print pipe to a command
 * (`print $0 | "sort"`), and the command/file forms of `getline` (`"cmd" | getline`,
 * `getline < "file"`). `system(...)` is deliberately NOT re-handled here -- the general
 * embedded-command descent already catches it.
 *
 * The tokenized `runs` the other argv rules read are LOSSY for this purpose:
 * `suppressQuotedMetacharacters` collapses `> < $ { } ,` inside quotes, so a redirect `>` and a
 * comparison `>` are indistinguishable there (`|` survives, but that alone is not enough). This
 * module therefore reparses the RAW command string, preserving the program operand's
 * metacharacters, and scans it.
 *
 * Both directions are fail-closed TO THE JUDGE: a confident token match denies (terminal), and
 * ANY uncertainty -- the program operand not found, `-f progfile` (program not inline), an
 * unrecognized option, an unbalanced literal -- yields no match, so the call falls through to the
 * judge exactly as before. A false negative is recoverable (the judge still gates it); a false
 * positive would wall a benign awk with no override, so it is the thing avoided.
 */

interface RawWord {
	/** The word with its quotes removed but its metacharacters (`> < { } |`) left intact. */
	text: string;
	/** Whether the word is a redirection operator, whose destination is the next word. */
	redirection: boolean;
}

/** One command run of the raw command string. */
interface RawRun {
	words: RawWord[];
	/** Where the run starts in the source it was read from. */
	start: number;
	/** Where the run ends (exclusive) in the source it was read from. */
	end: number;
	/**
	 * Whether this run and every earlier one hold only constructs the scanner reads exactly as the
	 * shell does: literal text, single quotes, double quotes with no `$` or backtick, `$'...'`,
	 * escapes, redirection operators other than a here-doc, separators, a `(` that opens a subshell,
	 * and blanks. Anything else -- an expansion or substitution (`$...`, a backtick, `<(...)`,
	 * `>(...)`), a glob or brace character, any other `(` (an extended glob `@(a|b)`, an arithmetic
	 * command `((...))`, a `<` newline-continued into `(`), a here-doc whose body is data -- can hold
	 * what reads as an operator, word break or run separator but is none of them to the shell
	 * (`${p:-print>out}`, `${p:-;cmd}`, a `#` inside `$(...)`), or expand to a different number of
	 * words and move the program (`-F "$@"`, `-F {x,y}`), so only then are the run's redirections and
	 * operands where the shell puts them.
	 */
	redirectionsExact: boolean;
}

const WORD_CHAR = /[A-Za-z0-9_]/;
/** Unquoted characters that start an expansion or can expand one word into several or none. */
const EXPANDING_CHARS = new Set(["$", "*", "?", "[", "{", "}"]);
/** What inside double quotes still expands: a parameter, command or arithmetic expansion. */
const DOUBLE_QUOTED_EXPANSION = /[$`]/;
/** The here-doc operators, whose body lines are data rather than commands. */
const HEREDOC_OPERATORS = new Set(["<<", "<<-"]);
/** What may sit directly in front of a redirection operator as its descriptor. */
const DESCRIPTOR = new RegExp(`^${REDIRECTION_FD}$`);
const RUN_SEPARATORS = new Set([";", "&", "|", "\n", "(", ")"]);
const WHITESPACE = new Set([" ", "\t", "\r", "\f", "\v"]);

/**
 * The keywords after which a `/` opens a REGEX literal rather than dividing. A `/` is a regex when
 * an operand is expected and a division when one just ended; keeping this straight is what stops a
 * `>` inside a regex from being read as a redirect. An ordinary identifier is an operand, so it is
 * NOT in this set -- only awk's operand-introducing keywords are.
 */
const OPERAND_KEYWORDS = new Set(["print", "printf", "return", "delete", "case", "do", "else", "in", "getline"]);

/** The first character at or after `start` that is not part of a line continuation. */
function charAfterContinuations(source: string, start: number): string | undefined {
	let i = start;
	while (source[i] === "\\" && source[i + 1] === "\n") i += 2;
	return source[i];
}

/**
 * Split the raw command string into one word-list per command run, keeping each word's raw text.
 *
 * Deliberately parallel to `tokenizeCommandRuns` in `shell-tokens.ts`, and it reuses that module's
 * quote/substitution readers so the quoting semantics cannot drift -- the one difference is that
 * quoted metacharacters are NOT suppressed, because the whole point is to read `>`/`<`/`{` in the
 * program operand verbatim. Runs are bounded by the same unquoted separators, so awk's operands
 * never bleed across a pipe or `;`. With `splitRedirections`, an unquoted redirection operator is
 * split out as its own word, with an unquoted descriptor written directly in front of it (`2>`,
 * `{fd}>&`), so `2>/dev/null` and `>a>b` break around their operators while a quoted or escaped
 * `>` stays ordinary text, and a `#` right after an operator is read as its destination rather
 * than a comment, so a run never ends where the unsplit reading goes on; without it, operators
 * stay in the words they are written in. It never throws: the readers consume an unterminated
 * construct to end-of-input, and an occurrence that cannot be parsed is simply omitted downstream.
 */
function rawCommandRuns(source: string, splitRedirections: boolean): RawRun[] {
	const runs: RawRun[] = [];
	let run: RawWord[] = [];
	let runStart = 0;
	let inexact = false;
	let atDestination = false;
	let text = "";
	let started = false;
	let quoted = false;

	const endWord = (): void => {
		if (started) {
			run.push({ text, redirection: false });
			atDestination = false;
		}
		text = "";
		started = false;
		quoted = false;
	};
	const endRun = (end: number): void => {
		endWord();
		if (run.length > 0) runs.push({ words: run, start: runStart, end, redirectionsExact: !inexact });
		run = [];
		atDestination = false;
	};

	let i = 0;
	const n = source.length;
	while (i < n) {
		const c = source[i];
		if (c === "\\" && i + 1 < n) {
			if (source[i + 1] !== "\n") {
				text += source[i + 1];
				started = true;
				quoted = true;
			}
			i += 2;
			continue;
		}
		if (c === "$" && source[i + 1] === "'") {
			const q = readAnsiCQuoted(source, i);
			text += q.text;
			started = true;
			quoted = true;
			i = q.end;
			continue;
		}
		if (c === "'" || c === '"') {
			const q = readQuoted(source, i, c);
			if (c === '"' && DOUBLE_QUOTED_EXPANSION.test(source.slice(i, q.end))) inexact = true;
			text += q.text;
			started = true;
			quoted = true;
			i = q.end;
			continue;
		}
		if ((c === "$" || c === "<" || c === ">") && source[i + 1] === "(") {
			inexact = true;
			const sub = readSubstitution(source, i);
			text += sub.raw;
			started = true;
			i = sub.end;
			continue;
		}
		if (c === "`") {
			inexact = true;
			const sub = readBackticks(source, i);
			text += sub.raw;
			started = true;
			i = sub.end;
			continue;
		}
		const operator =
			splitRedirections && (c === "<" || c === ">" || c === "&") ? readRedirectionOperator(source, i) : undefined;
		if (operator !== undefined) {
			if (HEREDOC_OPERATORS.has(operator.text)) inexact = true;
			const descriptor = operator.text[0] !== "&" && !quoted && DESCRIPTOR.test(text) ? text : "";
			if (descriptor === "") endWord();
			run.push({ text: descriptor + operator.text, redirection: true });
			atDestination = true;
			text = "";
			started = false;
			i = operator.end;
			continue;
		}
		if (c === "#" && !started && !atDestination) {
			endRun(i);
			while (i < n && source[i] !== "\n") i += 1;
			runStart = i;
			continue;
		}
		if (RUN_SEPARATORS.has(c)) {
			if (c === "(" && (started || run.length > 0 || charAfterContinuations(source, i + 1) === "(")) inexact = true;
			endRun(i);
			i += 1;
			runStart = i;
			continue;
		}
		if (WHITESPACE.has(c)) {
			endWord();
			i += 1;
			continue;
		}
		if (EXPANDING_CHARS.has(c)) inexact = true;
		text += c;
		started = true;
		i += 1;
	}
	endRun(n);
	return runs;
}

/** The text of a run's words with each redirection and its destination removed. */
function operandWords(run: readonly RawWord[]): string[] {
	const words: string[] = [];
	for (let k = 0; k < run.length; k++) {
		if (run[k].redirection) k += 1;
		else words.push(run[k].text);
	}
	return words;
}

/**
 * Every raw inline awk/gawk program in the command string.
 *
 * awk is found the same way the sed floor finds sed: `executableCommandIndexes` yields the command
 * position and follows exec-argument wrappers (`sudo`, `env`, `timeout`, ...), so `sudo awk` and
 * `env awk` are handled without a wrapper allow-list, and a non-executable `echo awk '...'` is NOT
 * a head. Redirections and their destinations are not operands, so they are dropped first -- but
 * only from a run whose redirections are split exactly (`RawRun.redirectionsExact`); any other run
 * is read again with its operators left in their words. A shell's positional parameters are not
 * operands of the awk its script names (`withoutShellParameters`). A command holding a blank bash
 * does not break words on (`NON_BASH_BLANK`) is read that way throughout, since any word boundary
 * in it may not be the shell's. Occurrences whose program cannot be located are omitted
 * (fail-closed).
 */
export function extractAwkPrograms(target: string): string[] {
	const programs: string[] = [];
	for (const run of rawCommandRuns(target, !NON_BASH_BLANK.test(target))) {
		const wordLists = run.redirectionsExact
			? [operandWords(run.words)]
			: rawCommandRuns(target.slice(run.start, run.end), false).map((unsplit) =>
					unsplit.words.map((word) => word.text),
				);
		for (const words of wordLists.map(withoutShellParameters)) {
			for (const index of executableCommandIndexes(words)) {
				if (staticWordMatches(words[index], "awk") || staticWordMatches(words[index], "gawk")) {
					programs.push(...awkInlineProgram(words, index).fragments);
				}
			}
		}
	}
	return programs;
}

/**
 * A character-level scanner over a raw awk program that returns true ONLY on a confident match for
 * one of the native escape hatches, and false on anything uncertain.
 *
 * It tracks the lexical state awk itself tracks so a metacharacter that is inert data is never read
 * as an operator: inside a `"..."` string (with `\` escapes), inside a `/regex/` literal (with a
 * `[...]` character class), inside a `# comment` to end-of-line, and paren/bracket nesting depth.
 * `operandExpected` disambiguates a `/` that starts a regex from one that divides -- the classic
 * awk lexer hazard -- so a `>` living inside `/a>b/` is never mistaken for a redirect.
 *
 * The four detections:
 *
 * - print pipe: a `|` at a `print`/`printf` statement's own paren depth -- `print $0 | "sort"`,
 *   `print | "cmd"` -- awk-native command execution, the same class as getline pipe.
 * - getline pipe: an unquoted `|` (or gawk `|&`), NOT the `||` operator, immediately followed by
 *   the word `getline` -- `"cmd" | getline`, `cmd |& getline`.
 * - getline file: the `getline` keyword, then an optional variable, then an unquoted `<` (not `<<`,
 *   not `<=`) -- `getline < "file"`, `getline var < file`. A `<` after a closing paren
 *   (`(getline line) < 0`) is left outside and does not match.
 * - print/printf redirect: the `print`/`printf` keyword, then -- before the statement ends and at
 *   the SAME paren depth the keyword opened at -- an unquoted `>` or `>>` (but not `>=`). A `>`
 *   deeper than that opening depth is a parenthesized comparison (`print ($1 > 5)`) and is skipped;
 *   in awk `print a > b` at statement level IS a redirect, while a comparison needs the parens.
 *
 * plain `getline` / `getline var` (next-record reads) and `print`/`printf` to stdout carry none of
 * these shapes and return false. On an unbalanced or ambiguous state the scan simply ends without a
 * match, which is the fail-closed direction.
 */
export function awkProgramHasNativeEscape(program: string): boolean {
	const n = program.length;
	let i = 0;
	let groupDepth = 0;
	let operandExpected = true;
	let printActive = false;
	let printDepth = 0;

	const skipSpaces = (k: number): number => {
		while (k < n && (program[k] === " " || program[k] === "\t")) k += 1;
		return k;
	};

	while (i < n) {
		const c = program[i];

		if (c === "#") {
			while (i < n && program[i] !== "\n") i += 1;
			continue;
		}

		if (c === '"') {
			i += 1;
			while (i < n && program[i] !== '"') i += program[i] === "\\" ? 2 : 1;
			i += 1;
			operandExpected = false;
			continue;
		}

		if (c === "/" && operandExpected) {
			i += 1;
			while (i < n && program[i] !== "/") {
				if (program[i] === "\\") i += 2;
				else if (program[i] === "[") {
					i += 1;
					while (i < n && program[i] !== "]") i += program[i] === "\\" ? 2 : 1;
					i += 1;
				} else i += 1;
			}
			i += 1;
			operandExpected = false;
			continue;
		}

		if (c === "\n" || c === ";" || c === "{" || c === "}") {
			printActive = false;
			operandExpected = true;
			i += 1;
			continue;
		}

		if (c === "(" || c === "[") {
			groupDepth += 1;
			operandExpected = true;
			i += 1;
			continue;
		}
		if (c === ")" || c === "]") {
			if (groupDepth > 0) groupDepth -= 1;
			operandExpected = false;
			i += 1;
			continue;
		}

		if (c === "|") {
			if (program[i + 1] === "|") {
				operandExpected = true;
				i += 2;
				continue;
			}
			// print/printf piped to a command (`print $0 | "sort"`, `print | "cmd"`) is awk-native
			// command execution -- the same class as `cmd | getline`. In awk the only `|` in a print
			// statement is the pipe-to-command operator, so at the print's own paren depth it is
			// always a command sink.
			if (printActive && groupDepth === printDepth) return true;
			let k = i + 1;
			if (program[k] === "&") k += 1;
			k = skipSpaces(k);
			if (program.slice(k, k + 7) === "getline" && !WORD_CHAR.test(program[k + 7] ?? "")) return true;
			operandExpected = true;
			i += 1;
			continue;
		}

		if (c === ">") {
			if (printActive && groupDepth === printDepth && program[i + 1] !== "=") return true;
			operandExpected = true;
			i += program[i + 1] === ">" ? 2 : 1;
			continue;
		}

		if (WORD_CHAR.test(c)) {
			let k = i;
			while (k < n && WORD_CHAR.test(program[k])) k += 1;
			const word = program.slice(i, k);
			if (word === "getline") {
				let m = skipSpaces(k);
				if (m < n && WORD_CHAR.test(program[m])) {
					while (m < n && WORD_CHAR.test(program[m])) m += 1;
					m = skipSpaces(m);
				}
				if (program[m] === "<" && program[m + 1] !== "<" && program[m + 1] !== "=") return true;
			}
			if (word === "print" || word === "printf") {
				printActive = true;
				printDepth = groupDepth;
			}
			operandExpected = OPERAND_KEYWORDS.has(word);
			i = k;
			continue;
		}

		if (WHITESPACE.has(c) || c === EXPANSION_SUPPRESSED) {
			i += 1;
			continue;
		}

		operandExpected = true;
		i += 1;
	}
	return false;
}
