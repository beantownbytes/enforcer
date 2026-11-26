import { describe, expect, test } from "bun:test";
import {
	braceSequenceStart,
	EXPANSION_SUPPRESSED,
	executableCommandIndexes,
	expandBraces,
	MAX_NEST_WORK,
	staticWordMatches,
	stripExpansions,
	tokenizeCommandForFloor,
	tokenizeCommandRuns,
} from "../src/shell-tokens.js";

/** The runs at the top level only: a zero budget suppresses the descent. */
function top(source: string): string[][] {
	return tokenizeCommandRuns(source, 0);
}

/** `depth` layers of command substitution around `inner` -- nesting that costs 3 chars a layer. */
function nestSub(inner: string, depth: number): string {
	let out = inner;
	for (let i = 0; i < depth; i++) out = `$(${out})`;
	return out;
}

/**
 * `depth` layers of quoting wrapped around `inner`, escaped the way a real shell needs.
 * Wrapped as `bash -c` payloads -- an EXECUTABLE position -- since a quoted word's own
 * commands only surface from one; the depth being probed is the quoting,
 * not the position.
 */
function nest(inner: string, depth: number): string {
	let out = inner;
	for (let i = 0; i < depth; i++) {
		out = `bash -c "${out.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
	}
	return out;
}

describe("tokenizeCommandRuns - splitting", () => {
	test("a plain command is one run", () => expect(top("rm -rf /")).toEqual([["rm", "-rf", "/"]]));
	test("&& splits", () =>
		expect(top("a b && c d")).toEqual([
			["a", "b"],
			["c", "d"],
		]));
	test("|| ; | & and newlines all split", () => {
		expect(top("a || b; c | d & e\nf")).toEqual([["a"], ["b"], ["c"], ["d"], ["e"], ["f"]]);
	});
	test("no-space separators split", () => expect(top("a&&b")).toEqual([["a"], ["b"]]));
	test("runs of separators do not emit empty runs", () => expect(top("a ;;&& b")).toEqual([["a"], ["b"]]));
	test("a redirect is its own token", () => expect(top("echo x > f")).toEqual([["echo", "x", ">", "f"]]));
	// A subshell group RUNS its contents, so the parentheses are syntax and must not glue onto
	// the command name -- `(git push -f)` is a push.
	test("subshell parentheses do not glue onto a token", () =>
		expect(top("(git push -f)")).toEqual([["git", "push", "-f"]]));
	test("a subshell splits internally too", () =>
		expect(top("(cd /tmp && rm -rf /)")).toEqual([
			["cd", "/tmp"],
			["rm", "-rf", "/"],
		]));
	test("a brace group splits on its separators", () =>
		expect(top("{ rm -rf /; }")).toEqual([["{", "rm", "-rf", "/"], ["}"]]));
	test("a quoted parenthesis is argument text", () => expect(top(`echo "(a)"`)).toEqual([["echo", "(a)"]]));
	// A `#` starting a word comments out the rest of the LINE, which is never executed.
	test("a comment ends the run", () => expect(top("rm -rf ./build # /")).toEqual([["rm", "-rf", "./build"]]));
	test("a comment ends only its own line", () =>
		expect(top("echo a # note\nrm -rf /")).toEqual([
			["echo", "a"],
			["rm", "-rf", "/"],
		]));
	test("a mid-word # is ordinary text", () => expect(top("echo a#b")).toEqual([["echo", "a#b"]]));
	test("a quoted # is ordinary text", () => expect(top(`echo "# /"`)).toEqual([["echo", "# /"]]));
});

describe("tokenizeCommandRuns - quoting and escapes", () => {
	test("a quoted run keeps spaces in one token", () =>
		expect(top('git -C "/tmp/repo dir" push')).toEqual([["git", "-C", "/tmp/repo dir", "push"]]));
	test("quotes are stripped", () => expect(top(`rm -rf '/'`)).toEqual([["rm", "-rf", "/"]]));
	test("mixed quoting glues into one token", () => expect(top(`a "b'c'd"e`)).toEqual([["a", "b'c'de"]]));
	test("a separator inside quotes is argument text", () =>
		expect(top(`git push origin 'feature;stuff' -f`)).toEqual([["git", "push", "origin", "feature;stuff", "-f"]]));
	test("backslash escapes whitespace", () =>
		expect(top(String.raw`rm -rf /tmp/a\ b`)).toEqual([["rm", "-rf", "/tmp/a b"]]));
	test("backslash escapes a separator", () => expect(top(String.raw`a \&\& b`)).toEqual([["a", "&&", "b"]]));
	// bash removes a backslash-newline outright, so the continuation must not fuse a stray
	// newline into the next token -- `rm -rf \<newline>/` is exactly `rm -rf /`.
	test("a line continuation is removed, not escaped", () => expect(top("rm -rf \\\n/")).toEqual([["rm", "-rf", "/"]]));
	test("a line continuation inside double quotes is removed", () => expect(top('a "x\\\ny"')).toEqual([["a", "xy"]]));
	test("a bare newline still separates runs", () => expect(top("rm -rf\n/")).toEqual([["rm", "-rf"], ["/"]]));
	test("inside double quotes only the four special chars are unescaped", () =>
		expect(top(String.raw`a "x\"y\\z\nw"`)).toEqual([["a", String.raw`x"y\z\nw`]]));
	test("an empty quoted argument is still a token", () => expect(top(`a "" b`)).toEqual([["a", "", "b"]]));
	test("an ANSI-C quoted segment ends at its first NUL, as in bash", () =>
		expect(top(String.raw`a $'-F\0x' $'b\x00c'd $'e\c@f' $'g\400h'`)).toEqual([["a", "-F", "bd", "e", "g"]]));
	// An apostrophe in ordinary prose opens a quote that runs to the end of the input. The
	// floor must not lose the commands after it, so the swallowed text is still descended into.
	test("an unterminated quote does not drop the rest of the input", () => {
		const runs = tokenizeCommandRuns("echo it's fine && rm -rf /");
		expect(runs).toContainEqual(["rm", "-rf", "/"]);
	});
});

describe("tokenizeCommandRuns - substitutions", () => {
	test("$( ) holds together as one token", () =>
		expect(top("git -c a=$(echo x y) push")).toEqual([["git", "-c", "a=$(echo x y)", "push"]]));
	test("nested parens close at the right one", () =>
		expect(top("a $(b $(c) d) e")).toEqual([["a", "$(b $(c) d)", "e"]]));
	test("a quoted paren does not close the substitution", () =>
		expect(top(`a $(b ")" c) d`)).toEqual([["a", `$(b ")" c)`, "d"]]));
	test("an escaped paren does not close the substitution", () =>
		expect(top(String.raw`a $(b \) c) d`)).toEqual([["a", String.raw`$(b \) c)`, "d"]]));
	test("a paren in a heredoc body does not close the substitution", () =>
		expect(top("a $(cat <<EOF\n)\nEOF\n) d")).toEqual([["a", "$(cat <<EOF\n)\nEOF\n)", "d"]]));
	test("a delimiter line holding a paren ends the heredoc and closes the substitution there", () =>
		expect(top("a $(cat <<EOF\nx\nEOF) d")).toEqual([["a", "$(cat <<EOF\nx\nEOF)", "d"]]));
	test("a paren in a parameter expansion does not close the substitution", () => {
		for (const expansion of [`\${x%)}`, `\${x#)}`, `\${x/)/y}`, `\${x:-\${y%)}}`, `\${x:-$(echo ))}`, `\${x:-{)}`]) {
			expect(top(`a $(echo ${expansion}; b) d`)).toEqual([["a", `$(echo ${expansion}; b)`, "d"]]);
		}
	});
	test("a parameter expansion ends at its first unquoted brace", () => {
		expect(top(`a $(echo \${x:-{}; b) d`)).toEqual([["a", `$(echo \${x:-{}; b)`, "d"]]);
		expect(top(`a $(echo \${x:-"}"}) d`)).toEqual([["a", `$(echo \${x:-"}"})`, "d"]]);
		expect(top(`a $(echo \${x:-\`}\`}) d`)).toEqual([["a", `$(echo \${x:-\`}\`})`, "d"]]);
	});
	test("the second dollar of $$ opens no parameter expansion", () =>
		expect(top(`a $(echo $\${x:-) d}`)).toEqual([["a", `$(echo $\${x:-)`, "d}"]]));
	// Each `<<B` here is quoted or refused, so bash opens no heredoc and closes at the second line.
	test("a << after a span the substitution does not follow opens no heredoc", () => {
		for (const opener of ['echo "$(echo "<<B ")"', "cat [ <<A\n] <<B\nA", "echo $'\\'<<B ' '\\'"]) {
			expect(top(`a $(${opener}\n) ; echo "\nB\n)" ; b`)).toEqual([
				["a", `$(${opener}\n)`],
				["echo", "\nB\n)"],
				["b"],
			]);
		}
	});
	// Bash starts a fresh quoting context inside a substitution a double-quoted word holds.
	test("a quote inside a double-quoted substitution does not end the word", () => {
		expect(top(`echo "$(: "'"; b; : "'")" c`)).toEqual([["echo", `$(: "'"; b; : "'")`, "c"]]);
		expect(top('echo "`: "\'"; b; : "\'"`" c')).toEqual([["echo", '`: "\'"; b; : "\'"`', "c"]]);
		expect(top(`echo "a $(echo "$(: "'")" "'") b" c`)).toEqual([["echo", `a $(echo "$(: "'")" "'") b`, "c"]]);
	});
	test("a command after a quote inside a double-quoted substitution is a run", () => {
		expect(tokenizeCommandRuns(`echo "$(: "'"; git push -f; : "'")"`)).toContainEqual(["git", "push", "-f"]);
		expect(tokenizeCommandRuns('echo "`: "\'"; git push -f; : "\'"`"')).toContainEqual(["git", "push", "-f"]);
	});
	test("an arithmetic body is not a command run", () =>
		expect(tokenizeCommandRuns("echo $((rm -rf /))")).not.toContainEqual(["rm", "-rf", "/"]));
	test("a substitution inside arithmetic is a command run", () =>
		expect(tokenizeCommandRuns("echo $(( $(rm -rf /) ))")).toContainEqual(["rm", "-rf", "/"]));
	test("a substitution inside single quotes is not a command run", () => {
		expect(tokenizeCommandRuns("echo '$(rm -rf /)'")).toEqual([["echo", `${EXPANSION_SUPPRESSED}(rm -rf /)`]]);
		expect(tokenizeCommandRuns("echo '$(echo $(rm -rf /))'")).not.toContainEqual(["rm", "-rf", "/"]);
	});
	test("a subshell inside a substitution is still a command run", () =>
		expect(tokenizeCommandRuns("echo $( (git push -f) )")).toContainEqual(["git", "push", "-f"]));
	test("the substitution body is tokenized as its own run", () =>
		expect(tokenizeCommandRuns("x $(git push -f)")).toContainEqual(["git", "push", "-f"]));
	test("a backtick body is tokenized as its own run", () =>
		expect(tokenizeCommandRuns("x `git push -f`")).toContainEqual(["git", "push", "-f"]));
	// Process substitution runs its body exactly like `$( )` does.
	test("<( ) holds together and its body is a run", () => {
		expect(top("cat <(git push -f)")).toEqual([["cat", "<(git push -f)"]]);
		expect(tokenizeCommandRuns("cat <(git push -f)")).toContainEqual(["git", "push", "-f"]);
	});
	test(">( ) holds together and its body is a run", () =>
		expect(tokenizeCommandRuns("tee >(rm -rf /)")).toContainEqual(["rm", "-rf", "/"]));
	// A `case` pattern's `)` is unbalanced, so counting parentheses alone would close the
	// substitution there and leave the arm outside it.
	test("a case pattern's paren does not close the substitution", () => {
		expect(top("a $(case x in x) b;; esac) c")).toEqual([["a", "$(case x in x) b;; esac)", "c"]]);
		expect(top("a <(case x in x|y) b;; *) c;; esac) d")).toEqual([["a", "<(case x in x|y) b;; *) c;; esac)", "d"]]);
		expect(top("a $(case x in (x) b;; esac) c")).toEqual([["a", "$(case x in (x) b;; esac)", "c"]]);
	});
	test("every case arm terminator returns to a pattern list", () =>
		expect(top("a $(case x in x) b;& y) c;;& z) d;; esac) e")).toEqual([
			["a", "$(case x in x) b;& y) c;;& z) d;; esac)", "e"],
		]));
	test("a case nested in an arm, in a subshell or in a pattern closes on its own", () => {
		expect(top("a $(case x in x) case y in y) b;; esac;; esac) c")).toEqual([
			["a", "$(case x in x) case y in y) b;; esac;; esac)", "c"],
		]);
		expect(top("a $( (case x in x) b;; esac) ) c")).toEqual([["a", "$( (case x in x) b;; esac) )", "c"]]);
		expect(top("a $(case x in @(x|y)) b;; $(echo z)) c;; esac) d")).toEqual([
			["a", "$(case x in @(x|y)) b;; $(echo z)) c;; esac)", "d"],
		]);
	});
	test("a case inside a pattern's command substitution keeps its own pattern parens", () => {
		expect(top("a $(case x in $(case y in y) :;; z) :;; esac)) b;; esac) c")).toEqual([
			["a", "$(case x in $(case y in y) :;; z) :;; esac)) b;; esac)", "c"],
		]);
		expect(top("a $(case x in @(w|$(case y in y) :;; z) :;; esac))) b;; esac) c")).toEqual([
			["a", "$(case x in @(w|$(case y in y) :;; z) :;; esac))) b;; esac)", "c"],
		]);
		expect(top("a $(case x in $((1))) b;; esac) c")).toEqual([["a", "$(case x in $((1))) b;; esac)", "c"]]);
	});
	test("a paren inside a backtick body does not close the substitution", () => {
		expect(top("a $(echo `case x in x) b;; esac`) c")).toEqual([["a", "$(echo `case x in x) b;; esac`)", "c"]]);
		expect(top("a $(echo `echo )`) c")).toEqual([["a", "$(echo `echo )`)", "c"]]);
	});
	test("a word named case inside arithmetic is not a reserved word", () => {
		expect(top("a $((case)) b")).toEqual([["a", "$((case))", "b"]]);
		expect(top("a $(echo $((case)); case x in x) b;; esac) c")).toEqual([
			["a", "$(echo $((case)); case x in x) b;; esac)", "c"],
		]);
		expect(top("a $(( $(case x in x) echo 1;; esac) )) b")).toEqual([
			["a", "$(( $(case x in x) echo 1;; esac) ))", "b"],
		]);
	});
	// Where a pattern would start, a bare `esac` ends the case, so the next `)` closes the body.
	test("a bare esac where a pattern would start ends the case", () => {
		expect(top("a $(case x in esac) b")).toEqual([["a", "$(case x in esac)", "b"]]);
		expect(top("a $(case x in x) b;; esac) c")).toEqual([["a", "$(case x in x) b;; esac)", "c"]]);
		expect(top("a $(case x in (esac) b;; esac) c")).toEqual([["a", "$(case x in (esac) b;; esac)", "c"]]);
		expect(top("a $(case x in x|esac) b;; esac) c")).toEqual([["a", "$(case x in x|esac) b;; esac)", "c"]]);
	});
	test("a comment's text is not structure inside a substitution", () => {
		expect(top("a $(case x in x) b # ;;\nc;; esac) d")).toEqual([["a", "$(case x in x) b # ;;\nc;; esac)", "d"]]);
		expect(top("a $(b # it's )\nc) d")).toEqual([["a", "$(b # it's )\nc)", "d"]]);
		expect(top("a $(echo b#c) d")).toEqual([["a", "$(echo b#c)", "d"]]);
	});
	test("a quoted case is an ordinary word and a continued one is reserved", () => {
		expect(top(`a $(ca"s"e x in x) b`)).toEqual([["a", `$(ca"s"e x in x)`, "b"]]);
		expect(top("a $(ca\\\nse x in x) b;; esac) c")).toEqual([["a", "$(ca\\\nse x in x) b;; esac)", "c"]]);
	});
	test("a case arm's command runs inside the substitution", () =>
		expect(tokenizeCommandRuns(`echo "$(case x in x) git push -f;; esac)"`)).toContainEqual(["git", "push", "-f"]));
	test("case outside command position, or quoted, is an ordinary word", () => {
		expect(top("a $(echo case x in x) b")).toEqual([["a", "$(echo case x in x)", "b"]]);
		expect(top(`a $("case" x in x) b`)).toEqual([["a", `$("case" x in x)`, "b"]]);
		expect(top("a $(x=case; echo in x) b")).toEqual([["a", "$(x=case; echo in x)", "b"]]);
	});
	test("case is recognized behind a reserved word, a separator or a function header", () => {
		expect(top("a $(if true; then case x in x) b;; esac; fi) c")).toEqual([
			["a", "$(if true; then case x in x) b;; esac; fi)", "c"],
		]);
		expect(top("a $(f() { case x in x) b;; esac; }; f) c")).toEqual([
			["a", "$(f() { case x in x) b;; esac; }; f)", "c"],
		]);
		expect(top("a $(true &&\ncase x in x) b;; esac) c")).toEqual([["a", "$(true &&\ncase x in x) b;; esac)", "c"]]);
	});
});

describe("tokenizeCommandRuns - redirections are not command separators", () => {
	test("2>&1 stays inside its command", () =>
		expect(top("git push 2>&1 --force origin main")).toEqual([["git", "push", "2>&1", "--force", "origin", "main"]]));
	test(">&2 stays inside its command", () => expect(top("rm -rf >&2 /")).toEqual([["rm", "-rf", ">&2", "/"]]));
	test("&> stays inside its command", () =>
		expect(top("git push &>log --force")).toEqual([["git", "push", "&>log", "--force"]]));
	test(">| stays inside its command", () => expect(top("rm -rf >| log /")).toEqual([["rm", "-rf", ">|", "log", "/"]]));
	test("an attached redirection starts a new word", () =>
		expect(top("git push>log --force")).toEqual([["git", "push", ">log", "--force"]]));
	test("an fd number stays with its operator", () => expect(top("echo 2>f")).toEqual([["echo", "2>f"]]));
	test("a digit ending a word does not become an fd", () => expect(top("echo a2>f")).toEqual([["echo", "a2", ">f"]]));
	test("a real background & still separates", () => expect(top("a & b")).toEqual([["a"], ["b"]]));
	test("a real pipe still separates", () => expect(top("a | b")).toEqual([["a"], ["b"]]));
	// The lookback must see a LIVE operator: an escaped `>` is a literal character.
	test("an escaped > does not make the next | a redirect", () =>
		expect(top(String.raw`a b\>|c d`)).toEqual([
			["a", `b${EXPANSION_SUPPRESSED}`],
			["c", "d"],
		]));
	test("a quoted > does not make the next | a redirect", () =>
		expect(top(`a "b>"|c d`)).toEqual([
			["a", "b\u0000"],
			["c", "d"],
		]));
	test("&& after a redirect still separates", () =>
		expect(top("git push 2>&1 && tail -f log")).toEqual([
			["git", "push", "2>&1"],
			["tail", "-f", "log"],
		]));
});

describe("executableCommandIndexes", () => {
	test("walks prefixes, wrapper options, and nested wrappers", () => {
		expect(executableCommandIndexes(["time", "-p", "sed"])).toEqual([2]);
		expect(executableCommandIndexes(["coproc", "sed"])).toEqual([1]);
		expect(executableCommandIndexes(["coproc", "FILTER", "sed"])).toEqual([1]);
		expect(executableCommandIndexes(["sudo", "-u", "root", "env", "-i", "sed"])).toEqual([0, 3, 5]);
		expect(executableCommandIndexes(["ssh", "-p", "22", "host", "sed"])).toEqual([0, 4]);
		expect(executableCommandIndexes(["/usr/bin/time", "sed"])).toEqual([0, 1]);
		expect(executableCommandIndexes(["exec", "-a", "label", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["unshare", "--root", "/tmp/root", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["bash", "-c", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["sh", "-ce", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["eval", "--", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["env", "-Ssed"])).toEqual([0, 1]);
		expect(executableCommandIndexes(["env", "-iSsed"])).toEqual([0, 1]);
		expect(executableCommandIndexes(["env", "-iS", "FOO=1", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["env", "-iu", "FOO", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["env", "-iuS", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["script", "/tmp/out", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["xargs", "--replace", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["xargs", "--replace", "{}", "sed", "{}"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["xargs", "--max-lines", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["xargs", "--max-lines", "2", "sed"])).toEqual([0, 3]);
	});
	test("terminal and non-command wrapper forms have no executable operand", () => {
		expect(executableCommandIndexes(["command", "-v", "sed"])).toEqual([0]);
		expect(executableCommandIndexes(["command", "-pv", "sed"])).toEqual([0]);
		expect(executableCommandIndexes(["sudo", "-l", "sed"])).toEqual([0]);
		expect(executableCommandIndexes(["sudo", "-ln", "sed"])).toEqual([0]);
		expect(executableCommandIndexes(["script", "/tmp/sed"])).toEqual([0]);
	});
	test("an abbreviated long option is read as the option it names", () => {
		expect(executableCommandIndexes(["env", "--uns", "FOO", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["env", "--ch", "/tmp", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["env", "--s=sed"])).toEqual([0, 1]);
		expect(executableCommandIndexes(["env", "--split", "FOO=1", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["nice", "--adj", "5", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["timeout", "--sig", "KILL", "5", "sed"])).toEqual([0, 4]);
		expect(executableCommandIndexes(["sudo", "--us", "root", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["/usr/bin/time", "--output", "/tmp/t", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["xargs", "--max-p", "2", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["script", "--e", "never", "/tmp/out", "sed"])).toEqual([0, 4]);
		expect(executableCommandIndexes(["flock", "--co", "1", "/tmp/lock", "sed"])).toEqual([0, 4]);
		expect(executableCommandIndexes(["xargs", "--r", "sed"])).toEqual([0, 2]);
	});
	test("an ambiguous abbreviation of value options only takes the next word", () => {
		expect(executableCommandIndexes(["sudo", "--ch", "/tmp", "sed"])).toEqual([0, 3]);
	});
	test("an abbreviation that names no single option is read as a flag", () => {
		expect(executableCommandIndexes(["env", "--i", "sed"])).toEqual([0, 2]);
		expect(executableCommandIndexes(["timeout", "--v", "5", "sed"])).toEqual([0, 3]);
		expect(executableCommandIndexes(["env", "--nope", "sed"])).toEqual([0, 2]);
	});
	test("an abbreviated terminating option runs no command", () => {
		expect(executableCommandIndexes(["sudo", "--li", "sed"])).toEqual([0]);
		expect(executableCommandIndexes(["env", "--vers", "sed"])).toEqual([0]);
	});
});

describe("tokenizeCommandRuns - descent into quoted content", () => {
	test("a quoted command is surfaced as a run", () =>
		expect(tokenizeCommandRuns(`sh -c 'rm -rf /'`)).toContainEqual(["rm", "-rf", "/"]));
	test("executable source arguments are surfaced as runs", () => {
		for (const [command, run] of [
			["bash -c sed", ["sed"]],
			["eval sed -n p", ["sed", "-n", "p"]],
			["trap sed EXIT", ["sed"]],
			["env -S 'sed -n p'", ["sed", "-n", "p"]],
			["env -Ssed -n p", ["sed"]],
			["env -iS 'sed -n p'", ["sed", "-n", "p"]],
			["env -0iS'sed -n p'", ["sed", "-n", "p"]],
			["eval -- sed -n p", ["sed", "-n", "p"]],
		] as const) {
			expect(tokenizeCommandRuns(command)).toContainEqual([...run]);
		}
	});
	test("descent recurses through several quoting layers", () =>
		expect(
			tokenizeCommandRuns(`node -e "require('child_process').execSync('git push origin main --force')"`),
		).toContainEqual(["git", "push", "origin", "main", "--force"]));
	// Layers are the cheap thing to add, so the bound is on total work rather than on depth:
	// wrapping the command in another `bash -c "..."` must not walk it past the floor.
	test("descent reaches several quoting layers", () =>
		expect(tokenizeCommandRuns(nest("rm -rf /", 4))).toContainEqual(["rm", "-rf", "/"]));
	// Substitution layers cost three characters each, so a DEPTH cap would be a bypass anyone
	// could reach by typing `$(` a few more times. The bound is on total work instead.
	test("descent reaches deeply nested substitution layers", () => {
		for (const layers of [4, 8, 32, 200]) {
			expect(tokenizeCommandRuns(nestSub("rm -rf /", layers))).toContainEqual(["rm", "-rf", "/"]);
		}
	});
	test("descent stops once the work budget is spent", () =>
		expect(tokenizeCommandRuns(nestSub("rm -rf /", 4), 8)).not.toContainEqual(["rm", "-rf", "/"]));
	test("a nested source the spent budget leaves unread is reported", () => {
		expect(tokenizeCommandForFloor(nestSub("rm -rf /", 4), 8).unread).toBe("nested");
		expect(tokenizeCommandForFloor(nestSub("rm -rf /", 4)).unread).toBe("none");
	});
	test("a budget spent on the last nested source leaves nothing unread", () =>
		expect(tokenizeCommandForFloor("echo $(ab)", 2).unread).toBe("none"));
	test("arithmetic the spent budget leaves unread is reported", () =>
		expect(tokenizeCommandForFloor("echo $(( $(rm -rf /) ))", 0).unread).toBe("nested"));
	test("a data heredoc body after the budget is spent is not counted as unread", () =>
		expect(tokenizeCommandForFloor("cat 'a b' > notes.md <<'EOF'\nbody\nEOF", 3).unread).toBe("none"));
	// The first operand spends the read-ahead budget, so the second, which rebinds `cat`, is
	// never read before the walk: the sink then counts as rebound rather than trusted.
	test("an eval operand left unread for its definitions arms every pipe sink", () =>
		expect(
			tokenizeCommandRuns(`echo 'sed -n p /dev/null' | cat; eval '${"a".repeat(25)}'; eval 'cat() { sh; }'`, 20),
		).toContainEqual(["sed", "-n", "p", "/dev/null"]));
	test("the default budget is large enough for any real command", () =>
		expect(MAX_NEST_WORK).toBeGreaterThan(100_000));
});

// A quoted word's own commands surface only from an executable position:
// command position, an interpreter-like token in the run, an assignment value, or a
// pipe into an interpreter. A prose operand (a commit message, a grep pattern) is data.
describe("tokenizeCommandRuns - quoted words surface only from executable positions", () => {
	test("a commit-message operand's words are not runs", () => {
		const runs = tokenizeCommandRuns("git commit -m 'docs: warn against rm -rf ~'");
		expect(runs).toEqual([["git", "commit", "-m", `docs: warn against rm -rf ${EXPANSION_SUPPRESSED}`]]);
	});
	test("command position: a quoted word that IS the command surfaces", () =>
		expect(tokenizeCommandRuns("'rm -rf /'")).toContainEqual(["rm", "-rf", "/"]));
	test("interpreter-like head: a quoted argument of a shell or wrapper surfaces", () => {
		expect(tokenizeCommandRuns("ssh host 'rm -rf /'")).toContainEqual(["rm", "-rf", "/"]);
		expect(tokenizeCommandRuns("timeout 5 'rm -rf /'")).toContainEqual(["rm", "-rf", "/"]);
		expect(tokenizeCommandRuns("grep -r 'rm -rf /' .")).not.toContainEqual(["rm", "-rf", "/"]);
	});
	test("a wrapper's quoted prose operands stay suppressed", () => {
		expect(tokenizeCommandRuns("sudo printf '%s\\n' 'sed -n p'")).not.toContainEqual(["sed", "-n", "p"]);
		expect(tokenizeCommandRuns("env printf '%s\\n' 'sed -n p'")).not.toContainEqual(["sed", "-n", "p"]);
		expect(tokenizeCommandRuns("xargs printf '%s\\n' 'sed -n p'")).not.toContainEqual(["sed", "-n", "p"]);
	});
	test("assignment value: a quoted value behind an unquoted = surfaces", () =>
		expect(tokenizeCommandRuns("git -c alias.nuke='!rm -rf /' nuke")).toContainEqual(["!rm", "-rf", "/"]));
	test("piped into an interpreter: the producer's quoted words surface", () => {
		expect(tokenizeCommandRuns("echo 'rm -rf /' | sh")).toContainEqual(["rm", "-rf", "/"]);
		expect(tokenizeCommandRuns("echo 'rm -rf /' | wc -c")).not.toContainEqual(["rm", "-rf", "/"]);
	});
	test("a suppressed operand's substitution descendants still surface", () =>
		expect(tokenizeCommandRuns(`git commit -m "$(rm -rf ~)"`)).toContainEqual(["rm", "-rf", "~"]));
	test("a substitution body inherits its run's interpreter context", () =>
		expect(tokenizeCommandRuns("bash <(echo 'rm -rf /')")).toContainEqual(["rm", "-rf", "/"]));
	test("a shell script's own quoted operands are gated like the top level's", () => {
		expect(tokenizeCommandRuns(`bash -c 'echo "rm -rf /"'`)).not.toContainEqual(["rm", "-rf", "/"]);
		expect(tokenizeCommandRuns(`bash -c 'ssh host "rm -rf /"'`)).toContainEqual(["rm", "-rf", "/"]);
	});
	test("a substitution in command position has its printed words read as commands", () => {
		expect(tokenizeCommandRuns(`$(echo 'rm -rf /')`)).toContainEqual(["rm", "-rf", "/"]);
		expect(tokenizeCommandRuns(`echo $(echo 'rm -rf /')`)).not.toContainEqual(["rm", "-rf", "/"]);
	});
	test("run order is stable: top-level runs precede nested ones", () => {
		const runs = tokenizeCommandRuns("sh -c 'rm -rf /' && ls");
		expect(runs).toEqual([["sh", "-c", "rm -rf /"], ["ls"], ["rm", "-rf", "/"]]);
	});
});

describe("stripExpansions", () => {
	test("removes a substitution", () => expect(stripExpansions("r$(x)m")).toBe("rm"));
	// A pattern for this is nesting-blind: one pass over `$($())` leaves a `$()` behind.
	test("removes nested substitutions", () => {
		expect(stripExpansions("r$($())m")).toBe("rm");
		expect(stripExpansions(`git pu${"$(".repeat(10)}x${")".repeat(10)}sh`)).toBe("git push");
	});
	test("removes backticks and braced expansions", () => {
		expect(stripExpansions("g``it")).toBe("git");
		expect(stripExpansions("r${x}m")).toBe("rm");
		expect(stripExpansions("r${x${y}}m")).toBe("rm");
	});
	test("keeps an arithmetic expansion, which contributes a number", () => {
		expect(stripExpansions("r$((1))m")).toBe("r$((1))m");
		expect(stripExpansions("r$(( 1 + 2 ))m")).toBe("r$(( 1 + 2 ))m");
	});
	test("keeps a process substitution, which always contributes a path", () => {
		expect(stripExpansions("r<(true)m")).toBe("r<(true)m");
		expect(stripExpansions("g>(true)it")).toBe("g>(true)it");
	});
	test("leaves ordinary text alone", () => {
		expect(stripExpansions("/usr/bin/git")).toBe("/usr/bin/git");
		expect(stripExpansions("$home")).toBe("$home");
	});
});

describe("tokenizeCommandRuns - heredoc bodies", () => {
	test("a heredoc-data command contributes no body runs", () =>
		expect(tokenizeCommandRuns("cat > x.md <<'EOF'\nrm -rf /\nEOF")).toEqual([["cat", ">", "x.md", "<<EOF"]]));
	test("several heredocs on one command stay data", () =>
		expect(tokenizeCommandRuns("cat <<A <<'B'\nrm -rf /\nA\ngit push -f\nB")).toEqual([["cat", "<<A", "<<B"]]));
	test("a second heredoc command reads the bodies as before", () =>
		expect(tokenizeCommandRuns("cat > a <<'A'\nrm -rf /\nA\ncat > b <<'B'\nx\nB")).toEqual([
			["cat", ">", "a", "<<A"],
			["rm", "-rf", "/"],
			["A"],
			["cat", ">", "b", "<<B"],
			["x"],
			["B"],
		]));
	test("any other command beside a heredoc reads the body as before", () =>
		expect(tokenizeCommandRuns("cat > x.md <<'EOF'\nrm -rf /\nEOF\nls")).toEqual([
			["cat", ">", "x.md", "<<EOF"],
			["rm", "-rf", "/"],
			["EOF"],
			["ls"],
		]));
	test("a shell consumer reads the body as before", () =>
		expect(tokenizeCommandRuns("bash <<'EOF'\nrm -rf /\nEOF")).toEqual([
			["bash", "<<EOF"],
			["rm", "-rf", "/"],
			["EOF"],
		]));
	test("an unquoted data body without substitutions contributes nothing", () =>
		expect(tokenizeCommandRuns("cat <<EOF\nrm -rf / $HOME\nEOF")).toEqual([["cat", "<<EOF"]]));
	test("a quoted data body contributes nothing, substitutions included", () =>
		expect(tokenizeCommandRuns("cat <<'EOF'\n$(git status)\nEOF")).toEqual([["cat", "<<EOF"]]));
});

// The floor runs synchronously on every tool call and cannot be overridden, so the tokenizer
// is a denial-of-service surface in its own right. It is a single linear scan and each descent
// level sees a strict substring of its parent, so cost is bounded by depth * input length --
// these shapes are the ones that would expose it if that were ever not true.
describe("tokenizeCommandRuns - stays linear on adversarial input", () => {
	const shapes: [string, (n: number) => string][] = [
		["quoted tokens", (n) => `git ${'-c "a b" '.repeat(n)}push`],
		["unterminated quote", (n) => `git ${'-c "aa '.repeat(n)}`],
		["alternating quote soup", (n) => `git ${`-c "a'b" 'c"d' `.repeat(n)}`],
		["separators", (n) => "a && b | c ; d & ".repeat(n)],
		["escapes", (n) => String.raw`rm -rf /tmp/a\ b\ c `.repeat(n)],
		["substitutions", (n) => `git ${"-c a=$(echo x) ".repeat(n)}push`],
		["nested substitutions", (n) => `a ${"$(".repeat(n)}x${")".repeat(n)}`],
		["unterminated substitution", (n) => `a ${"$(x ".repeat(n)}`],
		["backticks", (n) => `a ${"`x` ".repeat(n)}`],
		["double-quoted backticks", (n) => `a ${"\"x'`x`'\" ".repeat(n)}`],
		["many quoted command runs", (n) => `sudo printf '%s' 'sed -n p'; `.repeat(n)],
		["nested eval wrappers", (n) => `${"eval ".repeat(n)}printf ok`],
		["nested builtin wrappers", (n) => `${"builtin ".repeat(n)}eval printf ok`],
		["command wrappers before a declaring builtin", (n) => `${"command -p ".repeat(n)}export X='a b'`],
		["builtin wrappers before a sourcing builtin", (n) => `${"builtin ".repeat(n)}source <(echo 'a b')`],
		["eval definitions then a pipe", (n) => `${"eval 'f() { :; }' | cat; ".repeat(n)}echo x | cat`],
		// An arithmetic layer costs four characters, so recursing per layer would reach the call
		// stack's limit on an input the budget considers small.
		["nested arithmetic", (n) => `echo ${"$((".repeat(n)}1${"))".repeat(n)}`],
		["nested arithmetic with a substitution", (n) => `echo ${"$((".repeat(n)}$(rm -rf /)${"))".repeat(n)}`],
		["heredocs on one line", (n) => `cat ${"<<EOF ".repeat(n)}\n${"x\nEOF\n".repeat(n)}`],
		["written heredocs then runs", (n) => `${"cat > x <<E\nx\nE\n".repeat(n)}${"bash y; ".repeat(n)}`],
		["parameter expansions before a heredoc", (n) => `echo ${"${a} ".repeat(n)}<<EOF\nx\nEOF`],
		["heredocs in a substitution", (n) => `a "$(${"cat <<EOF\n)\nEOF\n".repeat(n)})"`],
		["heredocs on one line in a substitution", (n) => `a "$(cat ${"<<EOF ".repeat(n)}\n${")\nEOF\n".repeat(n)})"`],
		[
			"heredocs carried out of closed substitutions",
			(n) => `a "$(${"echo $(cat <<EOF) ".repeat(n)}\n${")\nEOF\n".repeat(n)})"`,
		],
		[
			"nested double-quoted substitutions holding heredocs",
			(n) => `echo x | tee >(: ${'"$(cat <<E '.repeat(n)}${'\nE\n)"'.repeat(n)})`,
		],
		["nested parameter expansions in a substitution", (n) => `a "$(${"${x:-".repeat(n)}b${"}".repeat(n)})"`],
		["substitutions nested in parameter expansions", (n) => `a "$(${"${x:-$(".repeat(n)}b${")}".repeat(n)})"`],
		["nested case substitutions", (n) => `a "${"$(case x in x) ".repeat(n)}b${";; esac)".repeat(n)}"`],
		["case arms in one substitution", (n) => `a "$(case x in ${"x) b;; ".repeat(n)}esac)"`],
		["here-strings fed to a wrapped shell", (n) => `sudo ${"-E ".repeat(n)}bash ${"<<< 'a b' ".repeat(n)}`],
		["here-strings on nested groups", (n) => `${"(".repeat(n)}bash${") <<< a".repeat(n)}`],
		["here-strings on nested keyword compounds", (n) => `${"if true; then ".repeat(n)}bash${"; fi <<< a".repeat(n)}`],
		["fish commands in their own options", (n) => `fish ${"--init-command=x ".repeat(n)}`],
		// Every reference to the parameters repeats all of them, so the spliced text grows as
		// references times parameters until the budget stops it.
		["quoted parameter references", (n) => `bash -c '${'"$@" '.repeat(n)}' _ ${"a ".repeat(n)}`],
		["unquoted parameter references", (n) => `bash -c '${"$* ".repeat(n)}' _ ${"a b ".repeat(n)}`],
		["many scripts spliced with parameters", (n) => `bash -c '"$@"' _ a; `.repeat(n)],
		["quoted substitutions in a spliced script", (n) => `bash -c '${'"$('.repeat(n)}$1${')"'.repeat(n)}' _ x`],
		["heredocs in a spliced script", (n) => `bash -c '${"cat <<E\n$1\nE\n".repeat(n)}' _ x`],
		["unterminated default references", (n) => `bash -c '${"${1:-".repeat(n)}' _ x`],
		["default references around substitutions", (n) => `bash -c '${"${1:-$(".repeat(n)}' _ x`],
		// The single-quotes-live context check scans each frame's source; an open bracket run with
		// no closer would expose any backtracking in it.
		["open brackets before a substitution", (n) => `echo ${"[a ".repeat(n)}'$(x)'`],
	];
	for (const [label, build] of shapes) {
		test(`${label} stays linear at 5000 tokens`, () => {
			const started = Date.now();
			tokenizeCommandRuns(build(5000));
			expect(Date.now() - started).toBeLessThan(1000);
		});
	}
	// Each nested operand's own analysis reads its definitions again, so without reading every
	// source once the pre-walk read goes cubic in the depth. Kept under the nest budget, where
	// that shows; past it every depth costs the same.
	test("nested eval definitions stay linear at 600 levels", () => {
		const started = Date.now();
		tokenizeCommandRuns(`${"eval ".repeat(600)}'f() { :; }'; echo x | cat`);
		expect(Date.now() - started).toBeLessThan(1000);
	});
});

// Each expected list is what bash 5.2 printed for the word (`printf '<%s>' WORD`).
describe("expandBraces", () => {
	const words = (word: string, limit = 100_000) => {
		const expanded = expandBraces(word, limit);
		return expanded.kind === "words" ? expanded.words : expanded.kind;
	};
	test("reads a group's alternatives and sequences as bash does", () => {
		const cases: [string, string[]][] = [
			["{/,x}", ["/", "x"]],
			["x{,/}", ["x", "x/"]],
			["{/,x}{a,b}", ["/a", "/b", "xa", "xb"]],
			["{{/,y},x}", ["/", "y", "x"]],
			["{a{b,c},d}", ["ab", "ac", "d"]],
			["{a,b}}}", ["a}}", "b}}"]],
			["{a,{b,c}", ["{a,b", "{a,c"]],
			["{x{b,c}}", ["{xb}", "{xc}"]],
			["{c}{a,b}", ["{c}a", "{c}b"]],
			["x{},/}", ["x}", "x/"]],
			["{2}{},++/-}", ["2}{}", "++/-"]],
			["{x{b,c}..y}", ["xb..y", "xc..y"]],
			["{a..}{b,c}", ["{a..}b", "{a..}c"]],
			["{..{a,b}}", ["..a", "..b"]],
			["{,}", []],
			["{a,}", ["a"]],
			["{1..3}", ["1", "2", "3"]],
			["{3..1}", ["3", "2", "1"]],
			["{1..3..0}", ["1", "2", "3"]],
			["{a..e..2}x", ["ax", "cx", "ex"]],
			["{01..10..3}", ["01", "04", "07", "10"]],
			["{-01..2}", ["-01", "000", "001", "002"]],
			["{-0..2}", ["0", "1", "2"]],
			["{+1..2}", ["1", "2"]],
			["{1..2}{a,b}", ["1a", "1b", "2a", "2b"]],
			[`{r..r..${"0".repeat(70)}1}`, ["r"]],
			[`{${"0".repeat(70)}1..2}`, [`${"0".repeat(70)}1`, `${"0".repeat(70)}2`]],
			["-{r..r..10000000000000000}f", ["-rf"]],
			["{a..c..9223372036854775807}", ["a"]],
			["{9007199254740993..9007199254740995}", ["9007199254740993", "9007199254740994", "9007199254740995"]],
			["{9223372036854775806..9223372036854775807}", ["9223372036854775806", "9223372036854775807"]],
		];
		for (const [word, expected] of cases) expect(words(word)).toEqual(expected);
	});
	test("keeps a word with no group that expands as it is", () => {
		for (const word of [
			"{}",
			"{/}",
			"{a..1}",
			"{1..2..a}",
			"{a..c..2..3}",
			"a,b}",
			"{a,b",
			"{1..99999999999999999999}",
			"{a..c..99999999999999999999}",
			"{1..3..-9223372036854775808}",
		])
			expect(words(word)).toEqual([word]);
	});
	// A span may be text the spelling cannot tell from a substitution (an escaped backtick), so a
	// span holding a brace or comma adds the reading with no span passed through after bash's.
	test("passes a substitution through whole and also reads it as text", () => {
		const cases: [string, string[], string[]][] = [
			["{$(echo a,b),c}", ["$(echo a,b)", "c"], ["$(echo a", "b)", "c"]],
			["{`echo a,b`,c}", ["`echo a,b`", "c"], ["`echo a", "b`", "c"]],
			["{${x:-a,b},c}", ["${x:-a,b}", "c"], ["$x:-a", "$b", "c"]],
			["${x:-{a,b}}", ["${x:-{a,b}}"], ["${x:-a}", "${x:-b}"]],
			["{`,/,`}", ["{`,/,`}"], ["`", "/", "`"]],
			["{$(,/,)}", ["{$(,/,)}"], ["$(", "/", ")"]],
		];
		for (const [word, passed, asText] of cases) expect(words(word)).toEqual([...passed, ...asText]);
	});
	test("reads a quoted brace or comma as text", () => {
		const q = EXPANSION_SUPPRESSED;
		for (const word of [`${q}/,x}`, `{/,x${q}`, `{/${q}x}`]) expect(words(word)).toEqual([word]);
		expect(words(`{${q},x}`)).toEqual([q, "x"]);
	});
	test("gives up on a listing past its limit or nesting past its depth", () => {
		expect(words("{a,b}".repeat(20), 100_000)).toBe("too-large");
		expect(words("{1..100000}", 100_000)).toBe("too-large");
		expect(words(`${"{a,".repeat(2000)}b${"}".repeat(2000)}`)).toBe("too-large");
		expect(words("{a,b}".repeat(10), 100_000)).toHaveLength(1024);
	});
	test("tells what a sequence's terms start with", () => {
		expect(braceSequenceStart("1..9")).toBe("digit");
		expect(braceSequenceStart("-3..3")).toBe("signed-digit");
		expect(braceSequenceStart("a..z")).toBe("letter");
		expect(braceSequenceStart("Z..a")).toBe("letter");
		for (const content of ["a..1", "a,b", "1..99999999999999999999", "1..3..-9223372036854775808"])
			expect(braceSequenceStart(content)).toBeNull();
	});
	test("stays linear on braces that never match", () => {
		for (const word of [`${"{".repeat(50_000)}}`, `${"{a}".repeat(20_000)},}`, `${"{a,".repeat(20_000)}}`]) {
			const started = Date.now();
			expandBraces(word, 100_000);
			expect(Date.now() - started).toBeLessThan(3000);
		}
	});
});

describe("staticWordMatches", () => {
	const json = `{v:1,diff_stat:{files:4,insertions:451},reviewers:[${"{id:d1,line:60,title:t,path:p,state:x,judge:y},".repeat(12)}{}]}`;
	test("a brace-heavy word that names no command matches nothing", () => {
		for (const name of ["sed", "rm", "git"]) expect(staticWordMatches(json, name)).toBe(false);
	});
	test("brace alternatives and sequences that yield the name match", () => {
		for (const word of ["{sed,-n}", "s{e,x}d", "s{e..e}d", "s{d..f}d", "/usr/bin/{x,sed}", "!!sed", "{x}/{sed,y}"])
			expect(staticWordMatches(word, "sed")).toBe(true);
	});
	test("words that do not yield the name do not match", () => {
		// bash does not re-expand a sequence built by an inner group: `s{e..{e,e}}d` is `s{e..e}d` twice.
		for (const word of ["{sed", "sed}", "{x,y}sed", "s{a..c}d", "{sed}", "sedx", "/sed/x", "s{e..{e,e}}d"])
			expect(staticWordMatches(word, "sed")).toBe(false);
	});
	test("a large product with a real alternative matches without enumerating it", () => {
		const started = Date.now();
		expect(staticWordMatches(`${"{a,b}".repeat(40)}/{sed,x}`, "sed")).toBe(true);
		expect(staticWordMatches(`${"{a,b}".repeat(40)}/{sex,x}`, "sed")).toBe(false);
		expect(Date.now() - started).toBeLessThan(1000);
	});
});
