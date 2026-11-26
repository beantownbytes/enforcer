import { describe, expect, test } from "bun:test";
import { awkProgramHasNativeEscape, extractAwkPrograms } from "../src/awk-deny.js";

describe("awkProgramHasNativeEscape - native escape hatches detected", () => {
	test("print redirect to a file", () => expect(awkProgramHasNativeEscape('{print $1 > "/etc/passwd"}')).toBe(true));
	test("bare print redirect", () => expect(awkProgramHasNativeEscape('{print > "out"}')).toBe(true));
	test("printf append redirect", () => expect(awkProgramHasNativeEscape('{printf "%s",$0 >> "out"}')).toBe(true));
	test("printf with parens then redirect", () =>
		expect(awkProgramHasNativeEscape('{printf("%s",$0) > "out"}')).toBe(true));
	test("redirect inside a nested block", () =>
		expect(awkProgramHasNativeEscape('{if (x) print $1 > "f"}')).toBe(true));
	test("getline from a piped command", () => expect(awkProgramHasNativeEscape('BEGIN{"id" | getline x}')).toBe(true));
	test("getline from a bare command word", () => expect(awkProgramHasNativeEscape("{cmd | getline}")).toBe(true));
	test("getline via a gawk coprocess", () => expect(awkProgramHasNativeEscape('{"svc" |& getline r}')).toBe(true));
	test("getline reading a file", () => expect(awkProgramHasNativeEscape('{getline line < "/etc/passwd"}')).toBe(true));
	test("getline reading a file with no variable", () =>
		expect(awkProgramHasNativeEscape('{getline < "in"}')).toBe(true));
	test("print piped to a command", () => expect(awkProgramHasNativeEscape('{print $0 | "sort"}')).toBe(true));
	test("bare print piped to a command", () => expect(awkProgramHasNativeEscape('{print | "cmd"}')).toBe(true));
	test("printf piped to a command", () => expect(awkProgramHasNativeEscape('{printf "%s",$0 | "cat"}')).toBe(true));
});

describe("awkProgramHasNativeEscape - benign programs pass", () => {
	test("print to stdout", () => expect(awkProgramHasNativeEscape("{print $1}")).toBe(false));
	test("print a field list", () => expect(awkProgramHasNativeEscape("{print $1, $2}")).toBe(false));
	test("comparison in a pattern", () => expect(awkProgramHasNativeEscape("$1 > 5 {print}")).toBe(false));
	test("comparison guarding a print", () => expect(awkProgramHasNativeEscape("{if ($1 > 5) print}")).toBe(false));
	test("parenthesized comparison after print", () =>
		expect(awkProgramHasNativeEscape("{print ($1 > 5)}")).toBe(false));
	test("subscript comparison", () => expect(awkProgramHasNativeEscape("{a[i>j]=1}")).toBe(false));
	test("plain getline", () => expect(awkProgramHasNativeEscape("{getline; print}")).toBe(false));
	test("plain getline into a variable", () =>
		expect(awkProgramHasNativeEscape("{getline var; print var}")).toBe(false));
	test("system() is left to the general descent", () =>
		expect(awkProgramHasNativeEscape('{ system("rm x") }')).toBe(false));
	test("logical or before getline is not a pipe", () =>
		expect(awkProgramHasNativeEscape("{x || getline; print}")).toBe(false));
	test("a redirect char inside a regex is inert", () =>
		expect(awkProgramHasNativeEscape("{print /a>b/}")).toBe(false));
	test("a redirect char inside a comment is inert", () =>
		expect(awkProgramHasNativeEscape("{print $1} # print > file")).toBe(false));
	test("a redirect char inside a string is inert", () =>
		expect(awkProgramHasNativeEscape('{print "a > b"}')).toBe(false));
	test("empty program", () => expect(awkProgramHasNativeEscape("")).toBe(false));
});

describe("extractAwkPrograms - locates the raw inline program", () => {
	test("a plain awk invocation", () => expect(extractAwkPrograms("awk '{print $1}' file")).toEqual(["{print $1}"]));
	test("a gawk invocation", () => expect(extractAwkPrograms("gawk '{print > \"x\"}' f")).toEqual(['{print > "x"}']));
	test("skips -F and -v options", () =>
		expect(extractAwkPrograms("awk -F: -v n=1 '{print $n > \"o\"}' f")).toEqual(['{print $n > "o"}']));
	test("skips -F with a separate value", () =>
		expect(extractAwkPrograms("awk -F , '{print}' f")).toEqual(["{print}"]));
	test("honors -- as end of options", () => expect(extractAwkPrograms("awk -- '{print}' f")).toEqual(["{print}"]));
	test("follows a sudo wrapper to awk", () =>
		expect(extractAwkPrograms("sudo awk '{print > \"x\"}' f")).toEqual(['{print > "x"}']));
	test("follows an env wrapper to awk", () =>
		expect(extractAwkPrograms("env awk '{print > \"x\"}' f")).toEqual(['{print > "x"}']));
	test("finds awk on each side of a pipe", () =>
		expect(extractAwkPrograms("awk '{print}' f | awk '{getline < \"x\"}'")).toEqual(["{print}", '{getline < "x"}']));
	test("takes the -e value as the program, not the data file", () =>
		expect(extractAwkPrograms("awk -e '{print > \"x\"}' f")).toEqual(['{print > "x"}']));
	test("takes the --source value as the program", () =>
		expect(extractAwkPrograms("awk --source '{getline < \"f\"}' g")).toEqual(['{getline < "f"}']));
	test("takes the --source= attached value as the program", () =>
		expect(extractAwkPrograms("awk --source='{print}' f")).toEqual(["{print}"]));
	test("skips a redirection glued to its target", () =>
		expect(extractAwkPrograms("awk 2>/dev/null '{print}' f")).toEqual(["{print}"]));
	test("skips a redirection and its detached target", () =>
		expect(extractAwkPrograms("awk 2> /dev/null '{print}' f")).toEqual(["{print}"]));
	test("skips a redirection whose target is quoted", () =>
		expect(extractAwkPrograms("awk 2>'/dev/null' '{print}' f")).toEqual(["{print}"]));
	test("follows a wrapper past a redirection to awk", () =>
		expect(extractAwkPrograms("sudo >/dev/null awk '{print}' f")).toEqual(["{print}"]));
	test("keeps a quoted > as the -F value", () =>
		expect(extractAwkPrograms("awk -F '>' '{print}' f")).toEqual(["{print}"]));
	test("keeps an escaped > as the -F value", () =>
		expect(extractAwkPrograms("awk -F \\> '{print}' f")).toEqual(["{print}"]));
	test("keeps a quoted redirection-looking word as the program", () =>
		expect(extractAwkPrograms("awk '2>x' f")).toEqual(["2>x"]));
	test("an empty quoted redirection target does not consume the program", () =>
		expect(extractAwkPrograms("awk <<<'' 'BEGIN{exit}' 'note=print > out'")).toEqual(["BEGIN{exit}"]));
	test("adjacent redirections consume the trailing operator's target", () =>
		expect(extractAwkPrograms("awk >/dev/null> 'print > out' 'BEGIN{print \"ok\"}'")).toEqual(['BEGIN{print "ok"}']));
	test("adjacent redirections after a detached target", () =>
		expect(extractAwkPrograms("awk > /dev/null> 'print > out' 'BEGIN{print \"ok\"}'")).toEqual([
			'BEGIN{print "ok"}',
		]));
	test("adjacent redirections after a quoted target", () =>
		expect(extractAwkPrograms("awk >'/dev/null'> 'print > out' 'BEGIN{print \"ok\"}'")).toEqual([
			'BEGIN{print "ok"}',
		]));
	test("a here-string whose target is a dash", () =>
		expect(extractAwkPrograms("awk <<<- 'BEGIN{exit}' 'note=print > out'")).toEqual(["BEGIN{exit}"]));
	test("a here-doc body line is not read with its redirections split", () =>
		expect(extractAwkPrograms("cat <<'EOF'\nawk 2>/dev/null 'print > out'\nEOF")).not.toContain("print > out"));
	test("a descriptor duplication before the program", () =>
		expect(extractAwkPrograms("awk 2>&1 '{print}' f")).toEqual(["{print}"]));
	test("a both-streams redirection before the program", () =>
		expect(extractAwkPrograms("awk &>/dev/null '{print}' f")).toEqual(["{print}"]));
	test("an operator inside a parameter expansion stays program text", () =>
		expect(extractAwkPrograms("awk 'BEGIN{'${p:-print>out}'}'")).toEqual(["BEGIN{${p:-print>out}}"]));
	test("a quoted brace inside a parameter expansion does not swallow the program", () =>
		expect(extractAwkPrograms("awk -v sep=${p:-'{'} '{print}' f")).toEqual(["{print}"]));
	test("an operator split by a line continuation is read whole", () =>
		expect(extractAwkPrograms("awk >\\\n> 'print > out' 'BEGIN{print \"ok\"}'")).toEqual(['BEGIN{print "ok"}']));
	test("a tab-stripping here-doc split by a line continuation does not expose its delimiter", () =>
		expect(extractAwkPrograms("awk <<\\\n- 'print > out' 'BEGIN{exit}'")).not.toContain("print > out"));
	test("an operator inside $[...] arithmetic stays program text", () =>
		expect(extractAwkPrograms("awk 'BEGIN{print '$[1>0]'>out}'")).toEqual(["BEGIN{print $[1>0]>out}"]));
	test("an expansion opener split by a line continuation keeps its operator as program text", () =>
		expect(extractAwkPrograms("awk 'BEGIN{'$\\\n{p:-print>out}'}'")).toEqual(["BEGIN{${p:-print>out}}"]));
	test("a comment-looking destination inside an expansion keeps the program", () =>
		expect(extractAwkPrograms('awk -v sep=${p:-x>#ignored} \'BEGIN{print "x" > "out"}\'')).toContain(
			'BEGIN{print "x" > "out"}',
		));
	test("a redirection glued after the program is not part of it", () =>
		expect(extractAwkPrograms("awk '{print}'>/dev/null f")).toEqual(["{print}"]));
});

describe("extractAwkPrograms - fail-closed omissions", () => {
	test("a program file (-f) is not inline, so it is omitted", () =>
		expect(extractAwkPrograms("awk -f prog.awk file")).toEqual([]));
	test("a long-form --file is omitted", () => expect(extractAwkPrograms("awk --file=prog.awk file")).toEqual([]));
	test("an unrecognized option omits the occurrence", () =>
		expect(extractAwkPrograms("awk --traditional '{print > \"x\"}' f")).toEqual([]));
	test("awk mentioned as a non-executable operand is not a head", () =>
		expect(extractAwkPrograms("echo awk '{print > \"x\"}'")).toEqual([]));
	test("awk with no operand yields nothing", () => expect(extractAwkPrograms("awk")).toEqual([]));
	test("an expansion inside a redirection target does not expose the target as the program", () =>
		expect(extractAwkPrograms("awk >${out:-unused 'print > out'} 'BEGIN{exit}'")).not.toContain("print > out}"));
	test("a separator inside an earlier expansion does not start a run read with redirections split", () =>
		expect(extractAwkPrograms("echo ${p:-;awk >out 'print > out'}")).not.toContain("print > out}"));
	test("an empty expansion after a redirection does not expose an option value as the program", () =>
		expect(extractAwkPrograms("awk >/dev/null -F $(true) 'print > out' 'BEGIN{exit}'")).not.toContain("print > out"));
	test("a process substitution's misread end does not start a run read with redirections split", () =>
		expect(extractAwkPrograms("echo <(true # ); awk >/dev/null 'print > out'\n)")).not.toContain("print > out"));
	test("a quoted all-arguments expansion does not expose an option value as the program", () =>
		expect(extractAwkPrograms("awk >/dev/null -F \"$@\" 'print > out' 'BEGIN{exit}'")).not.toContain("print > out"));
	test("a brace expansion does not expose an operand as the program", () =>
		expect(extractAwkPrograms("awk >/dev/null -F {x,'BEGIN{exit}'} 'print > out'")).not.toContain("print > out"));
	test("a quote inside a double-quoted substitution does not end the word", () => {
		expect(extractAwkPrograms(`awk -v k="$(echo ")")" 'print > out'`)).toContain("print > out");
		expect(extractAwkPrograms(`awk -v k="$(echo " 'print > out' ")" 'BEGIN{exit}'`)).toEqual(["BEGIN{exit}"]);
		expect(extractAwkPrograms("awk -v k=\"`echo \" 'print > out' \"`\" 'BEGIN{exit}'")).toEqual(["BEGIN{exit}"]);
	});
	test("a double-quoted substitution's misread end does not start a run read with redirections split", () =>
		expect(extractAwkPrograms('echo "$(true # "); awk >/dev/null \'print > out\'\n)"')).not.toContain("print > out"));
	test("an extended glob's alternatives are not read as runs with redirections split", () => {
		for (const opener of ["@", "+", "!"]) {
			expect(extractAwkPrograms(`printf '%s\\n' ${opener}(x|awk >/dev/null 'print > out')`)).not.toContain(
				"print > out",
			);
		}
	});
	test("an arithmetic command's body is not read as runs with redirections split", () =>
		expect(extractAwkPrograms('(( 1 || awk > + "print > out" ))')).not.toContain("print > out"));
	test("a process substitution split by a line continuation is not read as a redirection", () =>
		expect(extractAwkPrograms("printf '%s\\n' <\\\n(true)awk >/dev/null 'print > out'")).not.toContain(
			"print > out",
		));
	test("a subshell still has its redirections split", () =>
		expect(extractAwkPrograms("(cd /tmp && awk 2>/dev/null '{print}' f)")).toEqual(["{print}"]));
	test("a blank bash does not break words on leaves redirections in their words", () => {
		for (const blank of ["\r", "\f", "\v"]) {
			expect(extractAwkPrograms(`awk >out${blank}'print > out' 'BEGIN{exit}'`)).not.toContain("print > out");
		}
	});
});
