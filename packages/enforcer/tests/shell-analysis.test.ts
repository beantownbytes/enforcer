import { describe, expect, test } from "bun:test";
import { analyzeShellCommand } from "../src/shell-tokens.js";
import { expectScaling, SCALING_TEST_TIMEOUT_MS } from "./perf-bound.js";

describe("analyzeShellCommand", () => {
	test("preserves top-level command order and control operators", () => {
		expect(analyzeShellCommand("git status && git push | tee log")).toEqual({
			complete: true,
			topLevel: [
				{ kind: "command", argv: ["git", "status"] },
				{ kind: "operator", operator: "&&" },
				{ kind: "command", argv: ["git", "push"] },
				{ kind: "operator", operator: "|" },
				{ kind: "command", argv: ["tee", "log"] },
			],
			nested: [],
		});
	});

	test("preserves subshell group boundaries", () => {
		expect(analyzeShellCommand("(cd /tmp && pwd)").topLevel).toEqual([
			{ kind: "group", boundary: "start" },
			{ kind: "command", argv: ["cd", "/tmp"] },
			{ kind: "operator", operator: "&&" },
			{ kind: "command", argv: ["pwd"] },
			{ kind: "group", boundary: "end" },
		]);
	});

	test("inventories nested executable runs with provenance", () => {
		const command = 'echo $(git status; git push) <(git diff) `git log` "git branch && git tag"';
		expect(analyzeShellCommand(command).nested).toEqual([
			{ kind: "command-substitution", argv: ["git", "status"] },
			{ kind: "command-substitution", argv: ["git", "push"] },
			{ kind: "process-substitution", argv: ["git", "diff"] },
			{ kind: "backtick", argv: ["git", "log"] },
			{ kind: "quoted-potential", argv: ["git", "branch"] },
			{ kind: "quoted-potential", argv: ["git", "tag"] },
		]);
	});

	test("inventories a double-quoted backtick substitution whose body is one word", () => {
		for (const command of ['echo "`sed`"', "echo \"x'`sed`'\"", 'echo "a`sed`b"']) {
			expect(analyzeShellCommand(command).nested).toContainEqual({ kind: "backtick", argv: ["sed"] });
		}
		expect(analyzeShellCommand('echo "\\`sed\\`"').nested).not.toContainEqual({ kind: "backtick", argv: ["sed"] });
	});

	test("inventories a substitution inside single quotes", () => {
		expect(analyzeShellCommand("echo '$(git push)'").nested).toContainEqual({
			kind: "command-substitution",
			argv: ["git", "push"],
		});
	});

	test("inventories executable argument sources", () => {
		expect(analyzeShellCommand("bash -c sed").nested).toContainEqual({
			kind: "argument-source",
			argv: ["sed"],
		});
	});

	test("recursively inventories substitutions inside arithmetic", () => {
		expect(analyzeShellCommand("echo $(( $(git push) ))").nested).toContainEqual({
			kind: "command-substitution",
			argv: ["git", "push"],
		});
	});

	test("marks unclosed constructs and unsupported grammar incomplete", () => {
		for (const command of [
			'echo "unterminated',
			"echo $(unterminated",
			"(git status",
			"git status)",
			"if true; then echo yes; fi",
			"cat <<EOF\ncontent\nEOF",
			"case x in x) echo yes;; esac",
			`echo \${HOME}`,
			"echo trailing\\",
		]) {
			expect(analyzeShellCommand(command).complete).toBe(false);
		}
	});

	test(
		"stays linear on nested unsupported parameter expansions",
		() =>
			expectScaling({
				build: (depth) => `echo ${"${".repeat(depth)}x${"}".repeat(depth)}`,
				run: (command) => expect(analyzeShellCommand(command).complete).toBe(false),
				size: 5000,
				ceilingMs: 8000,
			}),
		SCALING_TEST_TIMEOUT_MS,
	);

	test("marks exhausted nested work incomplete", () => {
		const analysis = analyzeShellCommand('sh -c "git status && git push"', 0);
		expect(analysis.complete).toBe(false);
		expect(analysis.topLevel).toEqual([{ kind: "command", argv: ["sh", "-c", "git status && git push"] }]);
		expect(analysis.nested).toEqual([]);
	});

	test("does not confuse redirection syntax with control operators", () => {
		const analysis = analyzeShellCommand("git push 2>&1 && tail -f log");
		expect(analysis.complete).toBe(true);
		expect(analysis.topLevel).toEqual([
			{ kind: "command", argv: ["git", "push", "2>&1"] },
			{ kind: "operator", operator: "&&" },
			{ kind: "command", argv: ["tail", "-f", "log"] },
		]);
	});
});
