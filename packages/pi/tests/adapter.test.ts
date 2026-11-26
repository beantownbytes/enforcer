import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import enforcerPi from "../src/index.js";

// Isolated rules file so the test never reads the developer's real config.
const tempDir = mkdtempSync(join(tmpdir(), "enforcer-pi-adapter-"));
const priorEnv = process.env.ENFORCER_RULES;
beforeAll(() => {
	process.env.ENFORCER_RULES = join(tempDir, "rules.jsonc");
});
afterAll(() => {
	if (priorEnv === undefined) Reflect.deleteProperty(process.env, "ENFORCER_RULES");
	else process.env.ENFORCER_RULES = priorEnv;
	rmSync(tempDir, { recursive: true, force: true });
});

function makePi() {
	const registered = new Set<string>();
	let handler: ((event: any, ctx: any) => any) | undefined;
	const pi = {
		on: (event: string, h: (event: any, ctx: any) => any) => {
			registered.add(event);
			handler = h;
		},
	};
	const call = (event: any, ctx: any) => handler!(event, ctx);
	return { pi, registered, call };
}

function makeCtx(hasUI = false) {
	const warnings: string[] = [];
	const ctx = {
		hasUI,
		ui: { notify: (message: string) => warnings.push(message) },
	};
	return { ctx, warnings };
}

const bashCall = (command: string) => ({
	type: "tool_call",
	toolCallId: "t1",
	toolName: "bash",
	input: { command },
});
const customCall = (toolName: string, input: Record<string, unknown>) => ({
	type: "tool_call",
	toolCallId: "t1",
	toolName,
	input,
});

describe("adapter: blocked calls", () => {
	test("rm -rf / is blocked with the exact built-in reason", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		expect(call(bashCall("rm -rf /"), makeCtx().ctx)).toEqual({
			block: true,
			reason: "recursive/force delete targeting /, ~, $HOME or *",
		});
	});
	test("git push --force is blocked with the exact reason", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		expect(call(bashCall("git push origin main --force"), makeCtx().ctx)).toEqual({
			block: true,
			reason: "git push --force",
		});
	});
	test("redirect reason text is preserved verbatim", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		expect(call(bashCall("sed -n '1,10p' file"), makeCtx().ctx)).toEqual({
			block: true,
			reason:
				"sed is hard-denied; use slice lines for range reads, ripgrep (rg) or slice grep for searching/extracting, and the edit tool for in-place edits",
		});
	});
	test("custom tool input containing a dangerous command is blocked", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		expect(call(customCall("deprovision", { script: "rm -rf /" }), makeCtx().ctx)).toEqual({
			block: true,
			reason: "recursive/force delete targeting /, ~, $HOME or *",
		});
	});
});

describe("adapter: permitted calls", () => {
	test("ordinary bash commands pass through", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		for (const command of ["ls -la", "git push origin main", "rm -rf ./build", "echo hello"]) {
			expect(call(bashCall(command), makeCtx().ctx)).toBeUndefined();
		}
	});
	test("harmless custom tools pass through", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		expect(call(customCall("deploy_status", { message: "all good", count: 2 }), makeCtx().ctx)).toBeUndefined();
	});
	test("a blocked result carries no terminate flag", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		const result = call(bashCall("rm -rf ~"), makeCtx().ctx);
		expect(result?.terminate).toBeUndefined();
	});
});

describe("adapter: inputs and names unmutated", () => {
	test("the event is not modified by a blocked call", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		const event = bashCall("rm -rf /");
		const snapshot = JSON.parse(JSON.stringify(event));
		call(event, makeCtx().ctx);
		expect(event).toEqual(snapshot);
	});
	test("the event is not modified by a permitted call", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		const event = bashCall("ls -la");
		const snapshot = JSON.parse(JSON.stringify(event));
		call(event, makeCtx().ctx);
		expect(event).toEqual(snapshot);
	});
});

describe("adapter: no UI or model interactions", () => {
	test("registers exactly one tool_call handler", () => {
		const { pi, registered } = makePi();
		enforcerPi(pi as any);
		expect([...registered]).toEqual(["tool_call"]);
	});
	test("no warnings are notified when the rules load cleanly", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		const { ctx, warnings } = makeCtx(true);
		call(bashCall("rm -rf /"), ctx);
		call(bashCall("ls -la"), ctx);
		expect(warnings).toEqual([]);
	});
	test("no UI prompt is raised for blocked calls", () => {
		const { pi, call } = makePi();
		enforcerPi(pi as any);
		let prompted = false;
		const ctx = {
			hasUI: true,
			ui: {
				notify: () => {},
				prompt: () => {
					prompted = true;
				},
			},
		};
		call(bashCall("git push --force"), ctx);
		expect(prompted).toBe(false);
	});
});
