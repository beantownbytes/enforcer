import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BashToolCallEvent, LoadExtensionsResult } from "@earendil-works/pi-coding-agent";
import {
	DefaultResourceLoader,
	ExtensionRunner,
	ModelRegistry,
	ModelRuntime,
	SessionManager,
} from "@earendil-works/pi-coding-agent";

// Isolated agent dir + cwd so the real loader never touches the developer's
// ~/.pi settings, and a throwaway ENFORCER_RULES so only the built-in floor is
// active. The ModelRuntime gets its own temp auth/models paths for the same
// reason; it does not inherit the loader's agentDir.
const pkgDir = join(import.meta.dir, "..");
const agentDir = mkdtempSync(join(tmpdir(), "enforcer-pi-agent-"));
const cwd = mkdtempSync(join(tmpdir(), "enforcer-pi-cwd-"));
const priorEnv = process.env.ENFORCER_RULES;
const rulesPath = join(agentDir, "no-rules.jsonc");

let loaded: LoadExtensionsResult;
let runner: ExtensionRunner;

beforeAll(async () => {
	writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ extensions: [pkgDir] }));
	process.env.ENFORCER_RULES = rulesPath;
	const loader = new DefaultResourceLoader({ cwd, agentDir });
	await loader.reload();
	loaded = loader.getExtensions();
	runner = new ExtensionRunner(
		loaded.extensions,
		loaded.runtime,
		cwd,
		SessionManager.inMemory(cwd),
		new ModelRegistry(
			await ModelRuntime.create({
				authPath: join(agentDir, "auth.json"),
				modelsPath: join(agentDir, "models.json"),
				modelsStorePath: join(agentDir, "models-store.json"),
				refreshOnCreate: false,
			}),
		),
	);
});
afterAll(() => {
	if (priorEnv === undefined) Reflect.deleteProperty(process.env, "ENFORCER_RULES");
	else process.env.ENFORCER_RULES = priorEnv;
	rmSync(agentDir, { recursive: true, force: true });
	rmSync(cwd, { recursive: true, force: true });
});

const toolCall = (input: { command: string }): BashToolCallEvent => ({
	type: "tool_call",
	toolCallId: "smoke",
	toolName: "bash",
	input,
});

describe("loading smoke: real Pi loader", () => {
	test("the local package resolves through the pi.extensions manifest", () => {
		expect(loaded.errors).toEqual([]);
		expect(loaded.extensions).toHaveLength(1);
		const extension = loaded.extensions[0];
		expect(extension.path).toBe(join(pkgDir, "index.ts"));
	});
	test("the extension registers a tool_call handler", () => {
		const extension = loaded.extensions[0];
		const handlers = extension.handlers.get("tool_call");
		expect(handlers).toBeDefined();
		expect(handlers?.length).toBeGreaterThan(0);
	});
});

describe("loading smoke: extension runner dispatch", () => {
	test("a blocked rm -rf / returns the exact deny result", async () => {
		const result = await runner.emitToolCall(toolCall({ command: "rm -rf /" }));
		expect(result).toEqual({
			block: true,
			reason: "recursive/force delete targeting /, ~, $HOME or *",
		});
	});
	test("a permitted ls -la returns undefined", async () => {
		expect(await runner.emitToolCall(toolCall({ command: "ls -la" }))).toBeUndefined();
	});
});
