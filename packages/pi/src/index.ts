import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
	ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { loadRules, matchesHardDeny } from "@enforcer/core";

function reportWarning(warning: string, ctx: ExtensionContext): void {
	if (ctx.hasUI) ctx.ui.notify(warning, "warning");
	else console.warn(warning);
}

/**
 * enforcer-pi: apply enforcer's deterministic hard-deny floor to every agent
 * tool call. Nonmatching calls pass through untouched; no LLM judge, no
 * approval prompts, no terminating-agent behavior.
 */
export default function enforcerPi(pi: ExtensionAPI): void {
	pi.on("tool_call", (event: ToolCallEvent, ctx: ExtensionContext): ToolCallEventResult | undefined => {
		const { rules, warnings } = loadRules();
		for (const warning of warnings) reportWarning(warning, ctx);
		// No context is passed on purpose: matchesHardDeny's default context is
		// fail-closed (no tracked-file exemption), and an input-supplied flag
		// would be untrusted.
		const match = matchesHardDeny(event.toolName, event.input as Record<string, unknown>, rules);
		if (!match) return undefined;
		return { block: true, reason: match.reason };
	});
}
