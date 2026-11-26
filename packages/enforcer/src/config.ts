import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DEFAULT_HARD_DENY_ARGV } from "./argv-deny.js";
import type { CompiledHardDenyRule, HardDenyRule } from "./types.js";

export interface LoadRulesResult {
	rules: CompiledHardDenyRule[];
	warnings: string[];
}

/**
 * Strip `//` line and block comments so a JSONC rules file parses as JSON, without
 * touching comment-like sequences inside string literals. A small hand-rolled pass
 * keeps the package dependency-free.
 */
export function stripJsonComments(text: string): string {
	let out = "";
	let inString = false;
	let escaped = false;
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (inString) {
			out += c;
			if (escaped) escaped = false;
			else if (c === "\\") escaped = true;
			else if (c === '"') inString = false;
			continue;
		}
		if (c === '"') {
			inString = true;
			out += c;
			continue;
		}
		if (c === "/" && text[i + 1] === "/") {
			while (i < text.length && text[i] !== "\n") i++;
			out += "\n";
			continue;
		}
		if (c === "/" && text[i + 1] === "*") {
			i += 2;
			while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
			i += 1;
			continue;
		}
		out += c;
	}
	return out;
}

/** Compile config-supplied `{pattern, reason, flags?}` redirects into regex rules. */
export function compileRegexRules(rules: HardDenyRule[], warnings: string[]): CompiledHardDenyRule[] {
	const compiled: CompiledHardDenyRule[] = [];
	for (const rule of rules) {
		try {
			compiled.push({ kind: "regex", regex: new RegExp(rule.pattern, rule.flags ?? "i"), reason: rule.reason });
		} catch (err) {
			warnings.push(
				`enforcer: invalid rule pattern ${JSON.stringify(rule.pattern)}: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}
	return compiled;
}

/** The user rules file: `$ENFORCER_RULES`, else `~/.config/enforcer/rules.jsonc`. */
export function resolveRulesPath(): string {
	return process.env.ENFORCER_RULES ?? join(homedir(), ".config", "enforcer", "rules.jsonc");
}

/** Parse a rules file's contents into raw HardDenyRule entries; tolerant, never throws. */
export function parseUserRules(text: string, warnings: string[]): HardDenyRule[] {
	let data: unknown;
	try {
		data = JSON.parse(stripJsonComments(text));
	} catch (err) {
		warnings.push(
			`enforcer: rules file is not valid JSON/JSONC: ${err instanceof Error ? err.message : String(err)}`,
		);
		return [];
	}
	if (!Array.isArray(data)) {
		warnings.push("enforcer: rules file must be a JSON array of {pattern, reason, flags?}");
		return [];
	}
	const rules: HardDenyRule[] = [];
	for (const entry of data) {
		if (
			entry &&
			typeof entry === "object" &&
			typeof (entry as HardDenyRule).pattern === "string" &&
			typeof (entry as HardDenyRule).reason === "string"
		) {
			rules.push(entry as HardDenyRule);
		} else {
			warnings.push(`enforcer: skipping malformed rule entry ${JSON.stringify(entry)}`);
		}
	}
	return rules;
}

/**
 * Assemble the full rule list: the built-in deny floor (`DEFAULT_HARD_DENY_ARGV`, the
 * sed/awk/rm/force-push/secret-write redirects) followed by any user-added regex
 * redirects. A project can only ADD rules, never remove a built-in.
 */
export function loadRules(path: string = resolveRulesPath()): LoadRulesResult {
	const warnings: string[] = [];
	let userRules: HardDenyRule[] = [];
	if (existsSync(path)) {
		try {
			userRules = parseUserRules(readFileSync(path, "utf8"), warnings);
		} catch (err) {
			warnings.push(`enforcer: cannot read rules file ${path}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
	return { rules: [...DEFAULT_HARD_DENY_ARGV, ...compileRegexRules(userRules, warnings)], warnings };
}
