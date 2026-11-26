/**
 * @enforcer/core -- the deterministic tool-call deny floor with tool-substitution
 * redirects. No LLM, no session, no harness coupling:
 * `matchesHardDeny` is a pure function returning a redirect reason or null.
 */

export { DEFAULT_HARD_DENY_ARGV, isSecretPath } from "./argv-deny.js";
export type { LoadRulesResult } from "./config.js";
export { compileRegexRules, loadRules, parseUserRules, resolveRulesPath, stripJsonComments } from "./config.js";
export { GIT_GLOBAL_BOOL_OPTS, GIT_GLOBAL_VALUE_OPTS } from "./git-opts.js";
export type { HardDenyContext, HardDenyMatch } from "./hard-deny.js";
export { denyTarget, matchesHardDeny } from "./hard-deny.js";
export type {
	CompiledArgvHardDenyRule,
	CompiledHardDenyRule,
	CompiledRegexHardDenyRule,
	HardDenyRule,
} from "./types.js";
