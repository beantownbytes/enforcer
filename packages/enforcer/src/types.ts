/**
 * The hard-deny rule types. Only the deny-floor slice lives here; a judge's
 * Verdict/RiskLevel/config types are out of scope for this package.
 */

export interface HardDenyRule {
	pattern: string;
	reason: string;
	flags?: string;
}

/** A hard-deny rule matched by scanning the raw deny target. Every config-supplied rule is one. */
export interface CompiledRegexHardDenyRule {
	kind: "regex";
	regex: RegExp;
	reason: string;
}

/**
 * A built-in hard-deny rule matched against tokenized command runs rather than raw text.
 *
 * `match` receives the deny target already split into one dequoted argv array per command run
 * (including the runs nested inside quoted arguments and command substitutions), so a rule can
 * ask what a command IS -- program, flags, operands -- instead of re-deriving shell word
 * splitting in a pattern. See `argv-deny.ts`.
 *
 * `match` also receives the RAW deny target -- the command string before tokenizing -- because a
 * few rules need a distinction the tokenized runs erase: `suppressQuotedMetacharacters` collapses
 * `> < $ { } ,` inside quotes, so an argv rule cannot tell a redirect `>` from a comparison `>`
 * in an inline program (the awk floor). A rule that only asks what a command IS
 * ignores the extra parameter; a rule that must read a quoted program body reparses it from the
 * raw string with its metacharacters intact.
 */
export interface CompiledArgvHardDenyRule {
	kind: "argv";
	match: (runs: string[][], toolName: string, target: string) => boolean;
	reason: string;
}

export type CompiledHardDenyRule = CompiledRegexHardDenyRule | CompiledArgvHardDenyRule;
