/**
 * Evaluate one tool call against the built-in floor while every tokenization of `target` from the
 * `failFrom`-th on (1-based) throws, standing in for a tokenizer defect or an input crafted to
 * trigger one.
 *
 * The throw is injected by patching `String.prototype.includes`, the first call `tokenizeCommand`
 * makes on its source. A write to a built-in prototype can slow string handling for the rest of
 * the process it happens in, so this runs as its own process rather than inside the test runner.
 *
 * argv[2]: JSON `{ tool, input, target, failFrom }`. Prints JSON `{ reason, thrown }`: the deny
 * reason or null, and how many tokenizations threw, so a caller can prove the failure was injected.
 */
import { DEFAULT_HARD_DENY_ARGV } from "../../src/argv-deny.js";
import { matchesHardDeny } from "../../src/hard-deny.js";

interface Call {
	tool: string;
	input: Record<string, unknown>;
	target: string;
	failFrom: number;
}

const { tool, input, target, failFrom } = JSON.parse(process.argv[2] ?? "") as Call;
const includes = String.prototype.includes;
let tokenizations = 0;
let thrown = 0;
String.prototype.includes = function (this: string, search: string, position?: number): boolean {
	if (search === "<<" && String(this) === target) {
		tokenizations += 1;
		if (tokenizations >= failFrom) {
			thrown += 1;
			throw new RangeError("injected tokenizer failure");
		}
	}
	return includes.call(this, search, position);
};
const match = matchesHardDeny(tool, input, DEFAULT_HARD_DENY_ARGV);
String.prototype.includes = includes;
process.stdout.write(JSON.stringify({ reason: match?.reason ?? null, thrown }));
