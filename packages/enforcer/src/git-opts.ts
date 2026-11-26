/**
 * Git global-option arity tables, kept here so the deny floor (argv-deny.ts) does not
 * restate git's option tables. This package holds the single definition; consumers
 * import these rather than keeping their own copy.
 *
 * A global option in NEITHER set is treated as unknown-arity -> withhold (fail closed).
 */

/** Global options that TAKE a value (their next word is consumed, never the subcommand). */
export const GIT_GLOBAL_VALUE_OPTS = new Set([
	"-C",
	"-c",
	"--exec-path",
	"--git-dir",
	"--work-tree",
	"--namespace",
	"--config-env",
	"--super-prefix",
	"--attr-source",
]);

/** Global options that are boolean flags (consume no following word). */
export const GIT_GLOBAL_BOOL_OPTS = new Set([
	"-v",
	"--version",
	"-h",
	"--help",
	"-p",
	"--paginate",
	"-P",
	"--no-pager",
	"--bare",
	"--no-replace-objects",
	"--no-lazy-fetch",
	"--no-optional-locks",
	"--no-advice",
	"--html-path",
	"--man-path",
	"--info-path",
	"--literal-pathspecs",
	"--no-literal-pathspecs",
	"--glob-pathspecs",
	"--noglob-pathspecs",
	"--icase-pathspecs",
]);
