/**
 * The version the shipped binary reports through `--version`.
 *
 * `packages/enforcer/package.json` is bundled into the single-file executable, so the
 * answer needs no filesystem access at runtime and survives the binary being moved
 * anywhere on disk.
 *
 * The repository `VERSION` file is what the release pipeline bumps, so these are two
 * names for one number. `cli - version` in tests/cli.test.ts pins them together: a
 * release that bumps one file and not the other fails the test suite, and
 * `make version-check` (a prerequisite of both build targets) refuses to compile.
 */
import pkg from "../package.json" with { type: "json" };

export const ENFORCER_VERSION: string = pkg.version;
