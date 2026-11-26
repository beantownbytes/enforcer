/**
 * Ratio bound for the default step of one doubling, where a straight line costs 2x and a quadratic
 * 4x. A shape whose cost grows slightly faster than linear is measured against this bound only when
 * its size parameter also drives threshold behaviour that has to hold at every size; those shapes
 * pass a wider `ratioPair` and the bound that goes with it.
 */
export const MAX_DOUBLING_RATIO = 3;

/**
 * Per-test harness timeout for the scaling tests. It is a watchdog against a hang, not a bound the
 * measurements compete against -- the ceilings passed to `expectScaling` are the bound.
 */
export const SCALING_TEST_TIMEOUT_MS = 120_000;

/**
 * Shortest a single measurement may be, in ms. Below this a sample is mostly timer resolution and
 * scheduler jitter, so `expectScaling` repeats the run until it clears the target.
 */
const MIN_SAMPLE_MS = 50;

/** Upper bound on those repetitions, so a trivial shape cannot make a test loop for minutes. */
const MAX_REPETITIONS = 32;

/**
 * Longest a single measurement should be, in ms. The repeat count is chosen so the cheaper size
 * reaches MIN_SAMPLE_MS without pushing the expensive size past this, because the expensive size is
 * what the test's own ceiling has to stay affordable against.
 */
const MAX_SAMPLE_MS = 150;

export type ScalingCheck<Input> = {
	/** Builds the input for a given size. Called before anything is timed. */
	build: (size: number) => Input;
	/** Runs the function under test, plus whatever has to hold at every size. */
	run: (input: Input) => void;
	/** The size this shape is specified at. The ceiling is measured here, per call. */
	size: number;
	/** Absolute backstop for one call at `size`, in ms. */
	ceilingMs: number;
	/**
	 * The two sizes to compare for the ratio. Defaults to half of `size` and `size`; the larger entry
	 * has to be `size` itself, because that is the sample the ceiling is read from.
	 */
	ratioPair?: [number, number];
	/** Largest accepted cost multiplier across that pair. Defaults to `MAX_DOUBLING_RATIO`. */
	maxRatio?: number;
	/** Samples taken per size. Defaults to 3. */
	attempts?: number;
};

/** Wall-clock cost of `times` runs of `run(input)`, floored so a division by it stays finite. */
function measure<Input>(run: (input: Input) => void, input: Input, times = 1): number {
	const started = performance.now();
	for (let i = 0; i < times; i++) run(input);
	return Math.max(performance.now() - started, 0.01);
}

/**
 * Asserts that `run` costs less than `maxRatio` times as much at the larger of two sizes as at the
 * smaller, and less than `ceilingMs` at `size`.
 *
 * A cost ratio is what makes the assertion hold on whatever hardware runs it, which a wall-clock
 * budget is not: the same measurement moves several-fold between machines while the ratio does not.
 * A ratio is also scale-free, so a regression cheap enough to slip under any absolute budget still
 * shows up as 4x per doubling. The ceiling carries the denial-of-service half of the property, since
 * the code these tests cover runs synchronously on every tool call: it stays far above what any
 * runner measures for the shapes here (all of them under 3% of their ceiling), so only a change of
 * magnitude in the floor itself reaches it.
 *
 * The step between the two sizes is a free parameter worth spending. The distance between a shape
 * that costs n^exp and a quadratic is step^(2-exp), so widening the step widens that distance: at a
 * doubling a shape at n^1.4 sits 1.4x below a quadratic, and at a step of 8 it sits 2.8x below. Sites
 * therefore compare an eighth of the size where the shape's size parameter is a plain count, with
 * `maxRatio` set between the two anchors the step defines -- 8 for a straight line, 64 for a
 * quadratic. Shapes whose size parameter also drives a threshold that must hold at every size keep
 * the default doubling, since their `run` has to assert the threshold at both sizes.
 *
 * Both inputs are built before anything is timed, and the calibration runs are also the warm-up: each
 * input executes once untimed before the first sample is taken, because allocating an input tens of
 * kilobytes long costs more than the parse it feeds. A full collection
 * runs before every sample. That is not decoration: with the heap loaded the way a real test run
 * leaves it, the garbage an input allocates is collected inside whichever sample follows it, which
 * pushed the measured ratio of a shape that costs 2x per doubling to a median of 4.6 and a maximum of
 * 5.3, while collections brought the same shape back under 2.7 and left a quadratic at 4.0. Sampling
 * without collections measures the heap, and measuring the heap would mean picking a bound loose
 * enough to pass it, which is how an absolute budget failed in the first place.
 *
 * Samples alternate small, large so a machine that slows down partway through inflates both
 * measurements instead of only one, and each sample repeats the run enough times to be worth timing.
 * The ceiling is read off that large sample divided by the repeats it ran, so it stays a per-call
 * bound however many repeats the ratio sampling needed. Both bounds report the sizes, the repeat
 * count and both sample costs, because two bare totals would not say what was compared.
 */
export function expectScaling<Input>({
	build,
	run,
	size,
	ceilingMs,
	ratioPair,
	maxRatio = MAX_DOUBLING_RATIO,
	attempts = 3,
}: ScalingCheck<Input>): void {
	const [smallSize, largeSize] = ratioPair ?? [size / 2, size];
	if (largeSize !== size) {
		throw new Error(`expectScaling: the ratio pair has to end at size ${size}, got ${smallSize} -> ${largeSize}`);
	}
	const small = build(smallSize);
	const large = build(largeSize);
	// These two calibration runs are the warm-up as well: each input has executed once by the time
	// the first sample is taken, so there is no separate warm run to spend. Reading them cold can
	// only lower `repeats`, which stays a valid count for both sizes.
	const repeats = Math.min(
		MAX_REPETITIONS,
		// One count for both sizes so they stay comparable: bring the cheap side up to MIN_SAMPLE_MS
		// without letting the expensive side run past MAX_SAMPLE_MS.
		Math.max(1, Math.floor(Math.min(MIN_SAMPLE_MS / measure(run, small), MAX_SAMPLE_MS / measure(run, large)))),
	);
	let lowSmall = Number.POSITIVE_INFINITY;
	let lowLarge = Number.POSITIVE_INFINITY;
	for (let attempt = 0; attempt < attempts; attempt++) {
		Bun.gc(true);
		lowSmall = Math.min(lowSmall, measure(run, small, repeats));
		Bun.gc(true);
		lowLarge = Math.min(lowLarge, measure(run, large, repeats));
	}
	const ratio = lowLarge / lowSmall;
	if (ratio >= maxRatio) {
		throw new Error(
			`cost grew ${ratio.toFixed(2)}x from ${smallSize} to ${size}, over the bound of ${maxRatio}: ` +
				`${lowSmall.toFixed(2)}ms vs ${lowLarge.toFixed(2)}ms over ${repeats} run(s) per sample`,
		);
	}
	const perCallMs = lowLarge / repeats;
	if (perCallMs >= ceilingMs) {
		throw new Error(
			`${perCallMs.toFixed(2)}ms per call at size ${size} is over the ceiling of ${ceilingMs}ms: ` +
				`${lowLarge.toFixed(2)}ms over ${repeats} run(s) per sample`,
		);
	}
}
