package com.jexray.jadx.bridge;

import java.util.ArrayList;
import java.util.List;

import com.jexray.jadx.util.HumanFormat;

/**
 * Aggregate progress across every library being pre-warmed.
 *
 * <p>Libraries analyze concurrently, so progress can't be "library i of n plus a fraction" -- there
 * is no single current library. Instead each library contributes its own fraction and the overall
 * value is their mean, which keeps the denominator fixed and the value monotonic.
 *
 * <p>The counts are the honest summary of the whole pool, but the user still wants to know *what*
 * is running -- so each currently-analyzing library also contributes its own name/size/elapsed
 * label (see {@link #analyzingLine()}). This is different from naming a single library the way
 * {@code showLoadProgress} does for a one-at-a-time load: several libraries are shown together,
 * so none of them is misrepresented as "the" one in progress.
 */
public record PrewarmProgress(int total, int ready, int analyzing, int queued, int failed, double fraction,
		List<String> analyzingLabels) {

	/** Cap on how many analyzing-library names are shown at once (matches the bridge's load-pool
	 * size), so an unusually large pool can never stretch the overlay. */
	private static final int MAX_ANALYZING_NAMES = 3;

	/**
	 * One library's reported state, reduced to what aggregation needs.
	 *
	 * <p>{@code name}/{@code sizeBytes}/{@code startedAtMs} are only meaningful while analyzing --
	 * they describe what the overlay's names line should show for this library, not general
	 * library metadata. The 3-arg constructor covers the older call sites that don't have (or
	 * don't need) that display info, e.g. the ready/error/queued cases.
	 */
	public record LibState(String status, int completed, int total, String name, long sizeBytes, long startedAtMs) {

		public LibState(String status, int completed, int total) {
			this(status, completed, total, null, 0L, 0L);
		}
	}

	/**
	 * Each library contributes:
	 * <ul>
	 *   <li>{@code 1.0} once terminal -- ready, or failed (a failed library will never progress
	 *       further, and dropping it from the denominator instead would make the bar jump);</li>
	 *   <li>{@code completed/total} while analyzing with real counts;</li>
	 *   <li>{@code 0.0} while queued, or analyzing before any count exists (the import and
	 *       auto-analysis phase reports nothing) -- never an invented number.</li>
	 * </ul>
	 * With nothing measurable this reduces exactly to "finished / total".
	 */
	public static PrewarmProgress of(List<LibState> states) {
		return of(states, System.currentTimeMillis());
	}

	/**
	 * As {@link #of(List)}, but with the clock passed in rather than read here, so the
	 * analyzing-library elapsed labels are deterministic and testable without waiting in real
	 * time.
	 */
	public static PrewarmProgress of(List<LibState> states, long nowMs) {
		int n = states == null ? 0 : states.size();
		if (n == 0) {
			return new PrewarmProgress(0, 0, 0, 0, 0, 0.0, List.of());
		}
		int ready = 0;
		int analyzing = 0;
		int queued = 0;
		int failed = 0;
		double sum = 0.0;
		List<String> analyzingLabels = new ArrayList<>();
		for (LibState s : states) {
			String status = s.status() == null ? "" : s.status();
			switch (status) {
				case "ready" -> {
					ready++;
					sum += 1.0;
				}
				case "error" -> {
					failed++;
					sum += 1.0;
				}
				case "queued" -> queued++;
				default -> {
					analyzing++;
					if (s.total() > 0) {
						sum += Math.min(1.0, (double) s.completed() / s.total());
					}
					if (s.name() != null && !s.name().isBlank()) {
						analyzingLabels.add(analyzingLabel(s, nowMs));
					}
				}
			}
		}
		double fraction = Math.max(0.0, Math.min(1.0, sum / n));
		return new PrewarmProgress(n, ready, analyzing, queued, failed, fraction, List.copyOf(analyzingLabels));
	}

	/** Size and elapsed time are dropped when unknown rather than shown as a placeholder. */
	private static String analyzingLabel(LibState s, long nowMs) {
		String size = HumanFormat.formatSize(s.sizeBytes());
		String elapsed = s.startedAtMs() > 0 ? HumanFormat.formatDuration(nowMs - s.startedAtMs()) : "";
		if (size.isEmpty() && elapsed.isEmpty()) {
			return s.name();
		}
		String detail = size.isEmpty() ? elapsed : elapsed.isEmpty() ? size : size + ", " + elapsed;
		return s.name() + " (" + detail + ")";
	}

	/** True once every library has reached a terminal state. */
	public boolean isComplete() {
		return total > 0 && ready + failed == total;
	}

	/** Percentage for a determinate progress bar. */
	public int percent() {
		return (int) Math.round(fraction * 100.0);
	}

	/**
	 * Whether there is anything real to show. False means nothing has finished and nothing reports
	 * counts yet, so the bar should be indeterminate rather than pinned at zero.
	 */
	public boolean isMeasurable() {
		return fraction > 0.0;
	}

	public String summaryLine() {
		StringBuilder sb = new StringBuilder();
		sb.append(analyzing).append(" analyzing · ").append(ready).append(" done");
		if (queued > 0) {
			sb.append(" · ").append(queued).append(" queued");
		}
		if (failed > 0) {
			sb.append(" · ").append(failed).append(" failed");
		}
		return sb.toString();
	}

	/**
	 * The label of every analyzing library, joined by a middle dot. Empty when
	 * nothing is currently analyzing (all queued, or all finished) -- callers must not render a
	 * dangling names line in that case. Capped to the first {@value #MAX_ANALYZING_NAMES} libraries
	 * with a "+N more" suffix once the pool exceeds that, so an unexpectedly large pool can't grow
	 * this line without bound.
	 */
	public String analyzingLine() {
		if (analyzingLabels.isEmpty()) {
			return "";
		}
		if (analyzingLabels.size() <= MAX_ANALYZING_NAMES) {
			return String.join(" · ", analyzingLabels);
		}
		String shown = String.join(" · ", analyzingLabels.subList(0, MAX_ANALYZING_NAMES));
		return shown + " · +" + (analyzingLabels.size() - MAX_ANALYZING_NAMES) + " more";
	}
}
