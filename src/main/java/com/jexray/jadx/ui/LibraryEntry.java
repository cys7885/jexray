package com.jexray.jadx.ui;

import com.jexray.jadx.util.HumanFormat;

/**
 * One native library as shown in the library tree: what it is, how big it is, and where its
 * analysis has got to. Size matters to the user because analysis time scales with it -- a large
 * library can take hours -- so it is shown up front rather than discovered by waiting.
 */
public record LibraryEntry(
		String soId,
		String displayName,
		long sizeBytes,
		Status status,
		int functionCount,
		long startedAtMs) {

	public enum Status {
		/** Analyzed and cached; functions are browsable. */
		READY,
		/** Being analyzed right now. */
		ANALYZING,
		/** Submitted, waiting for a free slot. */
		QUEUED,
		/** Analysis failed. */
		FAILED,
		/** Never analyzed -- either not started yet, or too large to analyze without asking. */
		NOT_ANALYZED
	}

	public static LibraryEntry notAnalyzed(String soId, String displayName, long sizeBytes) {
		return new LibraryEntry(soId, displayName, sizeBytes, Status.NOT_ANALYZED, 0, 0);
	}

	/** Empty when the size isn't known -- callers branch on that. */
	public String sizeLabel() {
		return HumanFormat.formatSize(sizeBytes);
	}

	/** Queued counts as elapsed too: the wait is what the user is watching. */
	public String elapsedLabel(long nowMs) {
		if (startedAtMs <= 0 || (status != Status.ANALYZING && status != Status.QUEUED)) {
			return "";
		}
		return HumanFormat.formatDuration(nowMs - startedAtMs);
	}

	/** The line shown in the tree: name, size, and current state. */
	public String label(long nowMs) {
		return label(nowMs, statusLabel());
	}

	/**
	 * As {@link #label(long)}, but for a library whose function list is being filtered: shows
	 * "shown / total functions" instead of the library's plain total. Without this the library line
	 * and its filtered child group can disagree -- the library reporting no functions while the
	 * group right below it lists several -- because a text filter narrows what the child group
	 * displays but says nothing about the library's own count. Matching the tree's existing
	 * "shown / total" convention (see the panel's bottom count label) fixes that without inventing a
	 * new format.
	 *
	 * <p>Both numbers must come from the same cached function list the caller filtered (its size is
	 * {@code totalFunctionCount}), not from {@link #functionCount} (the bridge's separately-reported
	 * total) -- pairing a filtered count from one source with a total from another can only agree by
	 * coincidence, and a mismatch would present that disagreement as fact. Only
	 * meaningful for READY libraries; callers should not use this for other statuses, which have no
	 * function list to filter.
	 */
	public String filteredLabel(long nowMs, int shownFunctionCount, int totalFunctionCount) {
		return label(nowMs, shownFunctionCount + " / " + totalFunctionCount + " functions");
	}

	private String label(long nowMs, String status) {
		StringBuilder sb = new StringBuilder(displayName == null ? soId : displayName);
		String size = sizeLabel();
		if (!size.isEmpty()) {
			sb.append("   ").append(size);
		}
		sb.append(" · ").append(status);
		String elapsed = elapsedLabel(nowMs);
		if (!elapsed.isEmpty()) {
			sb.append(' ').append(elapsed);
		}
		return sb.toString();
	}

	private String statusLabel() {
		return switch (status) {
			// functionCount is negative only when a READY library's true count genuinely hasn't
			// reached this entry yet (the caller failed to look it up) -- showing "0 functions" in
			// that case would be an invented number, not the truth, so say "ready" instead.
			case READY -> functionCount < 0 ? "ready" : functionCount + " functions";
			case ANALYZING -> "analyzing";
			case QUEUED -> "queued";
			case FAILED -> "failed";
			case NOT_ANALYZED -> "not analyzed — click to analyze";
		};
	}
}
