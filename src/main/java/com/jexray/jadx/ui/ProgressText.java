package com.jexray.jadx.ui;

/**
 * Formats the load/analysis progress string shown while the bridge caches a library.
 * Pure text (no Swing) so the formatting is unit-testable.
 */
public final class ProgressText {

	private ProgressText() {
	}

	/**
	 * The function count is appended only when {@code total} is positive: a bridge that hasn't
	 * reported a total yet would otherwise render a misleading "0" denominator.
	 */
	public static String analyzing(String soName, String phase, int completed, int total) {
		String verb = phaseVerb(phase);
		String name = (soName == null || soName.isEmpty()) ? "native library" : soName;
		if (total > 0) {
			return verb + " " + name + "... (" + completed + "/" + total + " functions)";
		}
		return verb + " " + name + "...";
	}

	private static String phaseVerb(String phase) {
		if (phase == null) {
			return "Analyzing";
		}
		switch (phase) {
			case "caching":
				return "Caching";
			case "analyzing":
			default:
				return "Analyzing";
		}
	}
}
