package com.jexray.jadx.util;

/**
 * Human-readable byte-size and duration formatting. Pulled out from {@code LibraryEntry} so the
 * pre-warm overlay (which names the libraries currently analyzing, alongside their size and how
 * long they've been running) renders the exact same units and rounding as the library tree,
 * rather than growing a second formatter that could drift from it.
 */
public final class HumanFormat {

	private HumanFormat() {
	}

	/** Empty for any non-positive size. Zero is how an unknown APK entry size arrives, so a genuine
	 * zero and an unknown one both render as empty; a caller that must distinguish them has to
	 * branch before calling. */
	public static String formatSize(long bytes) {
		if (bytes <= 0) {
			return "";
		}
		if (bytes < 1024) {
			return bytes + " B";
		}
		double kb = bytes / 1024.0;
		if (kb < 1024) {
			return Math.round(kb) + " KB";
		}
		double mb = kb / 1024.0;
		if (mb < 10) {
			return String.format("%.1f MB", mb);
		}
		return Math.round(mb) + " MB";
	}

	/** Coarser units truncate rather than round; negatives clamp to zero. */
	public static String formatDuration(long millis) {
		long secs = Math.max(0, millis / 1000);
		if (secs < 60) {
			return secs + "s";
		}
		long mins = secs / 60;
		if (mins < 60) {
			return mins + "m";
		}
		return (mins / 60) + "h" + (mins % 60) + "m";
	}
}
