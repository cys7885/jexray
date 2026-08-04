package com.jexray.jadx.ui;

import java.util.Locale;

/**
 * Works out which match the caret is on. {@code SearchEngine} reports how many
 * matches it highlighted but not which one the caret landed on, so this counts literal occurrences
 * and finds the one starting at the current selection. Pure, so it is unit-testable headlessly.
 */
final class SearchCounter {

	/** 1-based {@code index} of the current match ({@code 0} = none) out of {@code total}. */
	record Position(int index, int total) {

		String display() {
			return total == 0 ? "0/0" : (index + "/" + total);
		}
	}

	private static final Position NONE = new Position(0, 0);

	private SearchCounter() {
	}

	static Position locate(String text, String needle, boolean matchCase, int matchStart) {
		if (text == null || needle == null || needle.isEmpty()) {
			return NONE;
		}
		String haystack = matchCase ? text : text.toLowerCase(Locale.ROOT);
		String target = matchCase ? needle : needle.toLowerCase(Locale.ROOT);

		int total = 0;
		int index = 0;
		int at = haystack.indexOf(target);
		while (at >= 0) {
			total++;
			if (at == matchStart) {
				index = total;
			}
			at = haystack.indexOf(target, at + 1); // overlapping matches count, like the editor's
		}
		return new Position(index, total);
	}
}
