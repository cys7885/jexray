package com.jexray.jadx.nav;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Case-insensitive substring filtering for the "all functions" picker. Pure so the
 * filtering behaviour is unit-testable without a GUI.
 */
public final class FunctionFilter {

	private FunctionFilter() {
	}

	/**
	 * @param all   full list of function names (nulls are dropped)
	 * @param query substring to match; blank/null returns all non-null names
	 * @return matching names, order preserved
	 */
	public static List<String> filter(List<String> all, String query) {
		List<String> out = new ArrayList<>();
		if (all == null) {
			return out;
		}
		String q = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
		for (String name : all) {
			if (name == null) {
				continue;
			}
			if (q.isEmpty() || name.toLowerCase(Locale.ROOT).contains(q)) {
				out.add(name);
			}
		}
		return out;
	}
}
