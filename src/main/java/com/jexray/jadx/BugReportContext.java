package com.jexray.jadx;

/**
 * Snapshot of what the Native View is showing when the user clicks a "Report Bug" control, so the
 * report can be seeded with the right context. Built by the dialog (which knows its view state),
 * consumed by the plugin (which adds version/library details and opens the issue).
 */
public record BugReportContext(Kind kind, String symbol, String address, String message) {

	public enum Kind {
		/** A function is currently displayed. */
		FUNCTION,
		/** The dialog is in its error state. */
		ERROR,
		/** Nothing is displayed yet. */
		EMPTY
	}

	public static BugReportContext empty() {
		return new BugReportContext(Kind.EMPTY, null, null, null);
	}

	public static BugReportContext function(String symbol, String address) {
		return new BugReportContext(Kind.FUNCTION, symbol, address, null);
	}

	public static BugReportContext error(String symbol, String message) {
		return new BugReportContext(Kind.ERROR, symbol, null, message);
	}
}
