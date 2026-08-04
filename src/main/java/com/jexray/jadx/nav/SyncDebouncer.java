package com.jexray.jadx.nav;

/**
 * Debounces caret-sync so the bridge is queried only after the caret has rested on the
 * same (new) native method for a stable interval. Pure and time-injected so the timing
 * logic is unit-testable without real clocks or a GUI.
 *
 * <p>Not thread-safe; intended to be driven from a single (EDT) polling loop.
 */
public class SyncDebouncer {

	private final long debounceMs;
	private String pendingSymbol;
	private long pendingSince;
	// The caret's native method the last time sync acted on it (fired, or adopted because it was
	// already shown). Sync follows caret MOVEMENT: it fires only when the caret rests on a method
	// different from this. Crucially it does NOT compare against the shown symbol, so navigating
	// within the view (double-click a call, All Functions, Back) is never undone while the caret
	// stays put -- that was the "snaps back to the first function" bug.
	private String lastSynced;

	public SyncDebouncer(long debounceMs) {
		this.debounceMs = debounceMs;
	}

	/**
	 * Feed one poll sample.
	 *
	 * @param shownSymbol     symbol currently displayed (null if none)
	 * @param candidateSymbol native symbol under the caret (null if caret not on a native method)
	 * @param nowMs           current time in millis
	 * @return the symbol to fetch now, or null if nothing should be fetched yet
	 */
	public String onPoll(String shownSymbol, String candidateSymbol, long nowMs) {
		// caret isn't on a native method: cancel any pending fire, but keep lastSynced so returning
		// to the same method doesn't re-snap over a manual in-view navigation
		if (candidateSymbol == null) {
			pendingSymbol = null;
			return null;
		}
		// caret hasn't moved to a different method than we last synced: do nothing, even if the
		// shown symbol now differs because the user navigated within the view themselves
		if (candidateSymbol.equals(lastSynced)) {
			pendingSymbol = null;
			return null;
		}
		// caret is on the method already displayed (first open, or the user navigated there): adopt
		// it as synced without a redundant reopen
		if (candidateSymbol.equals(shownSymbol)) {
			pendingSymbol = null;
			lastSynced = candidateSymbol;
			return null;
		}
		// caret moved to a new method: (re)start the stability window
		if (!candidateSymbol.equals(pendingSymbol)) {
			pendingSymbol = candidateSymbol;
			pendingSince = nowMs;
			return null;
		}
		// held on the new method long enough: fire once and remember it
		if (nowMs - pendingSince >= debounceMs) {
			pendingSymbol = null;
			lastSynced = candidateSymbol;
			return candidateSymbol;
		}
		return null;
	}

	public void reset() {
		pendingSymbol = null;
		lastSynced = null;
	}
}
