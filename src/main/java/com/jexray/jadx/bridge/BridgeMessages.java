package com.jexray.jadx.bridge;

/**
 * User-facing failure messages for bridge errors. Pure (no UI/JADX deps) so the
 * message-branching logic is unit-testable.
 */
public final class BridgeMessages {

	private BridgeMessages() {
	}

	/**
	 * Message shown when a bridge request fails.
	 *
	 * @param kind    failure category
	 * @param symbol  the queried symbol (used in the 404 message)
	 * @param baseUrl the bridge base URL (used in the connection message)
	 */
	public static String forFailure(BridgeException.Kind kind, String symbol, String baseUrl) {
		return forFailure(kind, symbol, baseUrl, null);
	}

	/**
	 * @param detail optional server-provided detail (e.g. an analysis error message),
	 *               appended to the generic HTTP-error message when present
	 */
	public static String forFailure(BridgeException.Kind kind, String symbol, String baseUrl, String detail) {
		switch (kind) {
			case NOT_FOUND:
				// Library mismatch is listed first because it is the most common cause for
				// Ghidra's synthetic FUN_<address> names: those are address-based and unique to
				// one .so, so looking one up in the wrong library can never succeed.
				return "Function '" + symbol + "' not found in the loaded library. "
						+ "It may belong to a different native library than the one being searched, "
						+ "or to a different ABI's copy of it. It can also happen if the function "
						+ "was inlined or stripped.";
			case CONNECTION_FAILED:
				return "Could not reach the Ghidra bridge. "
						+ "Ensure the bridge service is running at " + baseUrl + ".";
			case STILL_LOADING:
				return "The native library is still being analyzed. "
						+ "Please wait a moment and try again.";
			case BAD_RESPONSE:
				return "The Ghidra bridge returned an unreadable response.";
			case HTTP_ERROR:
			default:
				return "The Ghidra bridge reported an error while handling the request"
						+ (detail == null || detail.isEmpty() ? "." : ": " + detail);
		}
	}
}
