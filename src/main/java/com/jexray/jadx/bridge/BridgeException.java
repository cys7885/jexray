package com.jexray.jadx.bridge;

/**
 * Categorized failure from a Ghidra bridge request so the UI can show a meaningful
 * message (function-not-found vs. bridge-unreachable vs. other HTTP error).
 */
public class BridgeException extends Exception {

	public enum Kind {
		/** Bridge responded 404: the requested function/symbol was not found. */
		NOT_FOUND,
		/**
		 * Bridge responded 410: the name resolves only to a PLT stub, i.e. it is imported from
		 * another library (libc, liblog, ...) and has no body in this {@code .so} to show.
		 */
		EXTERNAL_SYMBOL,
		/** Could not reach the bridge (connection refused, timeout, unknown host, ...). */
		CONNECTION_FAILED,
		/** Bridge responded 409: the library is still being analyzed/cached. */
		STILL_LOADING,
		/** Bridge responded with a non-2xx status other than 404. */
		HTTP_ERROR,
		/** Bridge responded 2xx but the body could not be parsed. */
		BAD_RESPONSE
	}

	private final Kind kind;

	public BridgeException(Kind kind, String message) {
		super(message);
		this.kind = kind;
	}

	public BridgeException(Kind kind, String message, Throwable cause) {
		super(message, cause);
		this.kind = kind;
	}

	public Kind getKind() {
		return kind;
	}
}
