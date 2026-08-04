package com.jexray.jadx.ui;

import jadx.api.metadata.ICodeNodeRef;

/**
 * A fully-rendered native function view: the resolved content shown in the dialog plus an
 * optional back-reference to the originating Java native method (null for functions
 * reached by clicking a call inside pseudocode, which have no Java declaration).
 *
 * <p>Cached in the navigation history so back/forward do not re-hit the bridge.
 */
public record NativeFunctionView(
		String soId,
		String symbol,
		String address,
		String pseudocode,
		String disassembly,
		ICodeNodeRef javaRef) {

	/**
	 * History de-duplication key. The same function is reachable under different symbol
	 * strings depending on entry path (e.g. the JNI-mangled {@code Java_..._add} from the
	 * Java popup vs. the bridge's {@code _Java_..._add} from the function list), but all of
	 * them resolve to the same Ghidra address. Keying on the address collapses those into a
	 * single history entry; symbol is only a fallback when no address is available.
	 *
	 * <p>Scoped by library: addresses are only unique within one {@code .so}, so the same
	 * address in two libraries is two different functions and must not collapse into one entry.
	 */
	public String dedupKey() {
		String within = (address == null || address.isEmpty()) ? symbol : address;
		return (soId == null ? "" : soId) + "@" + within;
	}
}
