package com.jexray.jadx.ui;

import java.util.List;

/**
 * Result of a "Show xrefs" request: the callers of one function, scoped to the library it was
 * shown from (xrefs never cross a {@code .so} boundary, same as following a call).
 *
 * <p>{@code xrefsKnown=false} means the analysis cache backing {@code soId} predates
 * cross-reference collection (see {@code EmbeddedGhidraBridge}'s cache format version), so
 * {@code callers} is empty because it was never computed -- NOT because this function provably
 * has none. Rendering those two states identically would be exactly the kind of unverified claim
 * this plugin has removed elsewhere; callers of this record must keep them visually distinct.
 */
public record XrefsView(String soId, String symbol, boolean xrefsKnown, List<XrefEntry> callers) {
}
