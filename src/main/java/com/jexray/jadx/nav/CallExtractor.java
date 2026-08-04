package com.jexray.jadx.nav;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds function-call identifiers inside decompiled pseudocode so they can be made
 * clickable. Purely textual (regex/scan), no parser, no UI/JADX dependency, so it is
 * unit-testable in isolation.
 *
 * <p>Heuristic: a "call" is an identifier immediately followed (ignoring whitespace) by
 * '('. C keywords and control-flow words (if/for/while/switch/sizeof/return/...) are
 * excluded so they are not treated as navigable calls.
 */
public final class CallExtractor {

	private CallExtractor() {
	}

	private static final Pattern CALL = Pattern.compile("\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\(");

	private static final Set<String> KEYWORDS = Set.of(
			"if", "for", "while", "switch", "return", "sizeof", "else", "do",
			"case", "default", "goto", "break", "continue", "typedef", "struct",
			"union", "enum", "static", "const", "void", "unsigned", "signed");

	private static boolean isIdentChar(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
	}

	/** Distinct call identifiers appearing in the text, in first-seen order. */
	public static List<String> callIdentifiers(String text) {
		Set<String> found = new LinkedHashSet<>();
		if (text != null) {
			Matcher m = CALL.matcher(text);
			while (m.find()) {
				String name = m.group(1);
				if (!KEYWORDS.contains(name)) {
					found.add(name);
				}
			}
		}
		return new ArrayList<>(found);
	}

	/**
	 * The identifier token covering the given caret offset, or null if the offset is not
	 * inside an identifier.
	 */
	public static String identifierAt(String text, int offset) {
		if (text == null || offset < 0 || offset > text.length()) {
			return null;
		}
		int len = text.length();
		int start = offset;
		int end = offset;
		// if caret sits just past the identifier end, step back one
		if (start == len || !isIdentChar(text.charAt(start))) {
			if (start > 0 && isIdentChar(text.charAt(start - 1))) {
				start--;
				end = start;
			} else {
				return null;
			}
		}
		while (start > 0 && isIdentChar(text.charAt(start - 1))) {
			start--;
		}
		while (end < len && isIdentChar(text.charAt(end))) {
			end++;
		}
		String id = text.substring(start, end);
		return id.isEmpty() ? null : id;
	}

	/**
	 * The call identifier at the given offset (identifier followed by '(' and not a
	 * keyword), or null if the offset is not on a navigable call.
	 */
	public static String callIdentifierAt(String text, int offset) {
		String id = identifierAt(text, offset);
		if (id == null || KEYWORDS.contains(id)) {
			return null;
		}
		// verify it is followed by '(' after this identifier occurrence around offset
		int end = offset;
		int len = text.length();
		// move end to the char after the identifier that contains offset
		while (end < len && isIdentChar(text.charAt(end))) {
			end++;
		}
		int p = end;
		while (p < len && Character.isWhitespace(text.charAt(p))) {
			p++;
		}
		if (p < len && text.charAt(p) == '(') {
			return id;
		}
		return null;
	}
}
