package com.jexray.jadx;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds a prefilled GitHub "new issue" URL and opens it in the user's browser, so a bug report
 * carries version/environment context without the plugin ever holding a GitHub token (a token
 * baked into a distributed jar would be extractable by anyone). The user submits from their own
 * already-authenticated browser session.
 *
 * <p>URL building and body/environment formatting are pure and unit-testable; the actual
 * {@link Desktop#browse} call is behind {@link UrlOpener} so tests can assert the exact URI
 * without a display.
 */
public final class BugReportUtil {

	private static final String ISSUE_ENDPOINT = "https://github.com/cys7885/jexray/issues/new";

	/** Opens a URI in the user's browser; returns false if it could not (unsupported/headless). */
	@FunctionalInterface
	public interface UrlOpener {
		boolean open(URI uri);
	}

	/** Result of attempting to route the user to the prefilled issue. */
	public enum Outcome {
		OPENED_IN_BROWSER,
		COPIED_TO_CLIPBOARD,
		FAILED
	}

	/** Real opener: uses {@link Desktop} when a browser action is available. */
	public static final UrlOpener DESKTOP_OPENER = uri -> {
		try {
			if (!Desktop.isDesktopSupported()) {
				return false;
			}
			Desktop desktop = Desktop.getDesktop();
			if (!desktop.isSupported(Desktop.Action.BROWSE)) {
				return false;
			}
			desktop.browse(uri);
			return true;
		} catch (Exception e) {
			return false;
		}
	};

	private BugReportUtil() {
	}

	/** Build the prefilled GitHub issue URL for the given title and body (both URL-encoded). */
	public static String issueUrl(String title, String body) {
		return ISSUE_ENDPOINT
				+ "?title=" + enc(title == null ? "" : title)
				+ "&body=" + enc(body == null ? "" : body);
	}

	/** Markdown environment block auto-appended to every report. Reads OS/Java from system props. */
	public static String environmentMarkdown(String pluginVersion, String ghidraVersion) {
		String pv = (pluginVersion == null || pluginVersion.isEmpty()) ? "unknown" : pluginVersion;
		String gv = (ghidraVersion == null || ghidraVersion.isEmpty()) ? "not detected" : ghidraVersion;
		return "## Environment\n"
				+ "- Jexray plugin: " + pv + "\n"
				+ "- Ghidra: " + gv + "\n"
				+ "- OS: " + sys("os.name") + " " + sys("os.version") + "\n"
				+ "- Java: " + sys("java.version") + "\n";
	}

	/** Title/body for a blank, user-driven report (menu action). */
	public static String blankTitle() {
		return "[Bug] ";
	}

	public static String blankBody(String pluginVersion, String ghidraVersion) {
		return "**Description:**\n\n\n"
				+ "**Steps to reproduce:**\n1. \n\n"
				+ "**Expected vs. actual:**\n\n\n"
				+ environmentMarkdown(pluginVersion, ghidraVersion);
	}

	/** Title/body for a report seeded from a specific Native View error. */
	public static String errorTitle(String symbol) {
		return "[Bug] Error decompiling " + (symbol == null ? "" : symbol);
	}

	public static String errorBody(String symbol, String message, String library,
			String pluginVersion, String ghidraVersion) {
		return "**Description:**\nError while working with native function `" + nz(symbol) + "`.\n\n"
				+ "**Error message:**\n```\n" + nz(message) + "\n```\n\n"
				+ "**Steps to reproduce:**\n1. \n\n"
				+ "## Current view\n"
				+ "- Symbol: `" + nz(symbol) + "`\n"
				+ "- Library: " + orUnknown(library) + "\n\n"
				+ environmentMarkdown(pluginVersion, ghidraVersion);
	}

	/** Title/body for a report filed while a function is on screen (no error). */
	public static String functionTitle(String symbol) {
		return "[Bug] " + nz(symbol);
	}

	public static String functionBody(String symbol, String address, String library,
			String pluginVersion, String ghidraVersion) {
		return "**Description:**\n\n\n"
				+ "**Steps to reproduce:**\n1. \n\n"
				+ "**Expected vs. actual:**\n\n\n"
				+ "## Current view\n"
				+ "- Symbol: `" + nz(symbol) + "`\n"
				+ "- Address: " + orUnknown(address) + "\n"
				+ "- Library: " + orUnknown(library) + "\n\n"
				+ environmentMarkdown(pluginVersion, ghidraVersion);
	}

	private static String nz(String s) {
		return s == null ? "" : s;
	}

	private static String orUnknown(String s) {
		return (s == null || s.isEmpty()) ? "unknown" : s;
	}

	/**
	 * Try to open {@code url} in the browser; on failure, copy it to the clipboard so the user can
	 * paste it manually. UI-free so it stays testable -- the caller decides how to notify the user.
	 */
	public static Outcome open(String url, UrlOpener opener) {
		try {
			if (opener != null && opener.open(URI.create(url))) {
				return Outcome.OPENED_IN_BROWSER;
			}
		} catch (Exception ignore) {
			// fall through to clipboard
		}
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(url), null);
			return Outcome.COPIED_TO_CLIPBOARD;
		} catch (Exception e) {
			return Outcome.FAILED;
		}
	}

	private static String enc(String s) {
		// URLEncoder yields '+' for spaces; GitHub's query parser wants %20, so normalise.
		return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
	}

	private static String sys(String key) {
		String v = System.getProperty(key);
		return v == null ? "?" : v;
	}
}
