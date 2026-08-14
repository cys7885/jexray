package com.jexray.jadx.ui;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Properties;

/**
 * Small persisted UI preferences for the Native View: the shared code-area font size (Ctrl/⌘+wheel
 * zoom on {@link NativeViewDialog}'s pseudocode/disassembly areas), and how the sidebar was left --
 * showing or not, how wide, and which of its two lists was in front. Stored as a
 * flat properties file under the plugin's persistent home ({@code ~/.jexray}, see
 * {@code JexrayPlugin#startEmbeddedBridge}) rather than the OS temp cache dir, so it survives a
 * cache clear. Deliberately independent of Swing so it's unit-testable without a display.
 */
public final class UiPrefs {

	/** Sane bounds for the code-area font size -- generous enough for both a dense scan and a
	 * screen-share zoom, without letting a runaway scroll wedge the UI unusably tiny/huge. */
	public static final int MIN_FONT_SIZE = 6;
	public static final int MAX_FONT_SIZE = 48;

	/** Size used when nothing is persisted yet, or the persisted value can't be trusted -- matches
	 * the font size {@link NativeViewDialog} hard-coded before this preference existed. */
	public static final int DEFAULT_FONT_SIZE = 12;

	/** Bounds for the sidebar width, wide enough for a mangled JNI name and narrow enough to leave
	 * the code area usable; a persisted value outside these is treated as corrupt. */
	public static final int MIN_SIDEBAR_WIDTH = 180;
	public static final int MAX_SIDEBAR_WIDTH = 900;
	public static final int DEFAULT_SIDEBAR_WIDTH = 320;

	/** Which sidebar tab was last in front. */
	public static final int TAB_ALL_FUNCTIONS = 0;
	public static final int TAB_LOADED_LIBRARIES = 1;

	private static final String FONT_SIZE_KEY = "pseudocode.font.size";
	private static final String SIDEBAR_VISIBLE_KEY = "sidebar.visible";
	private static final String SIDEBAR_WIDTH_KEY = "sidebar.width";
	private static final String SIDEBAR_TAB_KEY = "sidebar.tab";
	private static final String FILE_NAME = "ui.properties";

	private final File file;
	/** Read once and kept: the getters are called several times while a window is built. */
	private Properties cached;

	public UiPrefs() {
		this(new File(System.getProperty("user.home"), ".jexray"));
	}

	UiPrefs(File homeDir) {
		this.file = new File(homeDir, FILE_NAME);
	}

	/**
	 * Load the persisted font size, degrading to {@link #DEFAULT_FONT_SIZE} for anything short of a
	 * valid in-range value -- missing file, unreadable file, corrupt/non-numeric value, or a value
	 * outside {@code [MIN_FONT_SIZE, MAX_FONT_SIZE]}. Mirrors {@code PluginVersion.load()}: never
	 * throws, so a bad preference degrades gracefully instead of breaking dialog construction.
	 */
	public int loadFontSize() {
		return readInt(FONT_SIZE_KEY, DEFAULT_FONT_SIZE, MIN_FONT_SIZE, MAX_FONT_SIZE);
	}

	/** Persist {@code size} (clamped). Best-effort: an unwritable home dir must not surface as an
	 * error to the user -- the in-memory size still applies for the rest of this session. */
	public void saveFontSize(int size) {
		write(FONT_SIZE_KEY, Integer.toString(clamp(size)));
	}

	/** Whether the sidebar was left showing; shown by default, since finding a function is what the
	 * window is for and a hidden list cannot be discovered. */
	public boolean loadSidebarVisible() {
		return readBoolean(SIDEBAR_VISIBLE_KEY, true);
	}

	public void saveSidebarVisible(boolean visible) {
		write(SIDEBAR_VISIBLE_KEY, Boolean.toString(visible));
	}

	public int loadSidebarWidth() {
		return readInt(SIDEBAR_WIDTH_KEY, DEFAULT_SIDEBAR_WIDTH, MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH);
	}

	public void saveSidebarWidth(int width) {
		write(SIDEBAR_WIDTH_KEY, Integer.toString(
				Math.max(MIN_SIDEBAR_WIDTH, Math.min(MAX_SIDEBAR_WIDTH, width))));
	}

	public int loadSidebarTab() {
		return readInt(SIDEBAR_TAB_KEY, TAB_ALL_FUNCTIONS, TAB_ALL_FUNCTIONS, TAB_LOADED_LIBRARIES);
	}

	public void saveSidebarTab(int index) {
		if (index == TAB_ALL_FUNCTIONS || index == TAB_LOADED_LIBRARIES) {
			write(SIDEBAR_TAB_KEY, Integer.toString(index));
		}
	}

	// ------------------------------------------------------------------ storage

	/**
	 * Every write is a read-modify-write of the whole file.
	 *
	 * <p>These preferences are written from unrelated gestures -- a zoom, a drag of the splitter, a
	 * tab switch -- and share one file. Writing only the key that changed would mean each gesture
	 * storing a file containing just its own key, and the last one to fire would silently erase the
	 * rest.
	 */
	private void write(String key, String value) {
		// Re-read rather than trusting the cache: another jadx window may share this file, and its
		// keys should survive this one's write for the same reason the other gestures' keys do.
		Properties p = loadFromDisk();
		p.setProperty(key, value);
		File parent = file.getParentFile();
		if (parent != null) {
			parent.mkdirs();
		}
		// Write beside the target and move it into place. Storing over the file truncates it first,
		// and a crash inside that window used to cost one font size; now it would take the whole
		// sidebar layout with it.
		File tmp = new File(file.getParentFile(), file.getName() + ".tmp");
		try {
			try (FileOutputStream out = new FileOutputStream(tmp)) {
				p.store(out, "Jexray UI preferences");
			}
			try {
				Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING,
						StandardCopyOption.ATOMIC_MOVE);
			} catch (AtomicMoveNotSupportedException e) {
				Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
			}
			cached = p;
		} catch (IOException ignored) {
			// best-effort persistence, see above
			tmp.delete();
		}
	}

	/** The stored preferences, read from disk once. */
	private Properties read() {
		if (cached == null) {
			cached = loadFromDisk();
		}
		return cached;
	}

	private Properties loadFromDisk() {
		Properties p = new Properties();
		try (FileInputStream in = new FileInputStream(file)) {
			p.load(in);
		} catch (Exception ignored) {
			// missing/unreadable -- an empty set of preferences, every getter falls back
		}
		return p;
	}

	/** A stored int, or {@code fallback} for anything short of a valid in-range value. */
	private int readInt(String key, int fallback, int min, int max) {
		try {
			String raw = read().getProperty(key);
			if (raw != null) {
				int value = Integer.parseInt(raw.trim());
				if (value >= min && value <= max) {
					return value;
				}
			}
		} catch (Exception ignored) {
			// corrupt/non-numeric -- fall back rather than fail construction
		}
		return fallback;
	}

	private boolean readBoolean(String key, boolean fallback) {
		String raw = read().getProperty(key);
		if (raw == null) {
			return fallback;
		}
		String v = raw.trim();
		return "true".equalsIgnoreCase(v) ? true : "false".equalsIgnoreCase(v) ? false : fallback;
	}

	/** Clamp {@code size} to {@code [MIN_FONT_SIZE, MAX_FONT_SIZE]}. */
	public static int clamp(int size) {
		return Math.max(MIN_FONT_SIZE, Math.min(MAX_FONT_SIZE, size));
	}

	/** One step larger, clamped -- wheel-up on the zoom gesture. */
	public static int increment(int size) {
		return clamp(size + 1);
	}

	/** One step smaller, clamped -- wheel-down on the zoom gesture. */
	public static int decrement(int size) {
		return clamp(size - 1);
	}
}
