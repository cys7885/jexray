package com.jexray.jadx.ui;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Small persisted UI preferences for the Native View -- currently just the shared code-area font
 * size (Ctrl/⌘+wheel zoom on {@link NativeViewDialog}'s pseudocode/disassembly areas). Stored as a
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

	private static final String FONT_SIZE_KEY = "pseudocode.font.size";
	private static final String FILE_NAME = "ui.properties";

	private final File file;

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
		try (FileInputStream in = new FileInputStream(file)) {
			Properties p = new Properties();
			p.load(in);
			String raw = p.getProperty(FONT_SIZE_KEY);
			if (raw != null) {
				int size = Integer.parseInt(raw.trim());
				if (size >= MIN_FONT_SIZE && size <= MAX_FONT_SIZE) {
					return size;
				}
			}
		} catch (Exception ignored) {
			// missing/unreadable/corrupt -- fall back to the default rather than fail construction
		}
		return DEFAULT_FONT_SIZE;
	}

	/** Persist {@code size} (clamped). Best-effort: an unwritable home dir must not surface as an
	 * error to the user -- the in-memory size still applies for the rest of this session. */
	public void saveFontSize(int size) {
		int clamped = clamp(size);
		File parent = file.getParentFile();
		if (parent != null) {
			parent.mkdirs();
		}
		Properties p = new Properties();
		p.setProperty(FONT_SIZE_KEY, Integer.toString(clamped));
		try (FileOutputStream out = new FileOutputStream(file)) {
			p.store(out, "Jexray UI preferences");
		} catch (IOException ignored) {
			// best-effort persistence, see above
		}
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
