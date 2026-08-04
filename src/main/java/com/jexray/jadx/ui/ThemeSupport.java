package com.jexray.jadx.ui;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;

import javax.swing.UIManager;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Theme detection and RSyntaxTextArea theming that adapts to the host Swing look-and-feel.
 *
 * <p>jadx-gui switches its L&amp;F between light and dark (FlatLaf). Rather than depend on any jadx
 * internal, the current L&amp;F's darkness is inferred from a standard {@link UIManager} colour via
 * perceived luminance, and the matching bundled RSTA theme ({@code dark.xml} / {@code default.xml})
 * is applied. Theme loading is best-effort: a missing/unparseable resource leaves the default look.
 */
final class ThemeSupport {

	private static final Logger LOG = LoggerFactory.getLogger(ThemeSupport.class);

	private ThemeSupport() {
	}

	/** Perceived-luminance test (ITU-R BT.601): true when {@code c} is dark. Null -&gt; false. */
	static boolean isDark(Color c) {
		if (c == null) {
			return false;
		}
		double luminance = 0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue();
		return luminance < 128.0;
	}

	/** Whether the current Swing L&amp;F is dark, judged from its panel background colour. */
	static boolean isDarkLookAndFeel() {
		Color bg = UIManager.getColor("Panel.background");
		if (bg == null) {
			bg = UIManager.getColor("control");
		}
		return isDark(bg);
	}

	/**
	 * Apply the bundled RSTA theme matching the L&amp;F (dark vs. default). Best-effort: if the
	 * resource is missing or fails to parse, the area simply keeps its default (unstyled) look.
	 */
	static void applySyntaxTheme(RSyntaxTextArea area, boolean dark) {
		String resource = dark ? "themes/dark.xml" : "themes/default.xml";
		// Resolve relative to Theme's own package so the shade relocation
		// (org.fife -> com.jexray.shaded.fife) moves the class and this resource together.
		try (InputStream in = Theme.class.getResourceAsStream(resource)) {
			if (in == null) {
				LOG.warn("Jexray: RSTA theme resource '{}' not found; using default styling", resource);
				return;
			}
			Theme theme = Theme.load(in);
			theme.apply(area);
		} catch (IOException | RuntimeException e) {
			LOG.warn("Jexray: failed to apply RSTA theme '{}'; using default styling", resource, e);
		}
	}
}
