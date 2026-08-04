package com.jexray.jadx.ui;

import java.awt.Color;

import javax.swing.UIManager;

/**
 * Theme-derived palette for the plugin's custom-painted chrome. Reads the host FlatLaf colours from
 * {@link UIManager} (accent, surfaces, text) so the overlay, search bar and progress chrome match
 * jadx's own look in both light and dark, instead of ad-hoc colour blends.
 *
 * <p>Constructed on demand (values are cheap to read) so a live theme switch is picked up.
 */
final class Palette {

	final boolean dark;
	final Color accent;
	final Color scrim;
	final Color cardBg;
	final Color cardBorder;
	final Color title;
	final Color subtitle;
	final Color track;

	Palette() {
		this.dark = ThemeSupport.isDarkLookAndFeel();
		this.accent = firstColor(new Color(0x4B8DEF),
				"ProgressBar.foreground", "Component.focusColor", "Component.linkColor");
		Color panel = firstColor(dark ? new Color(0x2B2D30) : new Color(0xF7F8FA), "Panel.background");
		Color fg = firstColor(dark ? new Color(0xECEEF2) : new Color(0x1B1F24), "Label.foreground");
		// lift the card a touch off the surrounding surface so it reads as elevated
		this.cardBg = shift(panel, dark ? 0.10f : -0.03f);
		this.title = fg;
		this.subtitle = alpha(fg, dark ? 165 : 150);
		this.cardBorder = alpha(fg, 40);
		this.track = alpha(fg, 38);
		this.scrim = new Color(0, 0, 0, dark ? 130 : 72);
	}

	private static Color firstColor(Color fallback, String... keys) {
		for (String k : keys) {
			Color c = UIManager.getColor(k);
			if (c != null) {
				return new Color(c.getRed(), c.getGreen(), c.getBlue());
			}
		}
		return fallback;
	}

	private static Color alpha(Color c, int a) {
		return new Color(c.getRed(), c.getGreen(), c.getBlue(), a);
	}

	/** Lighten (positive) or darken (negative) toward white/black by {@code amount} in [-1,1]. */
	private static Color shift(Color c, float amount) {
		int t = amount >= 0 ? 255 : 0;
		float m = Math.abs(amount);
		return new Color(
				Math.round(c.getRed() + (t - c.getRed()) * m),
				Math.round(c.getGreen() + (t - c.getGreen()) * m),
				Math.round(c.getBlue() + (t - c.getBlue()) * m));
	}
}
