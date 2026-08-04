package com.jexray.jadx.ui;

import javax.swing.ImageIcon;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads jadx-gui's own SVG icons for the plugin's toolbar, degrading gracefully to text-only
 * buttons when an icon can't be resolved.
 *
 * <p>jadx's low-level SVG loader ({@code UiUtils.openSvgIcon}, confirmed by decompiling
 * jadx-1.5.5-all.jar) does throw {@code JadxRuntimeException} for a name it can't resolve. But the
 * plugin-facing entry point that reaches us, {@code JadxGuiContext.getSVGIcon(String)} (implemented
 * by {@code GuiPluginContext}), wraps that call in its own {@code try/catch (Exception)}: on
 * failure it logs and returns {@code IconsCache.getSVGIcon("ui/error")} -- jadx's own red
 * exclamation-mark icon -- instead of throwing or returning {@code null}. So from here, an
 * unresolvable name comes back as a *valid-looking* {@link ImageIcon}, not an exception, and the
 * red icon is what a naive caller would display. Every lookup here still wraps the call (a genuine
 * throw remains possible, e.g. a jadx version that behaves as originally assumed), but additionally
 * recognizes jadx's error-icon placeholder by identity (see {@link #isErrorPlaceholder}) and treats
 * it the same as "no icon", so the existing text fallback applies either way. That resource set is
 * internal/undocumented, so every lookup here is wrapped and any failure is treated as "no icon" so
 * it can never break dialog construction.
 */
public final class JexrayIcons {

	private static final Logger LOG = LoggerFactory.getLogger(JexrayIcons.class);

	/** jadx's own name for the icon it silently substitutes when a name can't be resolved. */
	private static final String PLACEHOLDER_NAME = "ui/error";

	/** Supplies an icon by jadx resource name (e.g. {@code ui/left}); may throw when unresolved. */
	@FunctionalInterface
	public interface IconSource {
		ImageIcon get(String name);
	}

	private JexrayIcons() {
	}

	/**
	 * Resolve an icon by name, returning {@code null} (never throwing) when the source is absent,
	 * the name is null, jadx throws resolving it, or jadx silently substitutes its "ui/error"
	 * placeholder for it (see the class javadoc). A direct request for {@code "ui/error"} itself is
	 * left alone -- that is a legitimate icon, not a failure signal.
	 */
	public static ImageIcon load(IconSource source, String name) {
		if (source == null || name == null) {
			return null;
		}
		try {
			ImageIcon icon = source.get(name);
			if (icon != null && !PLACEHOLDER_NAME.equals(name) && isErrorPlaceholder(icon, source)) {
				LOG.warn("Jexray: jadx icon '{}' unavailable (jadx substituted its error icon); using text fallback",
						name);
				return null;
			}
			return icon;
		} catch (RuntimeException e) {
			LOG.warn("Jexray: jadx icon '{}' unavailable; using text fallback", name, e);
			return null;
		}
	}

	/**
	 * Whether {@code icon} is jadx's "ui/error" placeholder, detected by reference identity against
	 * a direct lookup of {@code "ui/error"} from the same source. This relies on jadx 1.5.5's
	 * {@code IconsCache} caching one {@link ImageIcon} instance per resource name for the life of
	 * the process, so two lookups of the same name -- the placeholder substitution and this direct
	 * check -- return the identical object. It is a heuristic tied to that implementation detail,
	 * not a documented contract: if a future jadx version stops caching, or genuinely has no
	 * "ui/error" icon, this comparison degrades to "assume the icon is genuine" (see the catch
	 * below) rather than misclassifying a real icon as the placeholder.
	 */
	private static boolean isErrorPlaceholder(ImageIcon icon, IconSource source) {
		try {
			return icon == source.get(PLACEHOLDER_NAME);
		} catch (RuntimeException e) {
			return false;
		}
	}

	/** First resolvable icon among {@code names}, or {@code null} if none resolve. */
	public static ImageIcon loadFirst(IconSource source, String... names) {
		if (names != null) {
			for (String n : names) {
				ImageIcon ic = load(source, n);
				if (ic != null) {
					return ic;
				}
			}
		}
		return null;
	}
}
