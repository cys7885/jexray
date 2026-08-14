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

	/** A name jadx has carried for as long as it has had this icon set, used to test the probe. */
	private static final String KNOWN_PRESENT = "ui/left";

	/** Where jadx keeps the icon this set names; see {@link #probing}. */
	private static final String RESOURCE_FORMAT = "icons/%s.svg";

	private JexrayIcons() {
	}

	/**
	 * Wrap an icon source so a name jadx does not have is never asked for.
	 *
	 * <p>{@link #loadFirst} works by trying candidates in turn, which assumes asking for a name that
	 * is not there is cheap. It is not: jadx logs the miss at ERROR with a stack trace before
	 * substituting its placeholder, so every probe of a name a given jadx release happens not to
	 * ship writes an exception into the user's log for an icon the plugin then quietly does without.
	 * Nothing is broken by it, which is exactly what makes it worth removing -- an ERROR that means
	 * nothing teaches the reader to skim past ones that do.
	 *
	 * <p>Looking the resource up first turns the miss into a lookup that costs nothing and says
	 * nothing. {@code loader} must be the one that loaded jadx's GUI, since that is where the icons
	 * live; the plugin's own loader would find none of them.
	 *
	 * <p>Fails open. If the probe cannot find even {@link #KNOWN_PRESENT} the assumption behind it is
	 * wrong for this jadx -- a different resource root, a loader that hides them -- and every name
	 * would be skipped, costing every icon the plugin has. In that case the probe disables itself and
	 * calls through exactly as before, noise and all, because a noisy toolbar with icons beats a
	 * silent one without.
	 */
	public static IconSource probing(IconSource raw, ClassLoader loader) {
		if (raw == null) {
			return null;
		}
		if (loader == null || !hasResource(loader, KNOWN_PRESENT)) {
			LOG.debug("Jexray: cannot see jadx's icon resources; requesting names without checking first");
			return raw;
		}
		return name -> name != null && !hasResource(loader, name) ? null : raw.get(name);
	}

	private static boolean hasResource(ClassLoader loader, String name) {
		try {
			return loader.getResource(String.format(RESOURCE_FORMAT, name)) != null;
		} catch (RuntimeException e) {
			return false;
		}
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

	/**
	 * First resolvable icon among {@code names}, or {@code null} if none resolve.
	 *
	 * <p>Callers put the icon they would rather have first and something jadx is known to ship last.
	 * Some of those first choices name nothing jadx has ever shipped -- they were guessed, and were
	 * left in place only because the fallback behind each one is a real icon and {@link #probing}
	 * now makes a miss cost nothing. Do not read a leading name as evidence the resource exists; the
	 * set jadx carries has grown from 29 to 41 across the releases this plugin supports, and names
	 * can leave it as well as join it.
	 */
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
