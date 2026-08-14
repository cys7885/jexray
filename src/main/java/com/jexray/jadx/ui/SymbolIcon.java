package com.jexray.jadx.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.geom.Arc2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;

import javax.swing.Icon;

/**
 * The four kinds of symbol a native library's function list holds.
 *
 * <p>jadx's own icon set names Java things -- class, method, field -- and a function list names ELF
 * things: an entry point the VM binds, a symbol the library publishes, a stub for code that lives
 * elsewhere, a routine it keeps to itself. Borrowing from the Java set puts an "m" for *method* on a
 * C function, and separates three of these groups by a six-pixel dot.
 *
 * <p>The letters and arrows are Tabler Icons (MIT, see {@code NOTICE}); the library page is drawn
 * here. Both sit on their 24-unit grid at a
 * 2-unit stroke and scaled down here. Icons for a set like this are not worth inventing: what makes
 * one legible at sixteen pixels is stroke discipline and grid alignment worked out across hundreds
 * of glyphs, and a shape improvised for one list reads as improvised next to jadx's own.
 *
 * <pre>
 *   Functions     (f)   the mark for a function, and nothing else to say about it
 *   JNI methods   (J)   the same badge, tagged for the side that binds it: Java
 *   Exports       [-&gt;   the boundary, with a name offered outward through it
 *   Imports       [&lt;-   the same boundary, with a name arriving from outside
 * </pre>
 *
 * <p>The vocabulary follows the tool the reader almost certainly has open beside this one. Ghidra
 * marks a function with an "f" and an external one with that same "f" carrying a small badge, and it
 * uses braces for a namespace -- so braces here, however well they say "code", would say the wrong
 * word in the one place it matters. An ordinary function keeps the plain mark; the entry points wear
 * the same badge tagged for the side that binds them.
 *
 * <p>Exports and imports deliberately share a glyph mirrored, because they are one relationship seen
 * from two sides; the arrowhead swaps ends and the hue changes with it. The other two are singular
 * shapes so they cannot be mistaken for either. Colour does the work at a glance down a long list --
 * four hues spaced around the wheel -- and shape is what settles it up close.
 *
 * <p>Painted with Java2D rather than shipped as SVG or PNG: nothing to bundle, nothing to keep in
 * two themes and two resolutions, and no dependency on the SVG loader jadx happens to carry. The
 * palette is read per paint (see {@link Palette}), so a live theme switch is picked up with no
 * invalidation of our own.
 */
final class SymbolIcon implements Icon {

	/** What the row is, in the terms the library itself uses. */
	enum Kind {
		/** Bound to a Java {@code native} method -- exported under its mangled name, or registered. */
		JNI,
		/** Defined here and published in the dynamic symbol table. */
		EXPORT,
		/** Defined here and not published: reachable only from inside the library. */
		INTERNAL,
		/** Named here, defined in another library. */
		IMPORT,
		/** Not a symbol at all: the {@code .so} the symbols below it come from. */
		LIBRARY
	}

	/** Nominal size. Java2D scales the whole drawing on a HiDPI surface, so this stays the size in
	 * user space rather than a pixel count anyone has to supply a second copy of. */
	private static final int SIZE = 16;

	/** The grid the source glyphs are drawn on, and the stroke they are drawn with. */
	private static final float GRID = 24f;
	private static final float STROKE = 2f;
	/** How far the mark is inset inside the tile. */
	private static final float GLYPH_SCALE = 0.56f;

	// Tabler Icons, MIT licensed -- see NOTICE. Kept as the path data upstream publishes rather
	// than transcribed into Java2D calls, so a glyph can be replaced by pasting a new one and a
	// reader can diff these against the source project. That holds for the letters and arrows
	// below; the library page and its fold are drawn here and match nothing upstream, so do not
	// go looking for them there.
	private static final String[] D_JNI = {
		"M17 4v12a4 4 0 0 1 -4 4h-2a4 4 0 0 1 -4 -4",
	};
	private static final String[] D_EXPORT = {
		"M5 12l14 0", "M15 16l4 -4", "M15 8l4 4",
	};
	/**
	 * A page with its corner turned, and the extension cut out of it -- the shape an IDE gives a
	 * file, because a library row is a file and the rows under it are not. Deliberately unlike the
	 * four symbol tiles: at a glance the reader should be able to tell the container from the
	 * things it contains without reading either.
	 */
	private static final String[] D_LIBRARY = {
		"M6 2h9l5 5v13a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-16a2 2 0 0 1 2 -2z",
	};
	/** The turned corner, drawn as a line so it reads as a fold and not as a notch. */
	private static final String[] D_LIBRARY_FOLD = { "M15 2v5h5" };
	private static final String[] D_LIBRARY_S = {
		"M17 8a4 4 0 0 0 -4 -4h-2a4 4 0 0 0 0 8h2a4 4 0 0 1 0 8h-2a4 4 0 0 1 -4 -4",
	};
	private static final String[] D_LIBRARY_O = {
		"M18 9a5 5 0 0 0 -5 -5h-2a5 5 0 0 0 -5 5v6a5 5 0 0 0 5 5h2a5 5 0 0 0 5 -5v-6",
	};

	private static final String[] D_IMPORT = {
		"M5 12l14 0", "M5 12l4 4", "M5 12l4 -4",
	};
	private static final String[] D_INTERNAL = {
		"M17 4h-10v16", "M7 12l8 0",
	};

	static final SymbolIcon JNI = new SymbolIcon(Kind.JNI, D_JNI);
	static final SymbolIcon EXPORT = new SymbolIcon(Kind.EXPORT, D_EXPORT);
	static final SymbolIcon INTERNAL = new SymbolIcon(Kind.INTERNAL, D_INTERNAL);
	static final SymbolIcon IMPORT = new SymbolIcon(Kind.IMPORT, D_IMPORT);
	static final SymbolIcon LIBRARY = new SymbolIcon(Kind.LIBRARY, D_LIBRARY);

	private final Kind kind;
	/** Parsed once. The geometry never changes; only the colour it is stroked in does. */
	private final Path2D.Float path;

	private SymbolIcon(Kind kind, String[] pathData) {
		this.kind = kind;
		this.path = parse(pathData);
	}

	@Override
	public int getIconWidth() {
		return SIZE;
	}

	@Override
	public int getIconHeight() {
		return SIZE;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		Graphics2D g2 = (Graphics2D) g.create();
		try {
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
			g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
			g2.translate(x, y);
			g2.scale(SIZE / GRID, SIZE / GRID);
			Palette p = new Palette();
			if (kind == Kind.LIBRARY) {
				paintLibrary(g2, p);
				return;
			}

			// A filled tile carrying a knocked-out mark, the way an IDE draws these: the colour is
			// the area, the glyph is the hole in it. Drawn as an outline instead, at this size, the
			// two weights match and the result reads as a letter set in a ring rather than an icon.
			g2.setColor(colorFor(p));
			g2.fill(new RoundRectangle2D.Float(2f, 2f, 20f, 20f, 6f, 6f));

			g2.setColor(surface(p));
			// The glyphs are drawn on the same 24 grid as the tile, so they arrive the tile's own
			// size; shrink them about the centre to sit inside it with a margin, and thicken the
			// stroke by as much as that shrink takes away so the knockout keeps its weight.
			g2.translate(12f, 12f);
			g2.scale(GLYPH_SCALE, GLYPH_SCALE);
			g2.translate(-12f, -12f);
			g2.setStroke(new BasicStroke(STROKE / GLYPH_SCALE, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
			g2.draw(path);
		} finally {
			g2.dispose();
		}
	}

	/** Parsed once, like {@link #path}; only the library glyph needs these. */
	private static final Path2D.Float FOLD = parse(D_LIBRARY_FOLD);
	private static final Path2D.Float LETTER_S = parse(D_LIBRARY_S);
	private static final Path2D.Float LETTER_O = parse(D_LIBRARY_O);

	/**
	 * The library row: a filled page with a folded corner and "SO" cut out of it.
	 *
	 * <p>The two letters are drawn at their own scale rather than the tile glyphs' -- a page is
	 * taller than it is wide, so a pair of letters has to shrink further than a single one to sit
	 * side by side, and the stroke is thickened to match so the cut-out keeps the same weight as the
	 * marks on the four symbol tiles.
	 */
	private void paintLibrary(Graphics2D g2, Palette p) {
		g2.setColor(colorFor(p));
		g2.fill(path);

		Color surface = surface(p);
		g2.setColor(surface);
		g2.setStroke(new BasicStroke(1.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
		g2.draw(FOLD);

		float scale = 0.40f;
		float stroke = STROKE / scale;
		for (Object[] letter : new Object[][] { { LETTER_S, -3.4f }, { LETTER_O, 3.4f } }) {
			Graphics2D lg = (Graphics2D) g2.create();
			try {
				lg.translate(12f + (Float) letter[1], 15.5f);
				lg.scale(scale, scale);
				lg.translate(-12f, -12f);
				lg.setColor(surface);
				lg.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
				lg.draw((Path2D.Float) letter[0]);
			} finally {
				lg.dispose();
			}
		}
	}

	/**
	 * What the knocked-out mark is filled with: the row behind the icon, so the glyph reads as a
	 * hole in the tile rather than a second colour laid over it. Taken from the tree's own background
	 * where the look-and-feel publishes one, since that is the surface these actually sit on.
	 */
	private static Color surface(Palette p) {
		for (String key : new String[] { "Tree.background", "Panel.background" }) {
			Color c = javax.swing.UIManager.getColor(key);
			if (c != null) {
				return new Color(c.getRed(), c.getGreen(), c.getBlue());
			}
		}
		return p.dark ? new Color(0x2B2D30) : Color.WHITE;
	}

	/**
	 * The colours IntelliJ already uses for these four ideas, rather than a palette of our own.
	 *
	 * <p>Android Studio marks a JNI-bound native function by putting the *Java* file icon in the
	 * gutter beside it, and marks the Java declaration by putting the C/C++ one there -- the mark
	 * names the language on the other side. Those two icons carry this blue and this violet. The
	 * green and the red are what its gutter uses for "implemented elsewhere" and "declared
	 * elsewhere", which is what an export and an import are.
	 */
	private Color colorFor(Palette p) {
		return switch (kind) {
			case JNI -> shift(p, 0x40B6E0);      // AllIcons.FileTypes.Java
			case INTERNAL -> shift(p, 0xB99BF8); // the C / C++ file types
			case EXPORT -> shift(p, 0x62B543);   // gutter: implemented elsewhere
			case IMPORT -> shift(p, 0xDB5860);   // gutter: declared elsewhere
			case LIBRARY -> shift(p, 0xF4AF3D);  // IntelliJ's amber, the one hue its file types leave free
		};
	}

	/**
	 * One of those colours, moved to where it can carry a 1.3px stroke.
	 *
	 * <p>IntelliJ publishes them as fills -- a band behind a dark letter, at 70% opacity -- so taken
	 * literally they are too light to draw a line with on a white row, and too dark on a dark one.
	 * Shifting each toward the surrounding text keeps the hue, which is the part carrying the
	 * meaning, and buys back the contrast the original got from being a filled area.
	 */
	private static Color shift(Palette p, int rgb) {
		Color base = new Color(rgb);
		int target = p.dark ? 255 : 0;
		float amount = p.dark ? 0.06f : 0.14f;
		return new Color(
				Math.round(base.getRed() + (target - base.getRed()) * amount),
				Math.round(base.getGreen() + (target - base.getGreen()) * amount),
				Math.round(base.getBlue() + (target - base.getBlue()) * amount));
	}

	// ------------------------------------------------------------------ path data

	/**
	 * The subset of SVG path syntax the bundled glyphs use: moves, lines, horizontal and vertical
	 * lines, elliptical arcs, and close, in both absolute and relative form.
	 *
	 * <p>A parser rather than transcribed geometry so the borrowed strings above can stay
	 * byte-identical to what the icon project publishes (the library page and fold are ours, and
	 * match nothing there). Anything outside that subset is ignored rather than
	 * guessed at -- a glyph pasted in from elsewhere that uses curves would come out visibly wrong,
	 * which is a better failure than a silently distorted one.
	 */
	private static Path2D.Float parse(String[] pathData) {
		Path2D.Float out = new Path2D.Float();
		for (String d : pathData) {
			Scanner s = new Scanner(d);
			float cx = 0;
			float cy = 0;
			float startX = 0;
			float startY = 0;
			char cmd = 0;
			while (s.hasMore()) {
				if (s.peekIsCommand()) {
					cmd = s.command();
				}
				boolean rel = Character.isLowerCase(cmd);
				switch (Character.toUpperCase(cmd)) {
					case 'M' -> {
						float nx = s.number() + (rel ? cx : 0);
						float ny = s.number() + (rel ? cy : 0);
						out.moveTo(nx, ny);
						cx = startX = nx;
						cy = startY = ny;
						// a second coordinate pair after a move continues as a line, per the spec
						cmd = rel ? 'l' : 'L';
					}
					case 'L' -> {
						cx = s.number() + (rel ? cx : 0);
						cy = s.number() + (rel ? cy : 0);
						out.lineTo(cx, cy);
					}
					case 'H' -> {
						cx = s.number() + (rel ? cx : 0);
						out.lineTo(cx, cy);
					}
					case 'V' -> {
						cy = s.number() + (rel ? cy : 0);
						out.lineTo(cx, cy);
					}
					case 'A' -> {
						float rx = s.number();
						float ry = s.number();
						float rot = s.number();
						boolean large = s.number() != 0;
						boolean sweep = s.number() != 0;
						float nx = s.number() + (rel ? cx : 0);
						float ny = s.number() + (rel ? cy : 0);
						arc(out, cx, cy, rx, ry, rot, large, sweep, nx, ny);
						cx = nx;
						cy = ny;
					}
					case 'Z' -> {
						out.closePath();
						cx = startX;
						cy = startY;
					}
					default -> s.skipNumber();
				}
			}
		}
		return out;
	}

	/**
	 * Append one SVG elliptical arc, converting its endpoint parameterisation to the centre form
	 * {@link Arc2D} wants (SVG 1.1, F.6.5). Java2D then produces the curve itself, so there is no
	 * bezier-splitting to get wrong here.
	 *
	 * <p>Angles are negated on the way out because SVG measures them clockwise on a y-down canvas
	 * and {@link Arc2D} measures them counter-clockwise.
	 */
	private static void arc(Path2D.Float out, float x1, float y1, float rx, float ry,
			float rotDeg, boolean large, boolean sweep, float x2, float y2) {
		if (rx == 0 || ry == 0 || (x1 == x2 && y1 == y2)) {
			out.lineTo(x2, y2);
			return;
		}
		rx = Math.abs(rx);
		ry = Math.abs(ry);
		double phi = Math.toRadians(rotDeg);
		double cosPhi = Math.cos(phi);
		double sinPhi = Math.sin(phi);
		double dx2 = (x1 - x2) / 2.0;
		double dy2 = (y1 - y2) / 2.0;
		double x1p = cosPhi * dx2 + sinPhi * dy2;
		double y1p = -sinPhi * dx2 + cosPhi * dy2;

		// Radii too small to span the endpoints are scaled up until they exactly do, as the spec
		// requires; without this the square root below goes imaginary.
		double lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
		if (lambda > 1) {
			double k = Math.sqrt(lambda);
			rx *= (float) k;
			ry *= (float) k;
		}

		double rx2 = rx * rx;
		double ry2 = ry * ry;
		double num = rx2 * ry2 - rx2 * y1p * y1p - ry2 * x1p * x1p;
		double den = rx2 * y1p * y1p + ry2 * x1p * x1p;
		double coef = Math.sqrt(Math.max(0, num / den)) * (large == sweep ? -1 : 1);
		double cxp = coef * (rx * y1p / ry);
		double cyp = coef * -(ry * x1p / rx);
		double cx = cosPhi * cxp - sinPhi * cyp + (x1 + x2) / 2.0;
		double cy = sinPhi * cxp + cosPhi * cyp + (y1 + y2) / 2.0;

		double theta = angle(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry);
		double delta = angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
		delta = Math.toDegrees(delta) % 360.0;
		if (!sweep && delta > 0) {
			delta -= 360.0;
		} else if (sweep && delta < 0) {
			delta += 360.0;
		}

		Arc2D.Double shape = new Arc2D.Double(cx - rx, cy - ry, rx * 2.0, ry * 2.0,
				-Math.toDegrees(theta), -delta, Arc2D.OPEN);
		if (rotDeg != 0) {
			out.append(AffineTransform.getRotateInstance(phi, cx, cy).createTransformedShape(shape), true);
		} else {
			out.append(shape, true);
		}
	}

	/** Signed angle from one vector to another, in radians. */
	private static double angle(double ux, double uy, double vx, double vy) {
		double dot = ux * vx + uy * vy;
		double len = Math.hypot(ux, uy) * Math.hypot(vx, vy);
		double a = Math.acos(Math.max(-1, Math.min(1, dot / len)));
		return (ux * vy - uy * vx) < 0 ? -a : a;
	}

	/** Walks a path string: commands are letters, everything else is a number. */
	private static final class Scanner {
		private final String s;
		private int i;

		Scanner(String s) {
			this.s = s;
		}

		boolean hasMore() {
			skipSeparators();
			return i < s.length();
		}

		boolean peekIsCommand() {
			skipSeparators();
			return i < s.length() && Character.isLetter(s.charAt(i));
		}

		char command() {
			return s.charAt(i++);
		}

		void skipNumber() {
			number();
		}

		float number() {
			skipSeparators();
			int start = i;
			if (i < s.length() && (s.charAt(i) == '-' || s.charAt(i) == '+')) {
				i++;
			}
			while (i < s.length() && (Character.isDigit(s.charAt(i)) || s.charAt(i) == '.')) {
				i++;
			}
			if (start == i) {
				// not a number after all: step over it so a malformed string cannot spin here
				i++;
				return 0;
			}
			return Float.parseFloat(s.substring(start, i));
		}

		private void skipSeparators() {
			while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == ',')) {
				i++;
			}
		}
	}

}
