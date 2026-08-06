package com.jexray.jadx.ui;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JLayeredPane;
import javax.swing.RootPaneContainer;
import javax.swing.Timer;
import javax.swing.UIManager;

/**
 * A macOS-style notification card that floats over the top-right of a window: rounded, tinted from
 * the current theme, fades in, holds, then fades out on its own.
 *
 * <p>Used for answers the user asked for but that aren't errors -- clicking an imported symbol, for
 * instance, where the honest reply is "that code lives in another library", not a failure dialog.
 * Deliberately not a {@code JOptionPane}: it must not steal focus or block the view behind it.
 * Clicking the card dismisses it early.
 */
final class Toast extends JComponent {

	private static final int MARGIN = 16;
	private static final int MAX_WIDTH = 340;
	private static final int PAD_X = 15;
	private static final int PAD_Y = 13;
	private static final int RADIUS = 14;
	private static final int LINE_GAP = 3;
	private static final int SHADOW = 5;

	private static final int FADE_IN_MS = 140;
	private static final int HOLD_MS = 5200;
	private static final int FADE_OUT_MS = 420;
	private static final int TICK_MS = 16;

	/** Key under which the live toast is parked on the layered pane, so a new one replaces it. */
	private static final String ACTIVE_KEY = "jexray.toast.active";

	private final String glyph;
	private final String title;
	private final List<String> bodyLines = new ArrayList<>();
	private final Palette palette = new Palette();
	private final Font titleFont;
	private final Font bodyFont;

	private final boolean copied;

	private float alpha;
	private Timer animator;
	private ComponentListener ownerResize;
	private JLayeredPane host;

	private Toast(String glyph, String title, String body) {
		this.glyph = glyph;
		this.title = title;
		this.copied = copyToClipboard(body);

		Font base = UIManager.getFont("Label.font");
		if (base == null) {
			base = new Font(Font.SANS_SERIF, Font.PLAIN, 12);
		}
		this.titleFont = base.deriveFont(Font.BOLD, base.getSize2D());
		this.bodyFont = base.deriveFont(Font.PLAIN, base.getSize2D() - 0.5f);

		setOpaque(false);
		// The card is decoration with a dismiss affordance; it must never take focus from the code
		// view, or Escape/arrow keys would stop reaching the editor while a toast is up.
		setFocusable(false);
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				dismiss();
			}
		});

		bodyLines.addAll(wrap(body, bodyFont));
	}

	/**
	 * Put the message on the system clipboard so it can be pasted into an issue or a note without
	 * selecting text that is about to fade away. Reported in the card's footer rather than done
	 * silently -- replacing the user's clipboard is not something to hide from them.
	 *
	 * @return whether the clipboard actually took it
	 */
	private static boolean copyToClipboard(String text) {
		if (text == null || text.isEmpty()) {
			return false;
		}
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(text), null);
			return true;
		} catch (Exception e) {
			// headless, or another app holding the clipboard: the toast is still worth showing
			return false;
		}
	}

	/**
	 * Show a toast over {@code owner}'s layered pane, replacing any toast already on screen.
	 * Safe to call with a null or not-yet-realised owner (does nothing).
	 */
	static void show(RootPaneContainer owner, String glyph, String title, String body) {
		if (owner == null) {
			return;
		}
		JLayeredPane layers = owner.getLayeredPane();
		if (layers == null) {
			return;
		}
		Object previous = layers.getClientProperty(ACTIVE_KEY);
		if (previous instanceof Toast) {
			((Toast) previous).remove();
		}
		Toast toast = new Toast(glyph, title, body);
		toast.host = layers;
		layers.putClientProperty(ACTIVE_KEY, toast);
		layers.add(toast, JLayeredPane.POPUP_LAYER);
		toast.place();
		toast.ownerResize = new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				toast.place();
			}
		};
		layers.addComponentListener(toast.ownerResize);
		toast.animate();
	}

	/** Anchor to the top-right corner of the host, inset by {@link #MARGIN}. */
	private void place() {
		if (host == null) {
			return;
		}
		int w = Math.min(MAX_WIDTH, Math.max(180, host.getWidth() - 2 * MARGIN));
		int h = heightFor(w);
		setBounds(host.getWidth() - w - MARGIN, MARGIN, w, h);
		host.revalidate();
		host.repaint();
	}

	private int heightFor(int width) {
		FontMetrics tm = getFontMetrics(titleFont);
		FontMetrics bm = getFontMetrics(bodyFont);
		int h = PAD_Y * 2 + tm.getHeight();
		for (int i = 0; i < bodyLines.size(); i++) {
			h += bm.getHeight() + LINE_GAP;
		}
		if (copied) {
			h += bm.getHeight() + LINE_GAP + 2;
		}
		return h + SHADOW;
	}

	private void animate() {
		long start = System.currentTimeMillis();
		animator = new Timer(TICK_MS, e -> {
			long t = System.currentTimeMillis() - start;
			if (t < FADE_IN_MS) {
				alpha = t / (float) FADE_IN_MS;
			} else if (t < FADE_IN_MS + HOLD_MS) {
				alpha = 1f;
			} else if (t < FADE_IN_MS + HOLD_MS + FADE_OUT_MS) {
				alpha = 1f - (t - FADE_IN_MS - HOLD_MS) / (float) FADE_OUT_MS;
			} else {
				remove();
				return;
			}
			repaint();
		});
		animator.start();
	}

	/** Start a quick fade-out from wherever the animation currently is. */
	private void dismiss() {
		if (animator != null) {
			animator.stop();
		}
		float from = alpha;
		long start = System.currentTimeMillis();
		animator = new Timer(TICK_MS, e -> {
			long t = System.currentTimeMillis() - start;
			alpha = from * (1f - t / 180f);
			if (alpha <= 0f) {
				remove();
				return;
			}
			repaint();
		});
		animator.start();
	}

	private void remove() {
		if (animator != null) {
			animator.stop();
			animator = null;
		}
		if (host != null) {
			if (ownerResize != null) {
				host.removeComponentListener(ownerResize);
				ownerResize = null;
			}
			if (host.getClientProperty(ACTIVE_KEY) == this) {
				host.putClientProperty(ACTIVE_KEY, null);
			}
			host.remove(this);
			host.revalidate();
			host.repaint();
			host = null;
		}
	}

	/** Greedy wrap to {@link #MAX_WIDTH} minus padding; long symbol names are broken mid-token. */
	private List<String> wrap(String text, Font font) {
		List<String> out = new ArrayList<>();
		if (text == null || text.isEmpty()) {
			return out;
		}
		FontMetrics fm = getFontMetrics(font);
		int limit = MAX_WIDTH - PAD_X * 2;
		StringBuilder line = new StringBuilder();
		for (String word : text.split(" ")) {
			String candidate = line.length() == 0 ? word : line + " " + word;
			if (fm.stringWidth(candidate) <= limit) {
				line.setLength(0);
				line.append(candidate);
				continue;
			}
			if (line.length() > 0) {
				out.add(line.toString());
				line.setLength(0);
			}
			// a single token wider than the card (mangled JNI symbols routinely are): hard-break it
			String rest = word;
			while (fm.stringWidth(rest) > limit && rest.length() > 1) {
				int cut = rest.length();
				while (cut > 1 && fm.stringWidth(rest.substring(0, cut)) > limit) {
					cut--;
				}
				out.add(rest.substring(0, cut));
				rest = rest.substring(cut);
			}
			line.append(rest);
		}
		if (line.length() > 0) {
			out.add(line.toString());
		}
		return out;
	}

	@Override
	protected void paintComponent(Graphics g) {
		Graphics2D g2 = (Graphics2D) g.create();
		try {
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
			g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
					RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
			g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER,
					Math.max(0f, Math.min(1f, alpha))));

			int w = getWidth();
			int h = getHeight() - SHADOW;

			// soft drop shadow: a few stacked round rects, each fainter and larger
			for (int i = SHADOW; i >= 1; i--) {
				g2.setColor(new Color(0, 0, 0, palette.dark ? 9 : 7));
				g2.fill(new RoundRectangle2D.Float(i * 0.5f, i, w - i, h, RADIUS + i, RADIUS + i));
			}

			Color bg = palette.cardBg;
			g2.setColor(new Color(bg.getRed(), bg.getGreen(), bg.getBlue(), palette.dark ? 242 : 250));
			g2.fill(new RoundRectangle2D.Float(0, 0, w, h, RADIUS, RADIUS));
			g2.setColor(palette.cardBorder);
			g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, w - 1, h - 1, RADIUS, RADIUS));

			// accent rail down the leading edge, clipped to the card's rounded corners
			Graphics2D rail = (Graphics2D) g2.create();
			rail.clip(new RoundRectangle2D.Float(0, 0, w, h, RADIUS, RADIUS));
			rail.setColor(palette.accent);
			rail.fillRect(0, 0, 3, h);
			rail.dispose();

			FontMetrics tm = g2.getFontMetrics(titleFont);
			FontMetrics bm = g2.getFontMetrics(bodyFont);
			int x = PAD_X;
			int y = PAD_Y + tm.getAscent();

			g2.setFont(titleFont);
			g2.setColor(palette.title);
			String head = (glyph == null || glyph.isEmpty()) ? title : glyph + "  " + title;
			g2.drawString(head, x, y);

			g2.setFont(bodyFont);
			g2.setColor(palette.subtitle);
			y += LINE_GAP;
			for (String line : bodyLines) {
				y += bm.getHeight();
				g2.drawString(line, x, y);
			}

			if (copied) {
				y += bm.getHeight() + 2;
				g2.setColor(palette.accent);
				g2.drawString("✓  Copied to clipboard", x, y);
			}
		} finally {
			g2.dispose();
		}
	}
}
