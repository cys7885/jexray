package com.jexray.jadx.ui;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.function.Supplier;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.border.EmptyBorder;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rtextarea.SearchContext;
import org.fife.ui.rtextarea.SearchEngine;
import org.fife.ui.rtextarea.SearchResult;

/**
 * Find bar for the Native View code tabs, built on RSyntaxTextArea's own {@link SearchEngine} /
 * {@link SearchContext} (wrap-around, highlight-all and next/previous come from the library rather
 * than being reimplemented here). Modelled on jadx-gui's own search bar, including the FlatLaf
 * {@code JComponent.outline=error} treatment when nothing matches.
 *
 * <p>Operates on whichever code tab is active, supplied lazily so tab switches are picked up.
 */
final class CodeSearchBar extends JToolBar {

	private static final long serialVersionUID = 1L;

	private final Supplier<RSyntaxTextArea> activeArea;
	private final JTextField field = new JTextField(24);
	private final JLabel counter = new JLabel("0/0");

	CodeSearchBar(Supplier<RSyntaxTextArea> activeArea, JexrayIcons.IconSource iconSource) {
		this.activeArea = activeArea;
		setFloatable(false);
		setVisible(false);

		JLabel findLabel = new JLabel("Find:");
		findLabel.setBorder(new EmptyBorder(0, 4, 0, 6));
		add(findLabel);

		// plain FlatLaf client-property keys (no compile dependency on FlatLaf itself)
		field.putClientProperty("JTextField.showClearButton", true);
		field.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				switch (e.getKeyCode()) {
					case KeyEvent.VK_ENTER -> {
						search(e.isShiftDown() ? -1 : 1); // Shift+Enter = previous
						e.consume();
					}
					case KeyEvent.VK_ESCAPE -> {
						hideBar();
						e.consume();
					}
					default -> {
					}
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				int code = e.getKeyCode();
				if (code != KeyEvent.VK_ENTER && code != KeyEvent.VK_ESCAPE) {
					search(0); // incremental search as the user types
				}
			}
		});
		add(field);

		counter.setBorder(new EmptyBorder(0, 10, 0, 10));
		counter.setForeground(new Palette().subtitle);
		add(counter);

		// jadx-1.5.5-all.jar ships no "ui/up" or "ui/down" SVGs (confirmed by listing the jar's
		// icons/ui/ entries), so there is no matching icon to request here; the plain glyphs read
		// clearly on their own and match jadx-gui's own find-bar look.
		JButton prev = new JButton("▲");
		prev.setToolTipText("Previous match (Shift+Enter)");
		prev.addActionListener(e -> search(-1));
		add(prev);

		JButton next = new JButton("▼");
		next.setToolTipText("Next match (Enter)");
		next.addActionListener(e -> search(1));
		add(next);

		JButton close = new JButton("✕");
		close.setToolTipText("Close (Esc)");
		close.addActionListener(e -> hideBar());
		applyIcon(close, JexrayIcons.load(iconSource, "ui/close"), "Close");
		add(close);
	}

	private static void applyIcon(JButton button, javax.swing.ImageIcon icon, String fallbackTip) {
		if (icon != null) {
			button.setIcon(icon);
			button.setText("");
		}
	}

	/** Reveal the bar, seed it from the current selection, and focus it. */
	void showAndFocus() {
		setVisible(true);
		RSyntaxTextArea area = activeArea.get();
		if (area != null) {
			String selected = area.getSelectedText();
			if (selected != null && !selected.isEmpty() && !selected.contains("\n")) {
				field.setText(selected);
			}
		}
		field.selectAll();
		field.requestFocusInWindow();
		revalidate();
		repaint();
		if (!field.getText().isEmpty()) {
			search(0);
		}
	}

	/** Hide the bar, clear highlights, and hand focus back to the code. */
	void hideBar() {
		setVisible(false);
		RSyntaxTextArea area = activeArea.get();
		if (area != null) {
			SearchContext clear = new SearchContext();
			clear.setSearchFor("");
			clear.setMarkAll(false);
			SearchEngine.markAll(area, clear);
			area.requestFocusInWindow();
		}
		revalidate();
		repaint();
	}

	void toggle() {
		if (isVisible()) {
			hideBar();
		} else {
			showAndFocus();
		}
	}

	/**
	 * Run a search. {@code direction} is 1 for next, -1 for previous, 0 for an in-place
	 * (incremental) search that does not jump past the current match.
	 */
	void search(int direction) {
		RSyntaxTextArea area = activeArea.get();
		String needle = field.getText();
		if (area == null || needle == null || needle.isEmpty()) {
			setNotFound(false);
			counter.setText("0/0");
			return;
		}

		SearchContext context = new SearchContext();
		context.setSearchFor(needle);
		context.setMatchCase(false);
		context.setRegularExpression(false);
		context.setWholeWord(false);
		context.setSearchWrap(true);
		context.setSearchForward(direction >= 0);
		context.setMarkAll(true); // highlight every match

		// for incremental search, start from the current match rather than after it so typing
		// doesn't skip ahead one occurrence per keystroke
		if (direction == 0) {
			int start = area.getSelectionStart();
			area.setCaretPosition(Math.max(0, start));
		}

		SearchResult result = SearchEngine.find(area, context);
		boolean found = result.wasFound();
		setNotFound(!found);

		SearchCounter.Position pos = SearchCounter.locate(
				area.getText(), needle, context.getMatchCase(), area.getSelectionStart());
		counter.setText(found ? pos.display() : "0/0");
	}

	private void setNotFound(boolean notFound) {
		field.putClientProperty("JComponent.outline", notFound ? "error" : "");
		field.repaint();
	}
}
