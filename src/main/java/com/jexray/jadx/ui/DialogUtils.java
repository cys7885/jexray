package com.jexray.jadx.ui;

import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.text.JTextComponent;

final class DialogUtils {

	static final String ESC_ACTION_KEY = "jexray-close-on-escape";
	private static final String FILTER_ESC_ACTION_KEY = "jexray-clear-filter-on-escape";

	private DialogUtils() {
	}

	/**
	 * Give {@code panel} the find shortcut for its own filter, live only while focus is inside it.
	 *
	 * <p>Scoped to the focused subtree rather than the window, because the Native View binds the same
	 * key to the code search and the two now share a window. Swing resolves an ancestor binding
	 * before a window-level one, so the side the user last clicked in is the side that answers. When
	 * focus is somewhere belonging to neither -- a toolbar button, or a window just opened -- the
	 * window-level binding wins and the key does what it does in every editor.
	 */
	static void installFilterFindShortcut(JComponent panel, String actionKey, Runnable focusFilter) {
		int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
		InputMap im = panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
		im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F, menuMask), actionKey);
		im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK), actionKey);
		panel.getActionMap().put(actionKey, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent e) {
				focusFilter.run();
			}
		});
	}

	/**
	 * Give Escape to the filter while the filter has focus: clear the query, or hand the keyboard
	 * to the list once there is nothing left to clear.
	 *
	 * <p>Without this, Escape typed in a filter reaches the Native View's own binding and closes the
	 * whole window. That was the right answer when these lists were windows of their own -- Escape
	 * dismissed the list, which is what the user meant -- but they share a window with the code now,
	 * and abandoning a search should not take the code being read along with it.
	 */
	static void installFilterEscape(JTextField filterField, JComponent list) {
		KeyStroke esc = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
		filterField.getInputMap(JComponent.WHEN_FOCUSED).put(esc, FILTER_ESC_ACTION_KEY);
		filterField.getActionMap().put(FILTER_ESC_ACTION_KEY, new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent e) {
				if (filterField.getText().isEmpty()) {
					list.requestFocusInWindow();
				} else {
					filterField.setText("");
				}
			}
		});
	}

	/**
	 * Close (hide) the dialog when Escape is pressed. Bound at the root pane with
	 * {@code WHEN_IN_FOCUSED_WINDOW} so it fires even while a child field (e.g. the filter
	 * text field) has focus.
	 */
	static void installEscToClose(JDialog dialog) {
		KeyStroke esc = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
		dialog.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(esc, ESC_ACTION_KEY);
		dialog.getRootPane().getActionMap().put(ESC_ACTION_KEY, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				dialog.setVisible(false);
			}
		});
	}

	/**
	 * Bind copy/cut/paste/select-all under both the platform menu key and Control, so ⌘C and
	 * Ctrl+C both work wherever the look-and-feel only wired one of them.
	 *
	 * <p>Each keystroke maps to an {@link AbstractAction} that calls the component directly rather
	 * than to a {@link DefaultEditorKit} action <em>name</em>. The name form depends on that name
	 * resolving through the component's action-map chain at dispatch time, and on
	 * {@code RSyntaxTextArea} it does not: ⌘F, bound to a real Action object, fires while ⌘C bound
	 * by name does nothing. Calling {@code copy()} outright is also exactly what the right-click
	 * menu does, so the two paths cannot drift apart.
	 *
	 * <p>On a read-only component cut and paste are inert -- {@link JTextComponent} drops edits
	 * when it is not editable -- so binding them there costs nothing and keeps the mapping uniform.
	 */
	static void installClipboardShortcuts(JTextComponent component) {
		int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
		InputMap im = component.getInputMap(JComponent.WHEN_FOCUSED);
		ActionMap am = component.getActionMap();

		bind(im, am, "jexray-copy", KeyEvent.VK_C, menuMask, component::copy);
		bind(im, am, "jexray-paste", KeyEvent.VK_V, menuMask, component::paste);
		bind(im, am, "jexray-cut", KeyEvent.VK_X, menuMask, component::cut);
		bind(im, am, "jexray-select-all", KeyEvent.VK_A, menuMask, component::selectAll);
	}

	/** Register {@code body} under both {@code mask} and Control for {@code keyCode}. */
	private static void bind(InputMap im, ActionMap am, String key, int keyCode, int mask, Runnable body) {
		am.put(key, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				body.run();
			}
		});
		im.put(KeyStroke.getKeyStroke(keyCode, mask), key);
		im.put(KeyStroke.getKeyStroke(keyCode, InputEvent.CTRL_DOWN_MASK), key);
	}
}
