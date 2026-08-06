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
import javax.swing.KeyStroke;
import javax.swing.text.JTextComponent;

final class DialogUtils {

	static final String ESC_ACTION_KEY = "jexray-close-on-escape";

	private DialogUtils() {
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
