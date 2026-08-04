package com.jexray.jadx.ui;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.KeyStroke;

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
}
