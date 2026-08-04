package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.InputMap;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import jadx.api.metadata.ICodeNodeRef;

import com.jexray.jadx.apk.LoadedLibrariesModel.Result;

/**
 * Non-modal window listing every native library the app asks the VM to load (opened from the
 * Native View toolbar), as a tree of resolved libraries, unreadable load-call arguments, and
 * unloaded .so's -- see {@link LoadedLibrariesPanel} for what each of those means and why none of
 * them is dropped.
 */
public class LoadedLibrariesDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	/** Same action-map key convention as {@link NativeViewDialog}'s find shortcut; distinct root
	 * pane, so no collision even though the string matches. */
	private static final String FIND_ACTION_KEY = "jexray-find";

	private final LoadedLibrariesPanel panel;

	public LoadedLibrariesDialog(JFrame parent, Consumer<ICodeNodeRef> onNavigate,
			Consumer<String> onLibraryExpanded) {
		this(parent, onNavigate, onLibraryExpanded, null);
	}

	public LoadedLibrariesDialog(JFrame parent, Consumer<ICodeNodeRef> onNavigate,
			Consumer<String> onLibraryExpanded, LoadedLibrariesPanel.FunctionReader functionReader) {
		super(parent, "Jexray - Loaded Libraries", false);
		setDefaultCloseOperation(HIDE_ON_CLOSE);
		DialogUtils.installEscToClose(this);

		panel = new LoadedLibrariesPanel(onNavigate, onLibraryExpanded, functionReader);
		installFindShortcut();

		JPanel content = new JPanel(new BorderLayout());
		content.add(panel, BorderLayout.CENTER);
		setContentPane(content);
		setPreferredSize(new Dimension(620, 620));
		pack();
		if (parent != null) {
			setLocationRelativeTo(parent);
		}
	}

	/**
	 * Ctrl+F (and ⌘+F on macOS) focuses the filter field, same accelerators as
	 * {@link NativeViewDialog}'s find shortcut. Bound {@code WHEN_IN_FOCUSED_WINDOW} on the root
	 * pane -- unlike {@link NativeViewDialog}, this window has no text component of its own that
	 * shadows Ctrl+F with a different meaning (the tree doesn't bind it), so a single window-level
	 * binding is enough to work regardless of what has focus inside the dialog.
	 */
	private void installFindShortcut() {
		int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
		KeyStroke menuF = KeyStroke.getKeyStroke(KeyEvent.VK_F, menuMask);
		KeyStroke ctrlF = KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK);

		Action findAction = new AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(ActionEvent e) {
				panel.focusFilter();
			}
		};

		InputMap im = getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
		im.put(menuF, FIND_ACTION_KEY);
		im.put(ctrlF, FIND_ACTION_KEY);
		getRootPane().getActionMap().put(FIND_ACTION_KEY, findAction);
	}

	/** Replace the tree's data (resolved libraries, unresolved calls, unloaded .so's). */
	public void setResult(Result result) {
		panel.setResult(result);
	}

	/** Show the "scanning…" placeholder while the background load-call scan runs; see
	 * {@link LoadedLibrariesPanel#setScanning}. */
	public void setScanning() {
		panel.setScanning();
	}

	/** Supply the exported function names for one library; shown when it is expanded. */
	public void setFunctions(String soId, List<String> names) {
		panel.setFunctions(soId, names);
	}

	public void surface() {
		if (!isVisible()) {
			setVisible(true);
		}
		toFront();
		panel.focusFilter();
	}
}
