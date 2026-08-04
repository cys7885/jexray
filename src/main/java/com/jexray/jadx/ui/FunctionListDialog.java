package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;

/**
 * Non-modal browser for every native library in the input and the functions inside them.
 *
 * <p>The list, grouping, sizes and filtering all live in {@link LibraryTreePanel}, which the Native
 * View sidebar uses too, so both places behave identically and the behaviour exists once.
 */
public class FunctionListDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private final LibraryTreePanel panel;

	public FunctionListDialog(JFrame parent, List<LibraryEntry> libraries, String currentSoId,
			List<String> names, BiConsumer<String, String> onPick, Consumer<String> onSoSelected) {
		this(parent, libraries, currentSoId, names, onPick, onSoSelected, null);
	}

	public FunctionListDialog(JFrame parent, List<LibraryEntry> libraries, String currentSoId,
			List<String> names, BiConsumer<String, String> onPick, Consumer<String> onSoSelected,
			Consumer<String> onForceReanalyze) {
		this(parent, libraries, currentSoId, names, onPick, onSoSelected, onForceReanalyze, null);
	}

	public FunctionListDialog(JFrame parent, List<LibraryEntry> libraries, String currentSoId,
			List<String> names, BiConsumer<String, String> onPick, Consumer<String> onSoSelected,
			Consumer<String> onForceReanalyze, LibraryTreePanel.MatchCounter matchCounter) {
		super(parent, "Jexray - All Functions", false);
		setDefaultCloseOperation(HIDE_ON_CLOSE);
		DialogUtils.installEscToClose(this);

		panel = new LibraryTreePanel(onPick, onSoSelected, onForceReanalyze, matchCounter);
		panel.setLibraries(libraries);
		if (currentSoId != null) {
			panel.setFunctions(currentSoId, names);
		}

		JPanel content = new JPanel(new BorderLayout());
		content.add(panel, BorderLayout.CENTER);
		setContentPane(content);
		setPreferredSize(new Dimension(620, 620));
		pack();
		if (parent != null) {
			setLocationRelativeTo(parent);
		}
	}

	/** Refresh library states (size/status/progress). */
	public void setLibraries(List<LibraryEntry> libraries) {
		panel.setLibraries(libraries);
	}

	/** Supply the functions for one library. */
	public void update(String soId, List<String> names) {
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
