package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import com.jexray.jadx.bridge.BridgeModels.CacheStatsResult;
import com.jexray.jadx.util.HumanFormat;

/**
 * shows how much disk space the Ghidra analysis cache is using and lets the user
 * reclaim it. Lives in the Native View toolbar rather than JADX Preferences because the plugin
 * options API ({@code BasePluginOptionsBuilder}, see {@code JexrayOptions}) only supports value
 * settings (bool/str/int/enum) with no button or action control -- there is nowhere in
 * Preferences to put a "Clear" button.
 *
 * <p>Splits the total into two generations because they mean different things to the user: the
 * "active" (content-hash-keyed) cache is doing its job, while "legacy" entries are dead weight
 * left behind by the pre-hash {@code <abi>_<soName>} keying this version replaced -- see the
 * migration note on {@code com.jexray.jadx.ghidra.CacheCatalog} for why those are never adopted
 * automatically. Legacy space is therefore always safe to reclaim; active space trades disk for
 * not having to re-analyze.
 */
public class CacheDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	public CacheDialog(JFrame parent, CacheStatsResult stats, Consumer<Boolean> onClear) {
		super(parent, "Jexray - Analysis Cache", true);
		DialogUtils.installEscToClose(this);

		JPanel content = new JPanel(new BorderLayout(8, 8));
		content.setBorder(new EmptyBorder(12, 12, 12, 12));

		JPanel info = new JPanel(new GridLayout(0, 1, 2, 4));
		info.add(new JLabel("Active cache (currently reusable): "
				+ librarySuffix(stats.activeCount) + ", " + HumanFormat.formatSize(stats.activeBytes)));
		info.add(new JLabel("Legacy cache (pre-content-hash, unused): "
				+ librarySuffix(stats.legacyCount) + ", " + HumanFormat.formatSize(stats.legacyBytes)));
		info.add(new JLabel(" "));
		info.add(new JLabel("Total on disk: "
				+ HumanFormat.formatSize(stats.activeBytes + stats.legacyBytes)));
		content.add(info, BorderLayout.CENTER);

		JPanel buttons = new JPanel();
		JButton clearLegacy = new JButton("Clear Legacy Cache");
		clearLegacy.setToolTipText("Remove only the unused pre-content-hash entries; keeps every reusable analysis");
		clearLegacy.setEnabled(stats.legacyCount > 0);
		clearLegacy.addActionListener(e -> {
			if (confirm("Delete " + HumanFormat.formatSize(stats.legacyBytes)
					+ " of unused legacy cache (" + librarySuffix(stats.legacyCount) + ")?"
					+ " This cannot be undone.")) {
				onClear.accept(false);
				dispose();
			}
		});

		JButton clearAll = new JButton("Clear All Cache");
		clearAll.setToolTipText("Remove every cached analysis, including libraries currently reusable");
		clearAll.setEnabled(stats.activeCount > 0 || stats.legacyCount > 0);
		clearAll.addActionListener(e -> {
			if (confirm("Delete ALL analysis cache (" + HumanFormat.formatSize(stats.activeBytes + stats.legacyBytes)
					+ "), including libraries currently reusable? Every one of them will need to be"
					+ " re-analyzed the next time it's opened. This cannot be undone.")) {
				onClear.accept(true);
				dispose();
			}
		});

		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());

		buttons.add(clearLegacy);
		buttons.add(clearAll);
		buttons.add(close);
		content.add(buttons, BorderLayout.SOUTH);

		setContentPane(content);
		pack();
		if (parent != null) {
			setLocationRelativeTo(parent);
		}
	}

	private static String librarySuffix(int count) {
		return count + " librar" + (count == 1 ? "y" : "ies");
	}

	private boolean confirm(String message) {
		return JOptionPane.showConfirmDialog(this, message, "Confirm", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION;
	}
}
