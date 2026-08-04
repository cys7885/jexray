package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.BiConsumer;

import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;

/**
 * Lists the callers of one function ("who calls this?") and lets the user jump to any of them.
 *
 * <p>Shows three distinct states, not two: a genuinely empty caller list must read differently
 * from a cache that predates xref collection -- see {@link XrefsView}'s javadoc for why
 * conflating "no callers" with "unknown" would be a false statement about the binary.
 */
public class XrefsDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	public XrefsDialog(Window parent, XrefsView view, BiConsumer<String, String> onNavigate) {
		super(parent, "Jexray - Xrefs: " + view.symbol());
		DialogUtils.installEscToClose(this);

		JPanel content = new JPanel(new BorderLayout(8, 8));
		content.setBorder(new EmptyBorder(10, 10, 10, 10));

		// A JTextArea, not an HTML JLabel: the "unknown format" message is long enough to need
		// wrapping, and a fixed-size HTML JLabel combined with pack() reliably clips wrapped text
		// instead of growing the dialog to fit it (caught by an actual offscreen render, not
		// reasoning about the layout). A plain wrapping JTextArea sized by setColumns reports a
		// correct multi-line preferred size, so pack() grows the dialog instead of clipping it.
		JTextArea header = new JTextArea(headerText(view));
		header.setEditable(false);
		header.setFocusable(false);
		header.setOpaque(false);
		header.setLineWrap(true);
		header.setWrapStyleWord(true);
		header.setFont(UIManager.getFont("Label.font"));
		header.setBorder(new EmptyBorder(0, 0, 6, 0));
		header.setColumns(46);
		content.add(header, BorderLayout.NORTH);

		DefaultListModel<XrefEntry> model = new DefaultListModel<>();
		for (XrefEntry c : view.callers()) {
			model.addElement(c);
		}
		JList<XrefEntry> list = new JList<>(model);
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setCellRenderer(new XrefCellRenderer());
		if (!model.isEmpty()) {
			list.setSelectedIndex(0);
		}
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateSelected(list, view, onNavigate);
				}
			}
		});
		// Sized on the scroll pane, not the dialog (see the header comment above): the dialog's
		// own size is left to pack(), so it always grows to fit whatever the header needs.
		JScrollPane listScroll = new JScrollPane(list);
		listScroll.setPreferredSize(new Dimension(420, 260));
		content.add(listScroll, BorderLayout.CENTER);

		JPanel buttons = new JPanel();
		JButton go = new JButton("Go to Caller");
		go.setEnabled(!model.isEmpty());
		go.addActionListener(e -> navigateSelected(list, view, onNavigate));
		JButton close = new JButton("Close");
		close.addActionListener(e -> dispose());
		buttons.add(go);
		buttons.add(close);
		content.add(buttons, BorderLayout.SOUTH);

		setContentPane(content);
		pack();
		if (parent != null) {
			setLocationRelativeTo(parent);
		}
	}

	private void navigateSelected(JList<XrefEntry> list, XrefsView view, BiConsumer<String, String> onNavigate) {
		XrefEntry sel = list.getSelectedValue();
		if (sel != null && onNavigate != null) {
			// same library the displayed function came from -- xrefs never cross a .so, same
			// rule as following a call from the pseudocode (see NativeViewDialog.onOpenSymbol)
			onNavigate.accept(view.soId(), sel.name());
			dispose();
		}
	}

	private static String headerText(XrefsView view) {
		if (!view.xrefsKnown()) {
			return "Callers of " + view.symbol() + ": unknown. This library was analyzed before"
					+ " cross-reference collection existed. Re-analyze it (All Functions > right-click"
					+ " the library > Re-analyze) to collect its call graph.";
		}
		if (view.callers().isEmpty()) {
			return "No callers found for " + view.symbol() + ".";
		}
		int n = view.callers().size();
		return n + " caller" + (n == 1 ? "" : "s") + " of " + view.symbol() + ":";
	}

	/** Renders each caller as "name   @ address". */
	private static final class XrefCellRenderer extends DefaultListCellRenderer {
		private static final long serialVersionUID = 1L;

		@Override
		public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index,
				boolean isSelected, boolean cellHasFocus) {
			JComponent c = (JComponent) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
			if (value instanceof XrefEntry e) {
				setText(e.name() + "   @ " + e.address());
			}
			c.setBorder(new EmptyBorder(3, 6, 3, 6));
			return c;
		}
	}
}
