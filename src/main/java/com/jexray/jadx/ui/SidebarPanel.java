package com.jexray.jadx.ui;

import javax.swing.JComponent;

/**
 * A symbol list the Native View can put in its sidebar.
 *
 * <p>Narrow on purpose: the window needs exactly two things from a panel -- somewhere to put it, and
 * a way to hand the keyboard to its filter when it comes to the front. Everything else about the two
 * panels differs, and taking them as plain components instead lost the second of those without
 * anything failing to compile.
 */
public interface SidebarPanel {

	/** Put the caret in this panel's filter box. */
	void focusFilter();

	/** This panel as a component, for the sidebar to lay out. */
	JComponent asComponent();
}
