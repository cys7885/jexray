package com.jexray.jadx.ui;

/**
 * Decides whether a mouse click on the pseudocode should trigger call-navigation.
 * Pure (no Swing/AWT types) so the gesture policy is unit-testable.
 */
public final class ClickPolicy {

	private ClickPolicy() {
	}

	/**
	 * Navigate only on a LEFT-button click that is not a popup/context-menu trigger, and
	 * is either modifier-held (Ctrl or Cmd) or a double-click.
	 *
	 * <p>The left-button requirement is what filters out a plain right-click: macOS AWT can
	 * set the Control modifier bit on a right-click (button3), so a modifier check alone
	 * would misfire — the button check does not.
	 *
	 * @param leftButton   whether the primary (left) mouse button was used
	 * @param popupTrigger whether the event is a platform popup/context-menu trigger
	 * @param ctrlOrMeta   whether Control or Meta (Cmd) is held
	 * @param clickCount   the click count (2 == double-click)
	 */
	public static boolean shouldNavigate(boolean leftButton, boolean popupTrigger, boolean ctrlOrMeta, int clickCount) {
		if (popupTrigger || !leftButton) {
			return false;
		}
		return ctrlOrMeta || clickCount == 2;
	}
}
