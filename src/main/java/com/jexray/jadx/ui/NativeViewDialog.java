package com.jexray.jadx.ui;

import java.awt.AWTEvent;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import javax.swing.AbstractButton;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayer;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.LayerUI;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import jadx.api.metadata.ICodeNodeRef;

import com.jexray.jadx.BugReportContext;
import com.jexray.jadx.bridge.PrewarmProgress;
import com.jexray.jadx.nav.CallExtractor;
import com.jexray.jadx.nav.NavigationHistory;

/**
 * Non-modal dialog showing Ghidra pseudocode (C-highlighted) and disassembly for a
 * selected native method. Stays open alongside the main JADX window.
 *
 * <p>Features:
 * <ul>
 *   <li>"Go to Java Source": jump back to the originating native method in jadx.</li>
 *   <li>Back / Forward: browser-style history across viewed functions (cached, no re-fetch).</li>
 *   <li>Ctrl/⌘-click a call identifier in the pseudocode to follow it (pushes history).</li>
 *   <li>Sync toggle: follow the jadx caret automatically (driven by the plugin).</li>
 *   <li>"Xref" toolbar button / right-click "Show xrefs": callers of the currently-displayed
 *       function, scoped to its own library -- see {@link XrefsView}.</li>
 * </ul>
 */
public class NativeViewDialog extends JDialog {

	// AWT reports the mouse side buttons as 4 (back) and 5 (forward)
	private static final int MOUSE_BACK_BUTTON = 4;
	private static final int MOUSE_FORWARD_BUTTON = 5;

	private static final String FIND_ACTION_KEY = "jexray-find";
	private static final String ESC_ACTION_KEY = "jexray-escape";
	private static final String XREF_ACTION_KEY = "jexray-xrefs";

	/**
	 * How close together two Escapes must be to close the window. Taken from the desktop's
	 * double-click interval so it matches what the user's other double-press gestures feel like,
	 * with a 500ms fallback when the toolkit doesn't publish one.
	 */
	private static final int DOUBLE_ESC_MS = doubleClickIntervalMs();

	private static int doubleClickIntervalMs() {
		try {
			Object v = java.awt.Toolkit.getDefaultToolkit().getDesktopProperty("awt.multiClickInterval");
			if (v instanceof Integer i && i > 0) {
				return i;
			}
		} catch (Exception ignored) {
			// headless or unsupported toolkit
		}
		return 500;
	}
	/** Bridge status for a library that is submitted but hasn't started analyzing yet. */
	private static final String QUEUED_PHASE = "queued";

	private final JLabel headerLabel;
	private JLabel versionLabel;
	private final JLabel statusLabel;
	private JPanel statusBar;
	private java.awt.Color statusBarDefaultBg;
	private Timer statusTimer;
	private final ImageIcon warningIcon;
	private final ImageIcon errorIcon;
	private final JButton backButton;
	private final JButton forwardButton;
	private final JButton gotoJavaButton;
	private final JCheckBox syncCheck;
	private final RSyntaxTextArea pseudoArea;
	private final RSyntaxTextArea disasmArea;
	private final CodeSearchBar searchBar;

	// Shared code-area font size (Ctrl/⌘+wheel zoom on either tab), persisted so it's the same
	// next time the plugin runs -- see UiPrefs. Both areas always show the same size.
	private final UiPrefs uiPrefs;
	private int codeFontSize;
	private final JTabbedPane codeTabs;

	// true while the code area shows the one-time "Analyzing…" placeholder and nothing
	// else (a real function / error / loading state) has taken it over since.
	private boolean progressActive;

	// Set when the user closes the window. Analysis continues in the background, but background
	// updates must not reopen a window the user deliberately dismissed.
	private volatile boolean userClosed;

	// timestamp of the last unpaired Escape, for the double-press close gesture
	private long lastEscapeAt;

	// Bottom status-bar progress across a multi-library pre-warm, and the dim/lock overlay that
	// covers the code tabs while analysis is running.
	private JProgressBar progressBar;
	private final LockOverlayUI lockOverlay = new LockOverlayUI();
	private JLayer<JComponent> codeLayer;
	private Timer spinnerTimer;
	// current library index (0-based) and total count for the running pre-warm; used to weight
	// the overall progress percentage. Default (0,1) => a single on-demand load.
	private volatile int prewarmLibIndex;
	private volatile int prewarmLibCount = 1;

	private final Consumer<ICodeNodeRef> onNavigateToJava;
	// (soId of the function currently on screen, called symbol) -> follow the call.
	// The owning library must come from the rendered view, not from any "most recent" global:
	// Ghidra's synthetic FUN_<address> names are address-based and therefore unique per library,
	// so querying the wrong .so can only miss.
	private final BiConsumer<String, String> onOpenSymbol;
	private final Consumer<Boolean> onSyncToggled;
	private final Runnable onListFunctions;
	// Files a prefilled bug report seeded with whatever the dialog is currently showing.
	// Shared by the always-present toolbar button and the error-only button.
	private final Consumer<BugReportContext> onReportBug;
	private final JButton reportBugButton;
	private final JButton reportErrorButton;
	private final JButton copyErrorButton;
	// cache size + clear. The JADX plugin options API has no button/action control
	// (see JexrayOptions), so this lives here in the Native View toolbar instead of Preferences.
	private final Runnable onShowCache;
	private final JButton cacheButton;
	// Xrefs ("who calls this?"): fires with (soId, symbol) of the function currently on screen --
	// same source of truth as onOpenSymbol's call-following (history.current()), so xrefs is
	// always scoped to the library actually displayed. The plugin fetches asynchronously and
	// reports back through showXrefs.
	private final BiConsumer<String, String> onShowXrefs;
	private final JButton xrefButton;
	// "Loaded Libraries": which .so's the app asks the VM to load, from the Native View toolbar
	// (this is scoped to Native View only -- no global jadx menu item).
	private final Runnable onShowLoadedLibraries;
	private final JButton loadedLibrariesButton;

	// last version info pushed via setVersionInfo, and the current error context (when in the
	// error state) -- so the "Report this error" button can seed an accurate report.
	private String pluginVersion;
	private String ghidraVersion;
	private String errorSymbol;
	private String errorMessage;

	private final NavigationHistory<NativeFunctionView> history = new NavigationHistory<>();

	public NativeViewDialog(JFrame parent,
			Consumer<ICodeNodeRef> onNavigateToJava,
			BiConsumer<String, String> onOpenSymbol,
			Consumer<Boolean> onSyncToggled,
			Runnable onListFunctions,
			Consumer<BugReportContext> onReportBug,
			JexrayIcons.IconSource iconSource) {
		this(parent, onNavigateToJava, onOpenSymbol, onSyncToggled, onListFunctions, onReportBug, null, iconSource);
	}

	public NativeViewDialog(JFrame parent,
			Consumer<ICodeNodeRef> onNavigateToJava,
			BiConsumer<String, String> onOpenSymbol,
			Consumer<Boolean> onSyncToggled,
			Runnable onListFunctions,
			Consumer<BugReportContext> onReportBug,
			Runnable onShowCache,
			JexrayIcons.IconSource iconSource) {
		this(parent, onNavigateToJava, onOpenSymbol, onSyncToggled, onListFunctions, onReportBug, onShowCache,
				null, iconSource);
	}

	public NativeViewDialog(JFrame parent,
			Consumer<ICodeNodeRef> onNavigateToJava,
			BiConsumer<String, String> onOpenSymbol,
			Consumer<Boolean> onSyncToggled,
			Runnable onListFunctions,
			Consumer<BugReportContext> onReportBug,
			Runnable onShowCache,
			BiConsumer<String, String> onShowXrefs,
			JexrayIcons.IconSource iconSource) {
		this(parent, onNavigateToJava, onOpenSymbol, onSyncToggled, onListFunctions, onReportBug, onShowCache,
				onShowXrefs, null, iconSource);
	}

	public NativeViewDialog(JFrame parent,
			Consumer<ICodeNodeRef> onNavigateToJava,
			BiConsumer<String, String> onOpenSymbol,
			Consumer<Boolean> onSyncToggled,
			Runnable onListFunctions,
			Consumer<BugReportContext> onReportBug,
			Runnable onShowCache,
			BiConsumer<String, String> onShowXrefs,
			Runnable onShowLoadedLibraries,
			JexrayIcons.IconSource iconSource) {
		this(parent, onNavigateToJava, onOpenSymbol, onSyncToggled, onListFunctions, onReportBug, onShowCache,
				onShowXrefs, onShowLoadedLibraries, new UiPrefs(), iconSource);
	}

	/**
	 * Base constructor: takes the {@link UiPrefs} directly instead of constructing one over the real
	 * {@code ~/.jexray}.
	 */
	NativeViewDialog(JFrame parent,
			Consumer<ICodeNodeRef> onNavigateToJava,
			BiConsumer<String, String> onOpenSymbol,
			Consumer<Boolean> onSyncToggled,
			Runnable onListFunctions,
			Consumer<BugReportContext> onReportBug,
			Runnable onShowCache,
			BiConsumer<String, String> onShowXrefs,
			Runnable onShowLoadedLibraries,
			UiPrefs uiPrefs,
			JexrayIcons.IconSource iconSource) {
		super(parent, "Jexray - Native View", false);
		this.uiPrefs = uiPrefs;
		this.onNavigateToJava = onNavigateToJava;
		this.onOpenSymbol = onOpenSymbol;
		this.onSyncToggled = onSyncToggled;
		this.onListFunctions = onListFunctions;
		this.onReportBug = onReportBug;
		this.onShowCache = onShowCache;
		this.onShowXrefs = onShowXrefs;
		this.onShowLoadedLibraries = onShowLoadedLibraries;
		this.warningIcon = JexrayIcons.load(iconSource, "ui/warning");
		this.errorIcon = JexrayIcons.load(iconSource, "ui/error");
		setDefaultCloseOperation(HIDE_ON_CLOSE);
		addWindowListener(new java.awt.event.WindowAdapter() {
			@Override
			public void windowClosing(java.awt.event.WindowEvent e) {
				// remember the dismissal so in-flight analysis doesn't pop the window back up
				userClosed = true;
			}
		});

		// Always available from the toolbar; seeds the report with the current view.
		// no emoji in the label: Swing mis-measures emoji glyphs (clipped text) and they render as
		// tofu on some platforms. jadx's bug icon is used when available.
		reportBugButton = new JButton("Report Bug");
		reportBugButton.setToolTipText("Open a prefilled GitHub issue about what you're looking at");
		applyIcon(reportBugButton, JexrayIcons.loadFirst(iconSource, "ui/bug", "ui/warning"), "Report Bug");
		reportBugButton.addActionListener(e -> fireReportBug());

		// Additionally surfaced next to an error, seeded with that error.
		reportErrorButton = new JButton("Report this error");
		reportErrorButton.setToolTipText("Open a prefilled GitHub issue with this error and your environment");
		reportErrorButton.setVisible(false);
		applyIcon(reportErrorButton, JexrayIcons.loadFirst(iconSource, "ui/bug", "ui/error"), "Report this error");
		reportErrorButton.addActionListener(e -> fireReportBug());

		// A guaranteed way to copy the error text: on some platforms Ctrl/⌘-C over the read-only
		// code area doesn't land (focus/keymap quirks), and the message may carry a long Ghidra tail.
		copyErrorButton = new JButton("Copy");
		copyErrorButton.setToolTipText("Copy this error message to the clipboard");
		copyErrorButton.setVisible(false);
		applyIcon(copyErrorButton, JexrayIcons.loadFirst(iconSource, "ui/copy"), "Copy");
		copyErrorButton.addActionListener(e -> copyErrorToClipboard());

		backButton = new JButton("◀ Back");
		backButton.setToolTipText("Previous function in view history");
		backButton.setEnabled(false);
		backButton.addActionListener(e -> goBack());
		applyIcon(backButton, JexrayIcons.load(iconSource, "ui/left"), "Back");

		forwardButton = new JButton("Forward ▶");
		forwardButton.setToolTipText("Next function in view history (right-click for full history)");
		forwardButton.setEnabled(false);
		forwardButton.addActionListener(e -> goForward());
		applyIcon(forwardButton, JexrayIcons.load(iconSource, "ui/right"), "Forward");

		backButton.setToolTipText("Previous function in view history (right-click for full history)");
		installHistoryPopup(backButton);
		installHistoryPopup(forwardButton);

		gotoJavaButton = new JButton("Go to Java Source");
		gotoJavaButton.setToolTipText("Jump back to the original native method declaration in jadx");
		gotoJavaButton.setEnabled(false);
		gotoJavaButton.addActionListener(e -> navigateToJava());
		applyIcon(gotoJavaButton, JexrayIcons.loadFirst(iconSource, "ui/locate", "ui/home"), "Go to Java Source");

		syncCheck = new JCheckBox("Sync");
		syncCheck.setToolTipText("Follow the jadx caret: auto-open the native method under the cursor");
		syncCheck.addActionListener(e -> {
			if (onSyncToggled != null) {
				onSyncToggled.accept(syncCheck.isSelected());
			}
		});

		JButton allFunctionsButton = new JButton("☰ All Functions");
		allFunctionsButton.setToolTipText("Browse every function in the loaded native library");
		allFunctionsButton.addActionListener(e -> {
			if (onListFunctions != null) {
				onListFunctions.run();
			}
		});
		applyIcon(allFunctionsButton, JexrayIcons.loadFirst(iconSource, "ui/find", "ui/usagesFinder"), "All Functions");

		loadedLibrariesButton = new JButton("Loaded Libraries");
		loadedLibrariesButton.setToolTipText(
				"Which .so files this app asks the VM to load, and their exported functions");
		loadedLibrariesButton.addActionListener(e -> {
			if (onShowLoadedLibraries != null) {
				onShowLoadedLibraries.run();
			}
		});
		applyIcon(loadedLibrariesButton, JexrayIcons.loadFirst(iconSource, "ui/moduleGroup", "ui/Module"),
				"Loaded Libraries");

		cacheButton = new JButton("Cache…");
		cacheButton.setToolTipText("See how much disk space the Ghidra analysis cache is using, and clear it");
		cacheButton.addActionListener(e -> {
			if (onShowCache != null) {
				onShowCache.run();
			}
		});
		applyIcon(cacheButton, JexrayIcons.loadFirst(iconSource, "ui/save", "ui/settings"), "Cache");

		xrefButton = new JButton("Xref");
		xrefButton.setToolTipText("Show cross references: who calls this function");
		xrefButton.setEnabled(false);
		xrefButton.addActionListener(e -> requestXrefs());
		// jadx 1.5.5 ships no dedicated "xref" icon; "usagesFinder" (find-usages) is its closest
		// semantic match and is otherwise unused as a primary icon (All Functions prefers "find").
		applyIcon(xrefButton, JexrayIcons.load(iconSource, "ui/usagesFinder"), "Xref");

		JToolBar toolbar = new JToolBar();
		toolbar.setFloatable(false);
		toolbar.add(backButton);
		toolbar.add(forwardButton);
		toolbar.addSeparator();
		toolbar.add(gotoJavaButton);
		toolbar.add(xrefButton);
		toolbar.addSeparator();
		toolbar.add(allFunctionsButton);
		toolbar.add(loadedLibrariesButton);
		toolbar.addSeparator();
		toolbar.add(syncCheck);
		toolbar.addSeparator();
		toolbar.add(reportBugButton);
		toolbar.add(cacheButton);
		toolbar.add(Box.createHorizontalGlue());
		versionLabel = new JLabel(" ");
		versionLabel.setBorder(new EmptyBorder(0, 6, 0, 8));
		versionLabel.setEnabled(false);
		toolbar.add(versionLabel);

		headerLabel = new JLabel("No native method selected");
		JPanel header = new JPanel(new BorderLayout());
		header.setBorder(new EmptyBorder(2, 8, 4, 8));
		header.add(headerLabel, BorderLayout.CENTER);
		JLabel hint = new JLabel("Ctrl/⌘-click or double-click a call to follow");
		hint.setEnabled(false);
		JPanel headerEast = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 6, 0));
		headerEast.setOpaque(false);
		headerEast.add(copyErrorButton);
		headerEast.add(reportErrorButton);
		headerEast.add(hint);
		header.add(headerEast, BorderLayout.EAST);

		JPanel north = new JPanel(new BorderLayout());
		north.add(toolbar, BorderLayout.NORTH);
		north.add(header, BorderLayout.SOUTH);

		codeFontSize = uiPrefs.loadFontSize();
		pseudoArea = buildArea(SyntaxConstants.SYNTAX_STYLE_C, codeFontSize);
		disasmArea = buildArea(SyntaxConstants.SYNTAX_STYLE_NONE, codeFontSize);
		installCallClickHandler(pseudoArea);
		installXrefsPopup(pseudoArea);
		installXrefsPopup(disasmArea);

		JTabbedPane tabs = new JTabbedPane();
		codeTabs = tabs;
		tabs.addTab("Pseudocode", new RTextScrollPane(pseudoArea));
		tabs.addTab("Disassembly", new RTextScrollPane(disasmArea));
		// the wheel-zoom listener sits on the text areas and forwards plain wheels to the scroll pane
		// itself (see installFontSizeWheelZoom for why this, not a listener on the scroll pane)
		installFontSizeWheelZoom(pseudoArea, disasmArea);

		// Dim + lock overlay covering the code tabs while a library is being analyzed. A plain
		// JDK JLayer/LayerUI (no extra dependency); an animated spinner is painted, not an icon.
		codeLayer = new JLayer<>(tabs, lockOverlay);

		// Find bar above the code tabs, always targeting whichever tab is active.
		searchBar = new CodeSearchBar(
				() -> tabs.getSelectedIndex() == 1 ? disasmArea : pseudoArea, iconSource);
		JPanel codeWrap = new JPanel(new BorderLayout());
		codeWrap.add(searchBar, BorderLayout.NORTH);
		codeWrap.add(codeLayer, BorderLayout.CENTER);

		// Bottom status bar: a distinct strip (border + tinted, theme-derived background) so
		// transient notices (silent-navigation misses, version warnings) read as a real status
		// bar rather than blending into ordinary text. A progress bar (right) fills during a
		// multi-library pre-warm; a plain JProgressBar inherits the host FlatLaf accent colour.
		statusLabel = new JLabel(" ");
		statusLabel.setBorder(new EmptyBorder(3, 8, 3, 8));
		progressBar = new JProgressBar(0, 100);
		progressBar.setStringPainted(true);
		progressBar.setVisible(false);
		progressBar.setPreferredSize(new Dimension(220, 16));
		JPanel progressHolder = new JPanel(new BorderLayout());
		progressHolder.setOpaque(false);
		progressHolder.setBorder(new EmptyBorder(2, 8, 2, 8));
		progressHolder.add(progressBar, BorderLayout.CENTER);
		statusBar = new JPanel(new BorderLayout());
		statusBar.add(statusLabel, BorderLayout.CENTER);
		statusBar.add(progressHolder, BorderLayout.EAST);
		statusBar.setOpaque(true);
		statusBarDefaultBg = statusBar.getBackground().darker();
		statusBar.setBackground(statusBarDefaultBg);
		statusBar.setBorder(javax.swing.BorderFactory.createMatteBorder(1, 0, 0, 0,
				statusBarDefaultBg.darker()));

		JPanel content = new JPanel(new BorderLayout());
		content.add(north, BorderLayout.NORTH);
		content.add(codeWrap, BorderLayout.CENTER);
		content.add(statusBar, BorderLayout.SOUTH);

		setContentPane(content);
		installFindShortcut();
		installDoubleEscapeToClose();
		installXrefsShortcut();
		installSideButtonNav(pseudoArea, disasmArea, tabs, content, headerLabel);
		// wide enough that the toolbar fits without the trailing buttons being clipped to "..."
		setPreferredSize(new Dimension(1000, 660));
		pack();
		if (parent != null) {
			setLocationRelativeTo(parent);
		}
	}

	/**
	 * Ctrl+F (and ⌘+F on macOS) opens the find bar. Escape is not bound by this method: closing on
	 * Escape is wired separately by {@link #installDoubleEscapeToClose()}, which requires two
	 * presses so a single Escape can be consumed by the find bar's own text field first.
	 */
	private void installFindShortcut() {
		int menuMask = java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
		javax.swing.KeyStroke menuF = javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F, menuMask);
		javax.swing.KeyStroke ctrlF = javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F,
				java.awt.event.InputEvent.CTRL_DOWN_MASK);

		javax.swing.Action findAction = new javax.swing.AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				searchBar.showAndFocus();
			}
		};

		javax.swing.InputMap im = getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
		im.put(menuF, FIND_ACTION_KEY);
		im.put(ctrlF, FIND_ACTION_KEY);
		getRootPane().getActionMap().put(FIND_ACTION_KEY, findAction);

		// RSyntaxTextArea binds Ctrl+F to caret-forward, and WHEN_FOCUSED wins over
		// WHEN_IN_FOCUSED_WINDOW -- so claim it on the code areas too, or Ctrl+F would just move
		// the caret while the code has focus (the common case) on Linux/Windows.
		for (RSyntaxTextArea area : new RSyntaxTextArea[] { pseudoArea, disasmArea }) {
			area.getInputMap(JComponent.WHEN_FOCUSED).put(menuF, FIND_ACTION_KEY);
			area.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlF, FIND_ACTION_KEY);
			area.getActionMap().put(FIND_ACTION_KEY, findAction);
		}
	}

	/**
	 * Escape twice in quick succession closes the window; a single Escape does nothing on its own.
	 *
	 * <p>Bound on the code areas as well as the window, because RSyntaxTextArea handles Escape
	 * itself and {@code WHEN_FOCUSED} outranks {@code WHEN_IN_FOCUSED_WINDOW} -- the same shadowing
	 * that made Ctrl+F only move the caret. When the find bar is open the first Escape closes just
	 * the find bar and does not count toward the pair, so dismissing a search never also throws
	 * away the window.
	 */
	private void installDoubleEscapeToClose() {
		javax.swing.KeyStroke esc = javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0);
		javax.swing.Action escAction = new javax.swing.AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				onEscapePressed();
			}
		};
		getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(esc, ESC_ACTION_KEY);
		getRootPane().getActionMap().put(ESC_ACTION_KEY, escAction);
		for (RSyntaxTextArea area : new RSyntaxTextArea[] { pseudoArea, disasmArea }) {
			area.getInputMap(JComponent.WHEN_FOCUSED).put(esc, ESC_ACTION_KEY);
			area.getActionMap().put(ESC_ACTION_KEY, escAction);
		}
	}

	/**
	 * Plain {@code X} over the code shows xrefs of the current function, the way IDA's X does.
	 *
	 * <p>Bound only on the code areas ({@code WHEN_FOCUSED}), never window-wide: the find bar is a
	 * text field, and a window-wide X would swallow the letter 'x' the moment the user typed it into
	 * a search. The code areas are read-only, so X carries no editing meaning to displace there.
	 */
	private void installXrefsShortcut() {
		javax.swing.KeyStroke x = javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_X, 0);
		javax.swing.Action xrefAction = new javax.swing.AbstractAction() {
			private static final long serialVersionUID = 1L;

			@Override
			public void actionPerformed(java.awt.event.ActionEvent e) {
				requestXrefs();
			}
		};
		for (RSyntaxTextArea area : new RSyntaxTextArea[] { pseudoArea, disasmArea }) {
			area.getInputMap(JComponent.WHEN_FOCUSED).put(x, XREF_ACTION_KEY);
			area.getActionMap().put(XREF_ACTION_KEY, xrefAction);
		}
	}

	/** Handle one Escape. */
	void onEscapePressed() {
		if (searchBar != null && searchBar.isVisible()) {
			// closing the find bar is its own action, and must not count toward closing the window
			searchBar.hideBar();
			lastEscapeAt = 0;
			return;
		}
		long now = System.currentTimeMillis();
		if (lastEscapeAt != 0 && now - lastEscapeAt <= DOUBLE_ESC_MS) {
			lastEscapeAt = 0;
			// go through the normal close path so userClosed is set and background progress
			// updates don't immediately reopen the window
			dispatchEvent(new java.awt.event.WindowEvent(this, java.awt.event.WindowEvent.WINDOW_CLOSING));
			return;
		}
		lastEscapeAt = now; // too slow to pair, or the first of a new pair
	}

	/** Mouse side buttons: BUTTON4 = Back, BUTTON5 = Forward (same as the toolbar buttons). */
	private void installSideButtonNav(java.awt.Component... components) {
		MouseAdapter nav = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				onMouseSideButton(e.getButton());
			}
		};
		for (java.awt.Component c : components) {
			c.addMouseListener(nav);
		}
	}

	/** Handle a mouse button: 4 navigates back, 5 navigates forward; others ignored. */
	void onMouseSideButton(int button) {
		if (button == MOUSE_BACK_BUTTON) {
			goBack();
		} else if (button == MOUSE_FORWARD_BUTTON) {
			goForward();
		}
	}

	/** Give a button jadx's icon plus a clean label; if the icon didn't load, keep the glyph text. */
	private static void applyIcon(AbstractButton button, ImageIcon icon, String plainText) {
		if (icon != null) {
			button.setIcon(icon);
			button.setText(plainText);
		}
	}

	private static RSyntaxTextArea buildArea(String syntaxStyle, int fontSize) {
		RSyntaxTextArea area = new RSyntaxTextArea(30, 90);
		area.setSyntaxEditingStyle(syntaxStyle);
		// Match the syntax colours to the host L&F (light/dark); best-effort, before our own font.
		ThemeSupport.applySyntaxTheme(area, ThemeSupport.isDarkLookAndFeel());
		area.setEditable(false);
		area.setCodeFoldingEnabled(true);
		area.setAntiAliasingEnabled(true);
		area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, fontSize));
		DialogUtils.installClipboardShortcuts(area);
		return area;
	}

	/**
	 * Ctrl+wheel (⌘+wheel on macOS) over either code area zooms the shared font size instead of
	 * scrolling -- same menu-shortcut modifier as Ctrl/⌘+F, so it tracks the platform automatically.
	 * The event is only consumed when the modifier is held; a plain wheel is left alone so it falls
	 * through to the enclosing {@link RTextScrollPane}'s normal scrolling untouched.
	 *
	 * <p>One shared size drives both tabs (so they can't drift apart) and is persisted on every
	 * change via {@link UiPrefs}, so the next dialog reflects whatever the user last chose.
	 */
	private void installFontSizeWheelZoom(RSyntaxTextArea... areas) {
		int menuMask = java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
		MouseWheelListener zoom = e -> {
			if ((e.getModifiersEx() & menuMask) != 0) {
				// modifier held: zoom, and stop here -- the event is not forwarded, so the scroll
				// pane never sees it and the code doesn't also scroll
				e.consume();
				codeFontSize = e.getWheelRotation() < 0 ? UiPrefs.increment(codeFontSize) : UiPrefs.decrement(codeFontSize);
				Font font = new Font(Font.MONOSPACED, Font.PLAIN, codeFontSize);
				for (RSyntaxTextArea a : areas) {
					a.setFont(font);
				}
				uiPrefs.saveFontSize(codeFontSize);
				return;
			}
			// Plain wheel: this listener sits on the text area, which intercepts the event before the
			// enclosing scroll pane can scroll -- so forward it to the scroll pane, which is the only
			// way normal scrolling still happens. (Listening on the scroll pane instead doesn't work:
			// its own wheel scroller runs before ours and scrolls even when we consume, so a modifier
			// wheel would both zoom AND scroll.)
			javax.swing.JScrollPane sp = (javax.swing.JScrollPane) javax.swing.SwingUtilities
					.getAncestorOfClass(javax.swing.JScrollPane.class, (java.awt.Component) e.getSource());
			if (sp != null) {
				sp.dispatchEvent(e);
			}
		};
		for (RSyntaxTextArea a : areas) {
			a.addMouseWheelListener(zoom);
		}
	}

	private void installCallClickHandler(RSyntaxTextArea area) {
		area.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (onOpenSymbol == null) {
					return;
				}
				boolean navigate = ClickPolicy.shouldNavigate(
						SwingUtilities.isLeftMouseButton(e),
						e.isPopupTrigger(),
						e.isControlDown() || e.isMetaDown(),
						e.getClickCount());
				if (!navigate) {
					return;
				}
				int offset = area.viewToModel2D(e.getPoint());
				String call = CallExtractor.callIdentifierAt(area.getText(), offset);
				if (call != null) {
					// resolve against the library this pseudocode came from, not whatever was
					// opened most recently elsewhere
					NativeFunctionView cur = history.current();
					onOpenSymbol.accept(cur == null ? null : cur.soId(), call);
				}
			}
		});
		area.addMouseMotionListener(new MouseAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				boolean mod = e.isControlDown() || e.isMetaDown();
				int offset = area.viewToModel2D(e.getPoint());
				boolean onCall = mod && CallExtractor.callIdentifierAt(area.getText(), offset) != null;
				area.setCursor(Cursor.getPredefinedCursor(onCall ? Cursor.HAND_CURSOR : Cursor.TEXT_CURSOR));
			}
		});
	}

	/**
	 * Right-click "Show xrefs" on the currently-displayed function -- not on whatever identifier
	 * happens to be under the cursor, so this behaves identically to the toolbar "X" button (both
	 * read {@code history.current()}, see {@link #requestXrefs}).
	 */
	private void installXrefsPopup(RSyntaxTextArea area) {
		JPopupMenu menu = new JPopupMenu();
		JMenuItem item = new JMenuItem("Show xrefs");
		item.addActionListener(e -> requestXrefs());
		menu.add(item);

		// Attaching our own popup replaces the one RSyntaxTextArea ships, which carried Copy and
		// Select All -- so put them back. These call the component directly rather than going
		// through the editor kit's action map, giving a copy path that holds regardless of how the
		// keyboard bindings resolve.
		menu.addSeparator();
		JMenuItem copyItem = new JMenuItem("Copy");
		copyItem.addActionListener(e -> area.copy());
		menu.add(copyItem);
		JMenuItem selectAllItem = new JMenuItem("Select All");
		selectAllItem.addActionListener(e -> area.selectAll());
		menu.add(selectAllItem);
		menu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
			@Override
			public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
				copyItem.setEnabled(area.getSelectedText() != null);
			}

			@Override
			public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {
			}

			@Override
			public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {
			}
		});

		area.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeShow(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeShow(e);
			}

			private void maybeShow(MouseEvent e) {
				if (e.isPopupTrigger()) {
					menu.show(area, e.getX(), e.getY());
				}
			}
		});
	}

	/** Ask the plugin for the callers of whatever function is currently on screen. */
	private void requestXrefs() {
		NativeFunctionView cur = history.current();
		if (cur == null || onShowXrefs == null) {
			return;
		}
		onShowXrefs.accept(cur.soId(), cur.symbol());
	}

	/** Show the callers fetched for a prior {@link #requestXrefs} call. */
	public void showXrefs(XrefsView view) {
		onEdt(() -> new XrefsDialog(this, view, onOpenSymbol).setVisible(true));
	}

	private void navigateToJava() {
		NativeFunctionView cur = history.current();
		if (cur != null && cur.javaRef() != null && onNavigateToJava != null) {
			onNavigateToJava.accept(cur.javaRef());
		}
	}

	private void goBack() {
		if (history.canBack()) {
			render(history.back());
		}
	}

	private void goForward() {
		if (history.canForward()) {
			render(history.forward());
		}
	}

	private void installHistoryPopup(JButton button) {
		button.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeShow(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeShow(e);
			}

			private void maybeShow(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showHistoryMenu(button, e.getX(), e.getY());
				}
			}
		});
	}

	/** Right-click dropdown listing the entire view history; click an entry to jump to it. */
	private void showHistoryMenu(JButton invoker, int x, int y) {
		List<NativeFunctionView> all = history.entries();
		if (all.isEmpty()) {
			return;
		}
		JPopupMenu menu = new JPopupMenu();
		int cur = history.cursor();
		for (int i = 0; i < all.size(); i++) {
			final int idx = i;
			String prefix = (i == cur) ? "● " : "  "; // filled dot marks current
			JMenuItem item = new JMenuItem(prefix + all.get(i).symbol());
			item.addActionListener(e -> render(history.jumpTo(idx)));
			menu.add(item);
		}
		menu.show(invoker, x, y);
	}

	/**
	 * Begin a (possibly multi-library) pre-warm: raise the lock overlay and the status-bar progress
	 * bar immediately, before the first library's analysis progress arrives.
	 */
	public void beginPrewarm(int libCount) {
		onEdt(() -> {
			clearErrorState();
			prewarmLibCount = Math.max(1, libCount);
			prewarmLibIndex = 0;
			progressActive = true;
			progressBar.setVisible(true);
			// nothing measurable yet: start indeterminate rather than showing a fake 0%
			progressBar.setIndeterminate(true);
			progressBar.setValue(0);
			progressBar.setString("Preparing");
			String kicker = prewarmLibCount > 1 ? (prewarmLibCount + " LIBRARIES") : "";
			lockOverlay.set(true, kicker, "Preparing analysis…", "Loading native libraries…");
			startSpinner();
			codeLayer.repaint();
			headerLabel.setText("Preparing native library analysis…");
			headerLabel.setIcon(null);
			pseudoArea.setText("// Preparing native library analysis…");
			pseudoArea.setCaretPosition(0);
			surface();
		});
	}

	/**
	 * Report aggregate progress while several libraries are analyzed concurrently. Unlike
	 * {@link #showLoadProgress}, this names no single library: with a pool of libraries in
	 * different phases, naming one would misrepresent the rest.
	 *
	 * <p>Called from the eager pre-warm's poll loop every {@code LOAD_POLL_MS} for as long as any
	 * library is still analyzing, so this must be idempotent: a tick that reports the exact same
	 * state as last time must produce no visible work (no re-parsed pseudocode area, no restarted
	 * spinner, no repaint, no re-front of the window) -- see {@link #setPseudoTextIfChanged} and
	 * {@link #surface()} for where each of those is guarded.
	 */
	public void showPrewarmProgress(PrewarmProgress p) {
		onEdt(() -> {
			clearErrorState();
			progressActive = true;

			boolean changed = p.isMeasurable()
					? setProgressDeterminate(p.percent())
					// nothing finished and no counts yet -- don't pin the bar at a number it can't leave
					: setProgressIndeterminate("Analyzing");

			String kicker = "LIBRARIES " + (p.ready() + p.failed()) + " / " + p.total();
			// names line is separate from the summary so it can be blank (and skipped) when nothing
			// is analyzing yet, rather than aggregate counts alone -- see analyzingLine() javadoc
			changed |= lockOverlay.set(true, kicker, "Analyzing native libraries", p.summaryLine(), p.analyzingLine());
			changed |= setHeaderTextIfChanged("Analyzing " + p.total() + " native libraries — " + p.summaryLine());
			headerLabel.setIcon(null);
			changed |= setPseudoTextIfChanged("// Analyzing native libraries: " + p.summaryLine()
					+ "\n// This one-time analysis runs once per library; queries are instant afterwards.");

			startSpinner();
			if (changed) {
				codeLayer.repaint();
				surface();
			}
		});
	}

	/** Set which library (0-based) of how many the pre-warm is currently on (weights the bar). */
	public void setLibraryContext(int libIndex, int libCount) {
		this.prewarmLibCount = Math.max(1, libCount);
		this.prewarmLibIndex = Math.max(0, libIndex);
	}

	public void showLoadProgress(String soName, String phase, int completed, int total) {
		showLoadProgress(soName, phase, completed, total, null);
	}

	/**
	 * Show one-time library analysis progress while the bridge caches the .so.
	 *
	 * <p>{@code total} is 0 until the bridge's post-script starts reporting function counts -- the
	 * import + auto-analysis phase before that has no measurable progress. Rather than showing a
	 * percentage frozen at a library boundary, the bar goes indeterminate for that stretch and only
	 * becomes determinate once real counts arrive. {@code detail} is the bridge's coarse phase text
	 * (e.g. "Auto-analyzing (Ghidra)..."), shown so the indeterminate stretch still says something.
	 *
	 * <p>Called from {@code ensureBridgeLoaded}'s poll loop every {@code LOAD_POLL_MS}, so -- like
	 * {@link #showPrewarmProgress} -- it must be idempotent: a tick reporting unchanged state must
	 * do no visible work. See that method's javadoc for what that guards against.
	 */
	public void showLoadProgress(String soName, String phase, int completed, int total, String detail) {
		onEdt(() -> {
			clearErrorState();
			progressActive = true;
			int libCount = Math.max(1, prewarmLibCount);
			int libIdx = Math.min(Math.max(0, prewarmLibIndex), libCount - 1);
			boolean queued = QUEUED_PHASE.equals(phase);
			boolean measurable = total > 0;

			String libPrefix = libCount > 1 ? ("Library " + (libIdx + 1) + "/" + libCount + ": ") : "";
			String line = libPrefix + (queued
					? "Queued " + (soName == null ? "native library" : soName) + "..."
					: ProgressText.analyzing(soName, phase, completed, total));

			String kicker = libCount > 1 ? ("LIBRARY " + (libIdx + 1) + " / " + libCount) : "ANALYZING";
			String subtitle;
			if (queued) {
				kicker = libCount > 1 ? ("QUEUED " + (libIdx + 1) + " / " + libCount) : "QUEUED";
				subtitle = "Waiting for another library to finish…";
			} else if (measurable) {
				subtitle = "Analyzing native code — " + completed + " / " + total + " functions";
			} else {
				subtitle = (detail == null || detail.isEmpty()) ? "Analyzing native code…" : detail;
			}

			boolean changed;
			if (measurable) {
				double within = Math.min(1.0, (double) completed / total);
				int pct = (int) Math.round((libIdx + within) / libCount * 100.0);
				pct = Math.max(0, Math.min(100, pct));
				changed = setProgressDeterminate(pct);
			} else {
				// no numeric progress exists yet -- don't invent one
				changed = setProgressIndeterminate(queued ? "Queued" : "Analyzing");
			}
			changed |= lockOverlay.set(true, kicker, soName, subtitle);
			changed |= setHeaderTextIfChanged(line);
			headerLabel.setIcon(null);
			changed |= setPseudoTextIfChanged(
					"// " + line + "\n// This one-time analysis runs once per library; queries are instant afterwards.");

			startSpinner();
			if (changed) {
				codeLayer.repaint();
				surface();
			}
		});
	}

	/**
	 * Settle the code area into a clear "ready" state once background pre-warm finishes, replacing
	 * the lingering "Analyzing…" placeholder and dropping the lock overlay / progress bar. No-op if
	 * the user already navigated to a function (or hit an error) meanwhile -- that content must not
	 * be clobbered.
	 */
	public void showReady(String message) {
		onEdt(() -> {
			if (!progressActive) {
				return;
			}
			progressActive = false;
			prewarmLibIndex = 0;
			prewarmLibCount = 1;
			clearProgressChrome();
			clearErrorState();
			headerLabel.setText(message);
			headerLabel.setIcon(null);
			pseudoArea.setText("// " + message
					+ "\n// Right-click a native method in the Java view, or use ☰ All Functions to browse.");
			pseudoArea.setCaretPosition(0);
		});
	}

	private void startSpinner() {
		if (spinnerTimer == null) {
			spinnerTimer = new Timer(45, e -> {
				lockOverlay.tick();
				if (codeLayer != null) {
					codeLayer.repaint();
				}
			});
			spinnerTimer.setRepeats(true);
		}
		if (!spinnerTimer.isRunning()) {
			spinnerTimer.start();
		}
	}

	private void stopSpinner() {
		if (spinnerTimer != null) {
			spinnerTimer.stop();
		}
	}

	/** Drop the lock overlay and hide the status-bar progress bar. Caller must be on the EDT. */
	private void clearProgressChrome() {
		stopSpinner();
		if (lockOverlay != null) {
			lockOverlay.set(false, "", "", "");
			if (codeLayer != null) {
				codeLayer.repaint();
			}
		}
		if (progressBar != null) {
			progressBar.setIndeterminate(false);
			progressBar.setVisible(false);
		}
	}

	/**
	 * Push new pseudocode-area text only when it actually differs from what's already shown.
	 *
	 * <p>{@code RSyntaxTextArea#setText} re-parses and repaints the whole document and resets the
	 * caret/scroll position even when the new text is identical to the old -- the single biggest
	 * contributor to the pre-warm poll loop's flicker (see the class-level note on
	 * {@link #showPrewarmProgress}). A poll tick that repeats the same content must not pay that
	 * cost.
	 *
	 * @return whether the text actually changed (and was therefore pushed)
	 */
	private boolean setPseudoTextIfChanged(String text) {
		if (text.equals(pseudoArea.getText())) {
			return false;
		}
		pseudoArea.setText(text);
		pseudoArea.setCaretPosition(0);
		return true;
	}

	/** As {@link #setPseudoTextIfChanged}, for the header label. @return whether it changed. */
	private boolean setHeaderTextIfChanged(String text) {
		if (text.equals(headerLabel.getText())) {
			return false;
		}
		headerLabel.setText(text);
		return true;
	}

	/**
	 * Put the status-bar progress bar in determinate mode at {@code pct}%, touching only the Swing
	 * properties that actually differ from what's already shown. @return whether anything changed.
	 */
	private boolean setProgressDeterminate(int pct) {
		boolean changed = false;
		if (!progressBar.isVisible()) {
			progressBar.setVisible(true);
			changed = true;
		}
		if (progressBar.isIndeterminate()) {
			progressBar.setIndeterminate(false);
			changed = true;
		}
		if (progressBar.getValue() != pct) {
			progressBar.setValue(pct);
			changed = true;
		}
		String text = pct + "%";
		if (!text.equals(progressBar.getString())) {
			progressBar.setString(text);
			changed = true;
		}
		return changed;
	}

	/** As {@link #setProgressDeterminate}, for the indeterminate case with static status text. */
	private boolean setProgressIndeterminate(String text) {
		boolean changed = false;
		if (!progressBar.isVisible()) {
			progressBar.setVisible(true);
			changed = true;
		}
		if (!progressBar.isIndeterminate()) {
			progressBar.setIndeterminate(true);
			changed = true;
		}
		if (!text.equals(progressBar.getString())) {
			progressBar.setString(text);
			changed = true;
		}
		return changed;
	}

	/** Transient loading state; does not affect history. */
	public void showLoading(String symbol) {
		onEdt(() -> {
			progressActive = false;
			clearProgressChrome();
			clearErrorState();
			headerLabel.setText("Loading " + symbol + " ...");
			headerLabel.setIcon(null);
			pseudoArea.setText("// requesting pseudocode from Ghidra bridge for " + symbol);
			pseudoArea.setCaretPosition(0);
			disasmArea.setText("; requesting disassembly for " + symbol);
			disasmArea.setCaretPosition(0);
			surface();
		});
	}

	/** Push a successfully-resolved function onto history and render it. */
	public void showFunction(NativeFunctionView view) {
		onEdt(() -> {
			// revisiting any already-viewed function (anywhere in the stack) just moves the
			// cursor there. Keyed by address (not symbol) so the same function reached under
			// different name forms across entry paths collapses to one history entry.
			history.visit(view, NativeFunctionView::dedupKey);
			render(view);
			surface();
		});
	}

	/** Transient error state; does not affect history. */
	public void showError(String symbol, String message) {
		onEdt(() -> {
			progressActive = false;
			clearProgressChrome();
			errorSymbol = symbol;
			errorMessage = message;
			reportErrorButton.setVisible(onReportBug != null);
			copyErrorButton.setVisible(true);
			headerLabel.setText("Error for " + symbol);
			headerLabel.setIcon(errorIcon); // null when unavailable -> no icon
			pseudoArea.setText("// " + message);
			pseudoArea.setCaretPosition(0);
			updateNavButtons();
			surface();
		});
	}

	/**
	 * Fire a bug report seeded with the current view. Shared by the toolbar button and the
	 * error-only button so both go through exactly one path.
	 */
	private void fireReportBug() {
		if (onReportBug != null) {
			onReportBug.accept(currentBugContext());
		}
	}

	/** What the dialog is showing right now: an error, a function, or nothing. */
	private BugReportContext currentBugContext() {
		if (errorSymbol != null) {
			return BugReportContext.error(errorSymbol, errorMessage);
		}
		NativeFunctionView cur = history.current();
		if (cur != null) {
			return BugReportContext.function(cur.symbol(), cur.address());
		}
		return BugReportContext.empty();
	}

	/** Leave the error state: forget the error context and hide the "Report this error" button. */
	private void clearErrorState() {
		errorSymbol = null;
		errorMessage = null;
		if (reportErrorButton != null) {
			reportErrorButton.setVisible(false);
		}
		if (copyErrorButton != null) {
			copyErrorButton.setVisible(false);
		}
	}

	/** Copy the current error (symbol + full message, including any Ghidra output tail) verbatim. */
	private void copyErrorToClipboard() {
		String text = (errorSymbol != null ? "Error for " + errorSymbol + "\n" : "")
			+ (errorMessage != null ? errorMessage : "");
		try {
			java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
				.setContents(new java.awt.datatransfer.StringSelection(text), null);
			flashStatus("Error copied to clipboard");
		} catch (Exception ex) {
			flashStatus("Could not access the clipboard: " + ex.getMessage());
		}
	}

	private void render(NativeFunctionView view) {
		onEdt(() -> {
			progressActive = false;
			clearProgressChrome();
			clearErrorState();
			headerLabel.setText(view.symbol()
					+ (view.address() == null || view.address().isEmpty() ? "" : "   @ " + view.address()));
			headerLabel.setIcon(null); // leaving any prior error state
			pseudoArea.setText(view.pseudocode() == null ? "" : view.pseudocode());
			pseudoArea.setCaretPosition(0);
			disasmArea.setText(view.disassembly() == null ? "" : view.disassembly());
			disasmArea.setCaretPosition(0);
			gotoJavaButton.setEnabled(view.javaRef() != null && onNavigateToJava != null);
			xrefButton.setEnabled(onShowXrefs != null);
			updateNavButtons();
		});
	}

	/** Show a brief, non-intrusive status message that auto-clears (does not touch content). */
	/**
	 * Float a notification card over the top-right of the view. For answers that are not failures
	 * -- the status bar reads as a warning, and a modal dialog would be far too loud for "this
	 * symbol lives in another library".
	 */
	public void showToast(String glyph, String title, String body) {
		onEdt(() -> Toast.show(this, glyph, title, body));
	}

	public void flashStatus(String message) {
		onEdt(() -> {
			if (warningIcon != null) {
				statusLabel.setIcon(warningIcon); // jadx warning glyph as the visual anchor
				statusLabel.setText(message);
			} else {
				statusLabel.setIcon(null);
				statusLabel.setText("ⓘ " + message); // fallback: circled small "i"
			}
			statusBar.setBackground(blend(statusBarDefaultBg, new java.awt.Color(0xE0B000), 0.28));
			statusBar.repaint();
			if (statusTimer != null) {
				statusTimer.stop();
			}
			statusTimer = new Timer(4000, e -> {
				statusLabel.setIcon(null);
				statusLabel.setText(" ");
				statusBar.setBackground(statusBarDefaultBg);
				statusBar.repaint();
			});
			statusTimer.setRepeats(false);
			statusTimer.start();
		});
	}

	/** Mix {@code accent} into {@code base} by {@code ratio} (0..1) -- theme-adaptive tinting
	 * (works for both light and dark look-and-feels since it starts from the real background). */
	private static java.awt.Color blend(java.awt.Color base, java.awt.Color accent, double ratio) {
		int r = (int) (base.getRed() * (1 - ratio) + accent.getRed() * ratio);
		int g = (int) (base.getGreen() * (1 - ratio) + accent.getGreen() * ratio);
		int b = (int) (base.getBlue() * (1 - ratio) + accent.getBlue() * ratio);
		return new java.awt.Color(r, g, b);
	}

	/**
	 * Show "Jexray {ver} · Ghidra {gver}" in the toolbar. When {@code warn} is set (untested
	 * Ghidra version) it is emphasized in red with the warning as a tooltip.
	 */
	public void setVersionInfo(String pluginVersion, String ghidraVersion, boolean warn, String warnText) {
		this.pluginVersion = pluginVersion;
		this.ghidraVersion = ghidraVersion;
		onEdt(() -> {
			if (versionLabel == null) {
				return;
			}
			String g = (ghidraVersion == null || ghidraVersion.isEmpty()) ? "Ghidra ?" : "Ghidra " + ghidraVersion;
			versionLabel.setText("Jexray " + pluginVersion + "  ·  " + g + (warn ? "  ⚠" : ""));
			versionLabel.setEnabled(true);
			versionLabel.setForeground(warn ? java.awt.Color.RED : javax.swing.UIManager.getColor("Label.foreground"));
			versionLabel.setToolTipText(warn ? warnText : null);
		});
	}

	private void updateNavButtons() {
		backButton.setEnabled(history.canBack());
		forwardButton.setEnabled(history.canForward());
	}

	public boolean isSyncEnabled() {
		return syncCheck.isSelected();
	}

	/** Symbol currently displayed (top of history), or null. */
	public String currentSymbol() {
		NativeFunctionView cur = history.current();
		return cur == null ? null : cur.symbol();
	}

	/**
	 * Bring the dialog forward for content that arrived on its own (progress ticks, caret sync,
	 * background results). If the user closed the window this does nothing: analysis keeps running
	 * in the background, but it must not force the window back open on every progress update.
	 *
	 * <p>{@code toFront()} only fires on the hidden -> visible transition, never when the window is
	 * already open: a multi-library pre-warm polls every {@code LOAD_POLL_MS}, and re-raising an
	 * already-visible window on every one of those ticks is exactly the "flickers like a page
	 * refresh" behaviour this is guarding against -- background progress is not a user action, so
	 * it may open the window once but must never keep stealing focus back to it afterwards.
	 */
	private void surface() {
		if (isVisible()) {
			return;
		}
		if (userClosed) {
			return;
		}
		setVisible(true);
		toFront();
	}

	/**
	 * Show the dialog because the user explicitly asked for it (menu action, "Show in Native View",
	 * browsing functions). This clears the "user closed it" state, so background updates may raise
	 * the window again until they close it once more.
	 */
	public void presentForUserAction() {
		onEdt(() -> {
			userClosed = false;
			setVisible(true);
			toFront();
			requestFocus();
		});
	}

	private static void onEdt(Runnable r) {
		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
		} else {
			SwingUtilities.invokeLater(r);
		}
	}

	/**
	 * Paints a translucent scrim + an elevated, shadowed card with an indeterminate spinner and a
	 * kicker/title/subtitle hierarchy over the code tabs while analysis runs, and swallows mouse
	 * input so the dimmed area is inert. Colours come from the theme-derived {@link Palette}.
	 */
	private static final class LockOverlayUI extends LayerUI<JComponent> {

		private boolean locked;
		private String kicker = "";
		private String title = "";
		private String subtitle = "";
		private String detail = "";
		private double spinnerAngle;

		boolean set(boolean locked, String kicker, String title, String subtitle) {
			return set(locked, kicker, title, subtitle, "");
		}

		/**
		 * @param detail a fourth line below the subtitle, e.g. the names of libraries currently
		 *               analyzing. Pass "" (never a placeholder) to omit it -- most overlay states
		 *               (preparing, single-library load) have nothing to put there.
		 * @return whether any of the overlay's visible state actually changed, so callers driven by
		 *         a poll loop (see {@link #showPrewarmProgress}) know whether a repaint is warranted.
		 */
		boolean set(boolean locked, String kicker, String title, String subtitle, String detail) {
			String k = kicker == null ? "" : kicker;
			String t = title == null ? "" : title;
			String s = subtitle == null ? "" : subtitle;
			String d = detail == null ? "" : detail;
			boolean changed = this.locked != locked || !this.kicker.equals(k) || !this.title.equals(t)
					|| !this.subtitle.equals(s) || !this.detail.equals(d);
			this.locked = locked;
			this.kicker = k;
			this.title = t;
			this.subtitle = s;
			this.detail = d;
			return changed;
		}

		/** Advance the indeterminate spinner one animation step. */
		void tick() {
			spinnerAngle = (spinnerAngle + 11) % 360;
		}

		@Override
		public void installUI(JComponent c) {
			super.installUI(c);
			((JLayer<?>) c).setLayerEventMask(AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK);
		}

		@Override
		public void uninstallUI(JComponent c) {
			((JLayer<?>) c).setLayerEventMask(0);
			super.uninstallUI(c);
		}

		@Override
		protected void processMouseEvent(MouseEvent e, JLayer<? extends JComponent> l) {
			if (locked) {
				e.consume(); // the code area is inert while analysis is running
			}
		}

		@Override
		protected void processMouseMotionEvent(MouseEvent e, JLayer<? extends JComponent> l) {
			if (locked) {
				e.consume();
			}
		}

		@Override
		public void paint(Graphics g, JComponent c) {
			super.paint(g, c);
			if (!locked) {
				return;
			}
			Palette p = new Palette();
			Graphics2D g2 = (Graphics2D) g.create();
			try {
				g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
				g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
				int w = c.getWidth();
				int h = c.getHeight();
				g2.setColor(p.scrim);
				g2.fillRect(0, 0, w, h);

				// the names-of-libraries detail line can be much wider than everything else in the
				// card (several "name (size, elapsed)" entries joined together), so the card widens
				// to fit it -- up to the available window space -- rather than clipping silently
				int maxCardW = Math.max(260, w - 48);
				int cardW = Math.min(420, maxCardW);
				Font detailFont = g2.getFont().deriveFont(Font.PLAIN, 12f);
				FontMetrics detailFm = g2.getFontMetrics(detailFont);
				String detailText = detail;
				if (!detailText.isEmpty()) {
					int neededW = detailFm.stringWidth(detailText) + 48; // side padding
					// round up to a coarse step: the detail line carries elapsed-time text that
					// gets re-rendered every poll tick, and its pixel width nudges slightly (or,
					// when the elapsed count crosses a digit boundary, a whole character wider)
					// on almost every tick. Sizing the card to the exact string
					// width would make it visibly resize that often; stepping the width means it
					// only grows when the needed width actually crosses a step, which in practice
					// means "a different library joined/left the analyzing set" rather than "a
					// second ticked over".
					int step = 24;
					neededW = ((neededW + step - 1) / step) * step;
					cardW = Math.min(maxCardW, Math.max(cardW, neededW));
					detailText = truncateToWidth(detailFm, detailText, cardW - 48);
				}
				int cardH = detailText.isEmpty() ? 172 : 194;
				int cx = (w - cardW) / 2;
				int cy = (h - cardH) / 2;

				// soft drop shadow: layered translucent rounded rects beneath the card
				for (int i = 6; i >= 1; i--) {
					g2.setColor(new Color(0, 0, 0, 10 + (6 - i) * 4));
					g2.fillRoundRect(cx - i, cy + i + 3, cardW + i * 2, cardH + i * 2, 24, 24);
				}
				g2.setColor(p.cardBg);
				g2.fillRoundRect(cx, cy, cardW, cardH, 20, 20);
				g2.setColor(p.cardBorder);
				g2.setStroke(new BasicStroke(1f));
				g2.drawRoundRect(cx, cy, cardW, cardH, 20, 20);

				int centerX = w / 2;
				drawSpinner(g2, centerX, cy + 24, 44, p);

				int textTop = cy + 24 + 44 + 24;
				if (!kicker.isEmpty()) {
					g2.setColor(p.accent);
					g2.setFont(g2.getFont().deriveFont(Font.BOLD, 11f));
					drawCentered(g2, kicker, centerX, textTop);
				}
				g2.setColor(p.title);
				g2.setFont(g2.getFont().deriveFont(Font.BOLD, 16f));
				drawCentered(g2, title, centerX, textTop + 22);
				g2.setColor(p.subtitle);
				g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 12f));
				drawCentered(g2, subtitle, centerX, textTop + 42);
				if (!detailText.isEmpty()) {
					g2.setFont(detailFont);
					drawCentered(g2, detailText, centerX, textTop + 62);
				}
			} finally {
				g2.dispose();
			}
		}

		/** Truncates with a trailing "…" so a name/size/elapsed line can never overflow the card. */
		private static String truncateToWidth(FontMetrics fm, String text, int maxWidth) {
			if (fm.stringWidth(text) <= maxWidth) {
				return text;
			}
			String ellipsis = "…";
			int lo = 0;
			int hi = text.length();
			while (lo < hi) {
				int mid = (lo + hi + 1) / 2;
				if (fm.stringWidth(text.substring(0, mid) + ellipsis) <= maxWidth) {
					lo = mid;
				} else {
					hi = mid - 1;
				}
			}
			return text.substring(0, lo) + ellipsis;
		}

		/** Indeterminate spinner: a full faint track plus a rotating accent arc. */
		private void drawSpinner(Graphics2D g2, int centerX, int topY, int size, Palette p) {
			int x = centerX - size / 2;
			g2.setStroke(new BasicStroke(4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
			g2.setColor(p.track);
			g2.drawArc(x, topY, size, size, 0, 360);
			g2.setColor(p.accent);
			g2.drawArc(x, topY, size, size, (int) (90 - spinnerAngle), -110);
		}

		private static void drawCentered(Graphics2D g2, String text, int centerX, int baselineY) {
			if (text == null || text.isEmpty()) {
				return;
			}
			int tw = g2.getFontMetrics().stringWidth(text);
			g2.drawString(text, centerX - tw / 2, baselineY);
		}
	}
}
