package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import com.jexray.jadx.nav.FunctionFilter;

/**
 * Library list plus per-library function tree, shared by the Native View sidebar and the All
 * Functions dialog so both present libraries the same way (and so the behaviour exists once).
 *
 * <p>Each library shows its size and analysis state, because analysis time scales with size and a
 * large library can take an hour -- the user needs to see that before waiting on it, and needs to
 * tell "still working" apart from "stuck". Functions are grouped into JNI entry points and
 * everything else, since entry points are where reversing usually starts.
 *
 * <p>Function children are built only when a library is expanded: a library can hold tens of
 * thousands, and there is no reason to build nodes for libraries the user never opens. The bottom
 * count label is the exception -- it totals filter matches across every READY library up front
 * (via {@link MatchCounter}, debounced), because a total that only counts libraries the user
 * happened to expand already is indistinguishable from a genuine zero and is
 * actively misleading rather than merely incomplete.
 */
public class LibraryTreePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	/** JNI entry points follow the {@code Java_pkg_Class_method} mangling. */
	private static final String JNI_PREFIX = "Java_";

	/** Quiet period before a filter edit turns into bridge queries, so a burst of keystrokes
	 * (typing "app") issues one batch of per-library counts instead of one batch per character. */
	private static final int COUNT_DEBOUNCE_MS = 250;

	private final BiConsumer<String, String> onPickFunction; // (soId, function name)
	private final Consumer<String> onLibraryChosen; // ask the owner to load this library
	// right-click "Re-analyze": discard this library's cache and re-run Ghidra on it. Null in
	// callers that don't offer it (kept optional so existing constructions aren't forced to wire
	// it up just to keep compiling).
	private final Consumer<String> onForceReanalyze;
	// counts filter matches for a library whose function list isn't loaded yet. Null in callers
	// that don't offer it (tests, and any future caller that doesn't have a bridge handy) -- such
	// libraries simply can't contribute to the total, same as one that isn't READY.
	private final MatchCounter matchCounter;

	private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("libraries");
	private final DefaultTreeModel model = new DefaultTreeModel(root);
	private final JTree tree = new JTree(model);
	private final JTextField filterField = new JTextField();
	private final JLabel countLabel = new JLabel();
	private final DebounceScheduler countDebounce;

	private final Map<String, LibraryEntry> libraries = new LinkedHashMap<>();
	private final Map<String, List<String>> functionsBySoId = new LinkedHashMap<>();

	/**
	 * Per library, the listed names that hold no body here -- imported from another library. They
	 * are shown so a library's dependencies are visible, but rendered apart from the functions you
	 * can actually open. Populated separately from {@link #setFunctions} so callers and tests that
	 * do not care keep working unchanged; a library with no entry simply marks nothing.
	 */
	private final Map<String, Set<String>> externalsBySoId = new LinkedHashMap<>();

	/**
	 * Per library, the listed names it publishes in its dynamic symbol table -- what another
	 * library or a {@code dlsym} call can reach. Populated separately from {@link #setFunctions}
	 * for the same reason {@link #externalsBySoId} is; a library with no entry simply groups
	 * everything defined under "Functions", as before.
	 */
	private final Map<String, Set<String>> exportsBySoId = new LinkedHashMap<>();

	/**
	 * Per library, the functions bound to a Java method by {@code RegisterNatives} rather than by
	 * name. They are entry points but carry no naming convention -- an obfuscated app registers
	 * them precisely so they cannot be found by name -- so nothing about the name reveals what they
	 * are, and only the registration table does.
	 */
	private final Map<String, Set<String>> registeredBySoId = new LinkedHashMap<>();

	// per-library "does it match the current filter" state, so a COLLAPSED library (never expanded,
	// so functionsBySoId has no entry for it) can still bold once its match is known -- reuses
	// exactly the count machinery recomputeTotal() already runs for the bottom total, instead of a
	// second match test. Populated instantly for a library already loaded locally, and
	// asynchronously as each MatchCounter result lands (see onLibraryCounted). Cleared at the start
	// of every recomputeTotal pass so a stale entry from a superseded query can never bold the wrong
	// library; a soId simply absent here means "not yet known" (still counting, not READY, or no
	// MatchCounter available) and must never be treated as a match -- see isMatchingCategoryNode.
	private final Map<String, Boolean> matchBySoId = new LinkedHashMap<>();

	// state for the in-flight eager total count; countEpoch identifies which run a pending async
	// result belongs to, so a result from a query the user has since changed away from (superseded)
	// is recognized and dropped instead of overwriting a newer, more correct total.
	private long countEpoch;
	private int countPendingRemaining;
	private int countAccumMatches;
	private int countAccumTotal;
	private int countAccumUncountable;

	/**
	 * Counts, off the EDT, how many of one library's already-analyzed functions match a substring
	 * query -- lets the panel total filter matches across every READY library without pulling each
	 * one's full function list to the client (a large library can hold hundreds of thousands). The
	 * bridge already does this filtering server-side ({@code GET /so/{soId}/search?query=}), so
	 * only the matching names cross the wire rather than the whole list, and the count is taken
	 * from that response's size.
	 */
	public interface MatchCounter {
		/**
		 * Reports the match count for {@code soId} at {@code query} by calling {@code onResult}
		 * exactly once with a non-negative count, from any thread -- implementations do the actual
		 * work (an HTTP call) off the caller's thread; the panel hops back to the EDT itself before
		 * touching any Swing state. On failure, call nothing: a silently-dropped count leaves the
		 * label honestly stuck at "counting…" for that query, which is a true statement, whereas
		 * reporting zero on failure would be exactly the fabricated-zero bug this exists to fix.
		 */
		void count(String soId, String query, IntConsumer onResult);
	}

	/**
	 * Seam behind the eager-count debounce: production schedules {@link #recomputeTotal()} on a
	 * real, cancellable delay ({@link SwingTimerDebounceScheduler}).
	 *
	 * <p>Package-private (not private) so {@link LoadedLibrariesPanel} can debounce its own bottom
	 * count label the same way, instead of a second copy of this same Timer-wrapping seam -- its
	 * eager count has the identical "quiet period, then recompute" shape, just over a different
	 * data source (a symbol-table read instead of a bridge match count).
	 */
	interface DebounceScheduler {
		/** (Re)schedule a firing after the debounce delay, discarding whatever was scheduled and
		 * not yet run. */
		void restart();

		/** Cancel whatever is scheduled, if anything, without running it. */
		void stop();
	}

	/** The real debounce: a {@link Timer} that fires {@code task} once, {@value #COUNT_DEBOUNCE_MS}ms
	 * after the most recent {@link #restart()}. Package-private -- see {@link DebounceScheduler}. */
	static final class SwingTimerDebounceScheduler implements DebounceScheduler {
		private final Timer timer;

		SwingTimerDebounceScheduler(int delayMs, Runnable task) {
			timer = new Timer(delayMs, e -> task.run());
			timer.setRepeats(false);
		}

		@Override
		public void restart() {
			timer.restart();
		}

		@Override
		public void stop() {
			timer.stop();
		}
	}

	public LibraryTreePanel(BiConsumer<String, String> onPickFunction, Consumer<String> onLibraryChosen) {
		this(onPickFunction, onLibraryChosen, null, null);
	}

	public LibraryTreePanel(BiConsumer<String, String> onPickFunction, Consumer<String> onLibraryChosen,
			Consumer<String> onForceReanalyze) {
		this(onPickFunction, onLibraryChosen, onForceReanalyze, null);
	}

	public LibraryTreePanel(BiConsumer<String, String> onPickFunction, Consumer<String> onLibraryChosen,
			Consumer<String> onForceReanalyze, MatchCounter matchCounter) {
		this(onPickFunction, onLibraryChosen, onForceReanalyze, matchCounter, null);
	}

	private LibraryTreePanel(BiConsumer<String, String> onPickFunction, Consumer<String> onLibraryChosen,
			Consumer<String> onForceReanalyze, MatchCounter matchCounter, DebounceScheduler scheduler) {
		super(new BorderLayout(0, 4));
		this.onPickFunction = onPickFunction;
		this.onLibraryChosen = onLibraryChosen;
		this.onForceReanalyze = onForceReanalyze;
		this.matchCounter = matchCounter;
		this.countDebounce = scheduler != null ? scheduler
				: new SwingTimerDebounceScheduler(COUNT_DEBOUNCE_MS, this::recomputeTotal);

		tree.setRootVisible(false);
		tree.setShowsRootHandles(true);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		// libraries render as "name  size · state", not the record's toString; while a filter is
		// active, the library and its JNI methods/Functions groups render bold when their subtree
		// actually has a match (see isMatchingCategoryNode) so the user can see at a glance which
		// categories have hits without expanding every one; a library CONFIRMED to have zero matches
		// dims instead (see matchStateFor), so the libraries worth looking at stand out from the ones
		// that were actually checked and came up empty -- but never from one that merely hasn't been
		// checked yet, which stays normal (see the MatchState javadoc); and a matching function leaf
		// highlights the exact matched span (see highlightMatch) so the user can see WHERE it matched
		tree.setCellRenderer(new javax.swing.tree.DefaultTreeCellRenderer() {
			private static final long serialVersionUID = 1L;

			@Override
			public java.awt.Component getTreeCellRendererComponent(JTree t, Object value, boolean sel,
					boolean expanded, boolean leaf, int row, boolean focus) {
				Object shown = value;
				boolean bold = false;
				boolean dim = false;
				String query = filterField.getText();
				if (value instanceof DefaultMutableTreeNode n) {
					if (n.getUserObject() instanceof LibraryEntry lib) {
						shown = libraryLabel(lib);
						dim = !query.isEmpty() && matchStateFor(lib, query) == MatchState.ZERO;
					} else if (leaf && n.getUserObject() instanceof String name && isFunctionNameLeaf(n)) {
						String highlighted = highlightMatch(name, query);
						if (highlighted != null) {
							shown = highlighted;
						}
					}
					bold = isMatchingCategoryNode(n, query);
				}
				java.awt.Component c = super.getTreeCellRendererComponent(t, shown, sel, expanded, leaf, row, focus);
				// the renderer component is reused across rows -- every row must set its own font
				// (not just the bold case), or a plain row rendered right after a bold one would
				// silently inherit that stale bold font. Built as a fresh plain Font rather than via
				// c.getFont().deriveFont(style): on Aqua (macOS), the tree's font is a "live"
				// UIResource (AquaFonts$DerivedUIResourceFont) tied to the system control font, and
				// its deriveFont(style) silently ignores the requested style and returns another
				// plain live font -- so the style change never actually takes effect.
				c.setFont(new Font(c.getFont().getName(), bold ? Font.BOLD : Font.PLAIN, c.getFont().getSize()));
				// same reuse trap as the font above, for foreground: every row must set its own,
				// explicitly, or a plain row right after a dimmed one would inherit the dim color.
				// Selected rows keep the selection foreground regardless of dim, matching how a
				// selection highlight already overrides bold/plain elsewhere in this tree.
				c.setForeground(sel ? getTextSelectionColor() : dim ? dimForeground() : getTextNonSelectionColor());
				return c;
			}
		});

		tree.addTreeWillExpandListener(new javax.swing.event.TreeWillExpandListener() {
			@Override
			public void treeWillExpand(javax.swing.event.TreeExpansionEvent e) {
				Object last = e.getPath().getLastPathComponent();
				if (last instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof LibraryEntry lib) {
					// populate on demand, and ask the owner to analyze it if we have nothing yet
					if (!functionsBySoId.containsKey(lib.soId()) && onLibraryChosen != null) {
						onLibraryChosen.accept(lib.soId());
					}
					rebuildChildren(n, lib);
				}
			}

			@Override
			public void treeWillCollapse(javax.swing.event.TreeExpansionEvent e) {
				// nothing to do
			}
		});

		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					firePick();
				}
			}

			@Override
			public void mousePressed(MouseEvent e) {
				maybeShowContextMenu(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeShowContextMenu(e);
			}
		});
		tree.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					firePick();
				}
			}
		});

		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				rebuild();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				rebuild();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				rebuild();
			}
		});

		JPanel filterRow = new JPanel(new BorderLayout(4, 0));
		filterRow.setBorder(new EmptyBorder(2, 2, 2, 2));
		filterRow.add(new JLabel("Filter:"), BorderLayout.WEST);
		filterRow.add(filterField, BorderLayout.CENTER);

		JPanel bottom = new JPanel(new BorderLayout());
		bottom.setBorder(new EmptyBorder(2, 4, 2, 4));
		bottom.add(countLabel, BorderLayout.WEST);

		// filter goes up top where the user reaches for it first; the count label stays at the
		// bottom -- it's status-bar-like, not something to type into, and pairing it with the
		// filter up top would make the header two rows thick
		add(filterRow, BorderLayout.NORTH);
		add(new JScrollPane(tree), BorderLayout.CENTER);
		add(bottom, BorderLayout.SOUTH);
	}

	/**
	 * The label for one library node, filter-aware. While a query is active and this library's
	 * function list is already loaded, shows "shown / total" so it agrees with the filtered child
	 * group directly below it instead of stating the library's plain total next to a narrower list.
	 * Falls back to the plain total when there is no filter, the library isn't READY, or its
	 * function list hasn't been loaded yet -- filtering an unloaded list would report a fabricated
	 * zero rather than "not checked".
	 *
	 * <p>Both "shown" and "total" are read from the same cached {@code names} list -- never
	 * {@code lib.functionCount()} (the bridge's separately-reported total) -- so the pair can never
	 * disagree with each other, even if the cache and the bridge count happen to differ.
	 */
	private String libraryLabel(LibraryEntry lib) {
		long now = System.currentTimeMillis();
		String query = filterField.getText();
		List<String> names = functionsBySoId.get(lib.soId());
		if (query.isEmpty() || lib.status() != LibraryEntry.Status.READY || names == null) {
			return lib.label(now);
		}
		return lib.filteredLabel(now, filtered(names, query).size(), names.size());
	}

	/** Replace the library list (size/status changes come through here too). */
	public void setLibraries(List<LibraryEntry> entries) {
		libraries.clear();
		if (entries != null) {
			for (LibraryEntry e : entries) {
				libraries.put(e.soId(), e);
			}
		}
		rebuild();
	}

	/** Supply the function names for one library; shown when that library is expanded. */
	/** Mark which of {@code soId}'s listed names are linked in rather than defined here. */
	public void setExternalNames(String soId, Set<String> names) {
		externalsBySoId.put(soId, names == null ? Set.of() : new java.util.HashSet<>(names));
	}

	/** Mark which of {@code soId}'s listed names it publishes for others to link against. */
	public void setExportedNames(String soId, Set<String> names) {
		exportsBySoId.put(soId, names == null ? Set.of() : new java.util.HashSet<>(names));
	}

	/** Mark which of {@code soId}'s listed names are bound to a Java method by registration. */
	public void setRegisteredNativeNames(String soId, Set<String> names) {
		registeredBySoId.put(soId, names == null ? Set.of() : new java.util.HashSet<>(names));
	}

	public void setFunctions(String soId, List<String> names) {
		functionsBySoId.put(soId, names == null ? List.of() : new ArrayList<>(names));
		rebuild();
	}

	/** The library currently selected (or the one owning the selected function), else null. */
	public String selectedSoId() {
		TreePath path = tree.getSelectionPath();
		if (path == null) {
			return null;
		}
		for (int i = path.getPathCount() - 1; i >= 0; i--) {
			Object o = path.getPathComponent(i);
			if (o instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof LibraryEntry lib) {
				return lib.soId();
			}
		}
		return null;
	}

	private void rebuild() {
		// remember what was open so a status refresh -- or narrowing the filter -- doesn't collapse
		// the user's view. Groups are tracked too, not just libraries: otherwise narrowing a filter
		// query by one more character would rebuild an already-open "Functions" group back to
		// collapsed and the user would have to reopen it every keystroke.
		List<String> expanded = expandedSoIds();
		java.util.Set<String> expandedGroups = expandedGroupKeys();
		String selected = selectedSoId();

		root.removeAllChildren();
		String query = filterField.getText();
		for (LibraryEntry lib : libraries.values()) {
			DefaultMutableTreeNode node = new DefaultMutableTreeNode(lib);
			node.add(new DefaultMutableTreeNode("…")); // placeholder; real children on expand
			root.add(node);
		}
		model.reload();

		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
			LibraryEntry lib = (LibraryEntry) n.getUserObject();
			// keep previously-open libraries open, and open any library that matches the filter
			if (expanded.contains(lib.soId()) || (!query.isEmpty() && !filtered(functionsBySoId.get(lib.soId()), query).isEmpty())) {
				rebuildChildren(n, lib);
				tree.expandPath(new TreePath(new Object[] { root, n }));
				// re-open the groups ("JNI methods"/"Functions"/"Imports") that were open, keyed by
				// title (the count in the label changes as the filter narrows, the title doesn't)
				for (int j = 0; j < n.getChildCount(); j++) {
					DefaultMutableTreeNode grp = (DefaultMutableTreeNode) n.getChildAt(j);
					if (grp.getUserObject() instanceof String s
							&& expandedGroups.contains(lib.soId() + GROUP_KEY_SEP + groupTitle(s))) {
						tree.expandPath(new TreePath(new Object[] { root, n, grp }));
					}
				}
			}
			if (lib.soId().equals(selected)) {
				tree.setSelectionPath(new TreePath(new Object[] { root, n }));
			}
		}
		// the bottom count label totals matches across EVERY library, not just the ones rebuilt
		// above (that set is only what's already loaded) -- see scheduleCountUpdate.
		scheduleCountUpdate();
	}

	/**
	 * Debounces the eager total-match count: a filter edit (or a library-state refresh while a
	 * filter is active) restarts a quiet-period timer instead of counting immediately, so a burst
	 * of keystrokes settles into one batch of per-library queries rather than one batch per
	 * keystroke. An empty query needs no counting at all -- "N libraries" is already exact -- so
	 * that case is handled immediately and also cancels any count still in flight for the query
	 * just abandoned.
	 */
	private void scheduleCountUpdate() {
		if (filterField.getText().trim().isEmpty()) {
			countDebounce.stop();
			countEpoch++; // invalidate any pending async results; nothing to count now
			countLabel.setText(libraries.size() + " libraries");
			return;
		}
		countDebounce.restart();
	}

	/**
	 * Runs once the filter has been quiet for {@link #COUNT_DEBOUNCE_MS}. Totals matches across
	 * every READY library: already-loaded libraries are counted locally for free (same source,
	 * same case-insensitive match as the per-library label uses -- see {@link #libraryLabel}); a
	 * READY library that isn't loaded yet asks {@link #matchCounter}, off the EDT. A library that
	 * isn't READY (or whose reported total is unknown) cannot be counted at all and is called out
	 * by name count in the final label rather than silently dropped, which would make a partial
	 * total look complete.
	 *
	 * <p>Every library that needs {@link #matchCounter} is collected into {@code toQuery} first, and
	 * only queried in a second pass, after {@code countPendingRemaining} and the accumulator fields
	 * are already set for {@code myEpoch}. A {@link MatchCounter} is free to answer from the calling
	 * thread before {@code count()} even returns (as the real, off-EDT implementation can, and as
	 * tests deliberately do to stay deterministic) -- querying inline in the same pass that computes
	 * {@code pending} would let such an answer's {@link #onLibraryCounted} run on the EDT and touch
	 * those fields while this method is still partway through initializing them.
	 */
	private void recomputeTotal() {
		String query = filterField.getText().trim();
		// this pass (or, for an empty query, the fact that there is nothing to count) supersedes
		// whatever the last pass recorded -- discard it now rather than let a stale entry outlive
		// its query and bold the wrong collapsed library (see matchBySoId).
		matchBySoId.clear();
		if (query.isEmpty()) {
			countLabel.setText(libraries.size() + " libraries");
			return;
		}
		long myEpoch = ++countEpoch;
		int matches = 0;
		int total = 0;
		int uncountable = 0;
		List<String> toQuery = new ArrayList<>();
		for (LibraryEntry lib : libraries.values()) {
			if (lib.status() != LibraryEntry.Status.READY || lib.functionCount() < 0) {
				uncountable++;
				continue;
			}
			List<String> names = functionsBySoId.get(lib.soId());
			if (names != null) {
				int libMatches = filtered(names, query).size();
				total += names.size();
				matches += libMatches;
				matchBySoId.put(lib.soId(), libMatches > 0);
				continue;
			}
			if (matchCounter == null) {
				// nothing to ask and no local list either -- can't count this one
				uncountable++;
				continue;
			}
			total += lib.functionCount();
			toQuery.add(lib.soId());
		}
		if (toQuery.isEmpty()) {
			finishCount(myEpoch, matches, total, uncountable);
			return;
		}
		countAccumMatches = matches;
		countAccumTotal = total;
		countAccumUncountable = uncountable;
		countPendingRemaining = toQuery.size();
		// never show a number that isn't fully established yet -- not even a partial sum, since
		// that reads as final. A zero shown while still counting is the exact bug this replaces.
		countLabel.setText("counting…");
		for (String soId : toQuery) {
			matchCounter.count(soId, query, n -> SwingUtilities.invokeLater(() -> onLibraryCounted(myEpoch, soId, n)));
		}
	}

	/** One pending {@link MatchCounter} result has landed, already on the EDT. */
	private void onLibraryCounted(long epoch, String soId, int matchCount) {
		if (epoch != countEpoch) {
			return; // superseded by a newer query; this result is stale
		}
		// record this library's match state and repaint right away -- a collapsed library should
		// bold the moment ITS count arrives, not wait for every other library's count to land too
		// (which is what waiting for finishCount below would mean).
		matchBySoId.put(soId, matchCount > 0);
		tree.repaint();
		countAccumMatches += matchCount;
		countPendingRemaining--;
		if (countPendingRemaining == 0) {
			finishCount(epoch, countAccumMatches, countAccumTotal, countAccumUncountable);
		}
	}

	private void finishCount(long epoch, int matches, int total, int uncountableLibs) {
		if (epoch != countEpoch) {
			return; // superseded while this result was landing
		}
		String base = matches + " / " + total + " functions";
		countLabel.setText(uncountableLibs == 0 ? base
				: base + " (" + uncountableLibs + " librar" + (uncountableLibs == 1 ? "y" : "ies") + " not yet analyzed)");
	}

	private void rebuildChildren(DefaultMutableTreeNode node, LibraryEntry lib) {
		node.removeAllChildren();
		List<String> names = filtered(functionsBySoId.get(lib.soId()), filterField.getText());
		if (names.isEmpty()) {
			node.add(new DefaultMutableTreeNode(placeholderFor(lib)));
			model.nodeStructureChanged(node);
			return;
		}
		// Grouped by what the entry is in linkage terms rather than by how it reads, so each group
		// answers a different question: which entry points Java can bind to, which functions are
		// internal to this library, which surface it publishes for anything else to call, and what
		// it links against but does not contain. Structure says it -- no styling to notice or miss.
		//
		// JNI methods are exported too, so they are claimed first and "Exports" means the rest of
		// the published surface; otherwise the two groups would overlap.
		//
		// "JNI method" is membership, not spelling: a function registered through RegisterNatives is
		// an entry point whatever it is called, and an app that hides its entry points chooses
		// exactly that route. Grouping it by the registration table rather than by name is the whole
		// point -- otherwise it sits anonymously among thousands of others.
		Set<String> external = externalsBySoId.getOrDefault(lib.soId(), Set.of());
		Set<String> exported = exportsBySoId.getOrDefault(lib.soId(), Set.of());
		Set<String> registered = registeredBySoId.getOrDefault(lib.soId(), Set.of());
		List<String> jni = new ArrayList<>();
		List<String> internal = new ArrayList<>();
		List<String> exports = new ArrayList<>();
		List<String> imports = new ArrayList<>();
		for (String n : names) {
			if (external.contains(n)) {
				imports.add(n);
			} else if (isJniEntryPoint(n) || registered.contains(n)) {
				jni.add(n);
			} else if (exported.contains(n)) {
				exports.add(n);
			} else {
				internal.add(n);
			}
		}
		if (!jni.isEmpty()) {
			node.add(group("JNI methods", jni));
		}
		if (!internal.isEmpty()) {
			node.add(group("Functions", internal));
		}
		if (!exports.isEmpty()) {
			node.add(group("Exports", exports));
		}
		if (!imports.isEmpty()) {
			node.add(group("Imports", imports));
		}
		model.nodeStructureChanged(node);
	}

	private static String placeholderFor(LibraryEntry lib) {
		return switch (lib.status()) {
			case ANALYZING -> "(analyzing…)";
			case QUEUED -> "(queued)";
			case FAILED -> "(analysis failed)";
			case NOT_ANALYZED -> "(not analyzed)";
			case READY -> "(no matching functions)";
		};
	}

	private static DefaultMutableTreeNode group(String title, List<String> names) {
		DefaultMutableTreeNode g = new DefaultMutableTreeNode(title + " (" + names.size() + ")");
		for (String n : names) {
			g.add(new DefaultMutableTreeNode(n));
		}
		return g;
	}

	/** A JNI entry point is one Java can bind to directly by name. */
	static boolean isJniEntryPoint(String name) {
		if (name == null) {
			return false;
		}
		// some toolchains prefix an underscore on the exported symbol
		String n = name.startsWith("_") ? name.substring(1) : name;
		return n.startsWith(JNI_PREFIX);
	}

	private static List<String> filtered(List<String> names, String query) {
		if (names == null) {
			return List.of();
		}
		return FunctionFilter.filter(names, query);
	}

	/**
	 * True for a "category" node -- a library, or one of its JNI methods/Functions groups -- whose
	 * subtree contains at least one filter match, so the renderer can bold it without a second,
	 * separate match test that could disagree with what the tree actually shows.
	 *
	 * <p>A group node ("JNI methods (n)", "Functions (n)", "Imports (n)") only ever exists once
	 * {@link #rebuildChildren} has already narrowed its children down to matches (an empty result
	 * gets a plain placeholder instead, never an empty group) -- so under an active filter, a group
	 * node's mere presence already proves it contains a match. A library node instead consults
	 * {@link #matchStateFor}, which is true exactly for {@link MatchState#MATCH}.
	 */
	private boolean isMatchingCategoryNode(DefaultMutableTreeNode n, String query) {
		if (query.isEmpty()) {
			return false;
		}
		Object obj = n.getUserObject();
		if (obj instanceof LibraryEntry lib) {
			return matchStateFor(lib, query) == MatchState.MATCH;
		}
		// the only non-leaf String nodes in this tree are the group headers above
		return obj instanceof String && !n.isLeaf();
	}

	/**
	 * Whether a library, under the given (non-empty) query, is known to MATCH, known to be a
	 * confirmed ZERO, or UNKNOWN because it hasn't been (or couldn't be) checked at all. The
	 * distinction between ZERO and UNKNOWN is the entire point: a library the count machinery never
	 * got an answer for (not READY, an unknown total, no {@link MatchCounter}, or an async count
	 * still in flight) must render exactly like one with no filter applied -- dimming it would say
	 * "checked, nothing here" about a library that was simply never checked, the same fabricated-zero
	 * failure the bottom count label's "not yet analyzed" callout already exists to avoid.
	 */
	private enum MatchState {
		MATCH, ZERO, UNKNOWN
	}

	private MatchState matchStateFor(LibraryEntry lib, String query) {
		List<String> names = functionsBySoId.get(lib.soId());
		if (names != null) {
			return filtered(names, query).isEmpty() ? MatchState.ZERO : MatchState.MATCH;
		}
		Boolean known = matchBySoId.get(lib.soId());
		if (known == null) {
			return MatchState.UNKNOWN;
		}
		return known ? MatchState.MATCH : MatchState.ZERO;
	}

	/** A theme-appropriate "dimmed" text color -- derived from the current look-and-feel's disabled
	 * label color rather than a hardcoded gray, so it reads as dimmed against both a light and a
	 * dark background instead of vanishing (a fixed light gray) or barely dimming (a fixed dark
	 * gray) depending on which one is active. */
	private static java.awt.Color dimForeground() {
		java.awt.Color c = javax.swing.UIManager.getColor("Label.disabledForeground");
		return c != null ? c : java.awt.Color.GRAY;
	}

	/**
	 * True for a leaf that is an actual function name (as opposed to a placeholder like
	 * "(analyzing…)" or "(no matching functions)", which is also a leaf {@link String} node).
	 * Distinguished structurally, not by sniffing the text: a function name's parent is always a
	 * group header -- itself a {@link String} node, see {@link #group} --
	 * whereas a placeholder is added directly under the {@link LibraryEntry} node it stands in for
	 * (see {@link #rebuildChildren}) -- so this can never mistake one for the other regardless of
	 * what a real symbol happens to be named. Package-visible: {@link LoadedLibrariesPanel} builds
	 * its function leaves the same way (see its {@code group}) and reuses this rather than
	 * duplicating the structural check, the same way it already reuses {@link #isJniEntryPoint}.
	 */
	static boolean isFunctionNameLeaf(DefaultMutableTreeNode n) {
		return n.getParent() instanceof DefaultMutableTreeNode p && p.getUserObject() instanceof String;
	}

	/**
	 * Builds an HTML label with the first matched span emphasized, using the exact same
	 * trim-then-case-insensitive-contains semantics {@link FunctionFilter#filter} already uses to
	 * decide leaf inclusion -- so what's highlighted is exactly what caused the leaf to survive
	 * filtering, never a second guess that could disagree. Returns null (render plain) when the
	 * query is blank or genuinely doesn't match, so a stale/mismatched filter never leaves a
	 * highlight behind. Only the first occurrence is highlighted when the query appears more than
	 * once -- enough to show WHERE it matched without multi-span bookkeeping.
	 *
	 * <p>{@code name} is HTML-escaped before the {@code <b>} span is spliced in by index, so a
	 * symbol containing {@code &}, {@code <}, or {@code >} still renders as literal text instead of
	 * breaking the label. Package-visible so {@link LoadedLibrariesPanel} can reuse it for its own
	 * function leaves instead of duplicating the escaping/splicing logic.
	 */
	static String highlightMatch(String name, String query) {
		String q = query == null ? "" : query.trim().toLowerCase(java.util.Locale.ROOT);
		if (q.isEmpty()) {
			return null;
		}
		int idx = name.toLowerCase(java.util.Locale.ROOT).indexOf(q);
		if (idx < 0) {
			return null;
		}
		String before = escapeHtml(name.substring(0, idx));
		String match = escapeHtml(name.substring(idx, idx + q.length()));
		String after = escapeHtml(name.substring(idx + q.length()));
		return "<html>" + before + "<b>" + match + "</b>" + after + "</html>";
	}

	private static String escapeHtml(String s) {
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

	private List<String> expandedSoIds() {
		List<String> open = new ArrayList<>();
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
			if (n.getUserObject() instanceof LibraryEntry lib
					&& tree.isExpanded(new TreePath(new Object[] { root, n }))) {
				open.add(lib.soId());
			}
		}
		return open;
	}

	/** Separates a library soId from a group title in an expansion key; NUL never appears in either. */
	private static final String GROUP_KEY_SEP = "\u0000";

	/**
	 * Keys ({@code soId + NUL + groupTitle}) for every currently-open function group, so
	 * {@link #rebuild()} can re-open the same groups afterwards. Keyed by title, not the full label,
	 * because the label's count changes as the filter narrows ("Functions (3)" -> "Functions (1)").
	 */
	private java.util.Set<String> expandedGroupKeys() {
		java.util.Set<String> keys = new java.util.HashSet<>();
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode lib = (DefaultMutableTreeNode) root.getChildAt(i);
			if (!(lib.getUserObject() instanceof LibraryEntry le)
					|| !tree.isExpanded(new TreePath(new Object[] { root, lib }))) {
				continue;
			}
			for (int j = 0; j < lib.getChildCount(); j++) {
				DefaultMutableTreeNode grp = (DefaultMutableTreeNode) lib.getChildAt(j);
				if (grp.getUserObject() instanceof String s
						&& tree.isExpanded(new TreePath(new Object[] { root, lib, grp }))) {
					keys.add(le.soId() + GROUP_KEY_SEP + groupTitle(s));
				}
			}
		}
		return keys;
	}

	/** "Imports (5)" -> "Imports": the stable part of a group label, without its match count. */
	private static String groupTitle(String label) {
		int p = label.lastIndexOf(" (");
		return p < 0 ? label : label.substring(0, p);
	}

	/**
	 * Right-click on a library node: offer "Re-analyze" -- force-discard this library's cache and
	 * re-run Ghidra on it. Only shown over a library node, since the action
	 * applies to a whole library, not an individual function or group header. Only enabled once
	 * the library has something to discard (READY or FAILED); re-analyzing something that is
	 * already queued/analyzing, or was never analyzed, is meaningless or redundant.
	 */
	private void maybeShowContextMenu(MouseEvent e) {
		if (!e.isPopupTrigger() || onForceReanalyze == null) {
			return;
		}
		TreePath path = tree.getPathForLocation(e.getX(), e.getY());
		if (path == null) {
			return;
		}
		Object last = path.getLastPathComponent();
		if (!(last instanceof DefaultMutableTreeNode n) || !(n.getUserObject() instanceof LibraryEntry lib)) {
			return;
		}
		tree.setSelectionPath(path);
		boolean canReanalyze = lib.status() == LibraryEntry.Status.READY
				|| lib.status() == LibraryEntry.Status.FAILED;
		JMenuItem reanalyze = new JMenuItem("Re-analyze (discard cache)");
		reanalyze.setEnabled(canReanalyze);
		if (!canReanalyze) {
			reanalyze.setToolTipText("Available once this library's analysis has finished (or failed)");
		}
		reanalyze.addActionListener(a -> onForceReanalyze.accept(lib.soId()));
		JPopupMenu menu = new JPopupMenu();
		menu.add(reanalyze);
		menu.show(tree, e.getX(), e.getY());
	}

	private void firePick() {
		TreePath path = tree.getSelectionPath();
		if (path == null || onPickFunction == null) {
			return;
		}
		Object last = path.getLastPathComponent();
		if (!(last instanceof DefaultMutableTreeNode n) || !(n.getUserObject() instanceof String name)) {
			return;
		}
		if (n.getChildCount() > 0 || name.startsWith("(") || name.endsWith(")")) {
			return; // a group header or placeholder, not a function
		}
		String soId = selectedSoId();
		if (soId != null) {
			onPickFunction.accept(soId, name);
		}
	}

	/** Focus the filter box (called when the panel is surfaced). */
	public void focusFilter() {
		filterField.requestFocusInWindow();
	}

}
