package com.jexray.jadx.ui;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeWillExpandListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import jadx.api.metadata.ICodeNodeRef;

import com.jexray.jadx.LoadLibraryDetector.Kind;
import com.jexray.jadx.apk.LoadedLibrariesModel.LoadSite;
import com.jexray.jadx.apk.LoadedLibrariesModel.ResolvedLibrary;
import com.jexray.jadx.apk.LoadedLibrariesModel.Result;
import com.jexray.jadx.apk.LoadedLibrariesModel.UnloadedLibrary;
import com.jexray.jadx.apk.LoadedLibrariesModel.UnresolvedCall;
import com.jexray.jadx.nav.FunctionFilter;
import com.jexray.jadx.util.HumanFormat;

/**
 * Tree for the "Loaded Libraries" window: which native libraries the app asks the VM to load
 * (via {@code System.loadLibrary}/{@code load}), what each resolves to in the APK, and its
 * exported functions -- alongside the two things detection can never fully account for, shown
 * with equal visibility rather than folded away:
 * <ul>
 *   <li>a load call whose argument isn't a string literal (obfuscated/computed) -- real, but
 *       unnameable from here;</li>
 *   <li>a .so present in the input that no detected call site loads (dead weight, or reached only
 *       via reflection / a native {@code JNI_OnLoad} registrar this pass can't see).</li>
 * </ul>
 *
 * <p>Function lists come from {@link com.jexray.jadx.symbols.NativeSymbols} (the ELF/Mach-O
 * symbol table read directly, no Ghidra), and are populated lazily on expand, same rationale as
 * {@link LibraryTreePanel}: a library can export thousands of symbols and there's no reason to
 * build nodes for one the user never opens.
 */
public class LoadedLibrariesPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	/** Same quiet-period as {@link LibraryTreePanel}'s eager count -- a burst of filter keystrokes
	 * should settle into one batch of per-library symbol reads, not one batch per character. */
	private static final int COUNT_DEBOUNCE_MS = 250;

	private final Consumer<ICodeNodeRef> onNavigate; // jump to a load site's Java source
	private final Consumer<String> onLibraryExpanded; // ask the owner to read this soId's symbols
	// reads a library's exported function names for the bottom count label, for a library not
	// already cached in functionsBySoId. Null in callers/tests that don't offer it -- such a
	// library simply can't contribute to the total, same as one that isn't in the APK.
	private final FunctionReader functionReader;

	private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("loaded libraries");
	private final DefaultTreeModel model = new DefaultTreeModel(root);
	private final JTree tree = new JTree(model);
	private final JTextField filterField = new JTextField();
	private final JLabel countLabel = new JLabel();
	private final LibraryTreePanel.DebounceScheduler countDebounce;

	private Result result = new Result(List.of(), List.of(), List.of());
	private final java.util.Map<String, List<String>> functionsBySoId = new java.util.LinkedHashMap<>();

	// state for the in-flight eager function count; countEpoch identifies which recompute pass a
	// pending async read belongs to, so a read that lands after the user has since changed the
	// filter (superseded) is recognized and dropped instead of overwriting a newer, more correct
	// total -- same guard LibraryTreePanel.recomputeTotal uses for its own async matchCounter calls.
	private long countEpoch;
	private int countPendingRemaining;
	private int countAccumMatches;
	private int countAccumTotal;
	private int countAccumUncountable;

	/**
	 * Reads {@code soId}'s exported function names off the EDT, for the bottom count label to
	 * total a library it hasn't already cached (see {@link #setFunctions}) -- the Loaded
	 * Libraries analog of {@link LibraryTreePanel.MatchCounter}. A separate interface rather than
	 * reusing that one: {@code MatchCounter} asks a Ghidra-bridge server to both filter AND count
	 * in one round trip, but there is no such server-side search here -- a resolved library's
	 * function total isn't known ahead of time the way {@code LibraryEntry.functionCount()} is
	 * (reported by the bridge up front), so the only way to learn a library's total, let alone how
	 * many match, is to actually read its symbol table (see
	 * {@link com.jexray.jadx.symbols.NativeSymbols#exportedSymbols}) and filter the result
	 * client-side with the exact same {@link FunctionFilter} the tree already uses.
	 */
	public interface FunctionReader {
		/**
		 * Reports {@code soId}'s exported function names by calling {@code onResult} exactly once,
		 * from any thread -- implementations do the actual read (real disk I/O for a possibly
		 * large .so) off the caller's thread; the panel hops back to the EDT itself before
		 * touching any Swing state.
		 *
		 * <p>Pass a null list to report that the read failed. This deliberately differs from
		 * {@link LibraryTreePanel.MatchCounter}, which stays silent on failure (a transient bridge
		 * hiccup is worth quietly retrying on the next keystroke): a failed read here is a real,
		 * deterministic problem with one specific .so's extraction (see
		 * {@code SoManager#extractedForId}) that would recur for the exact same query, so leaving
		 * the count stuck at "counting…" forever would be less honest than counting the library
		 * as unreadable and saying so in the final total.
		 */
		void read(String soId, Consumer<List<String>> onResult);
	}

	public LoadedLibrariesPanel(Consumer<ICodeNodeRef> onNavigate, Consumer<String> onLibraryExpanded) {
		this(onNavigate, onLibraryExpanded, null);
	}

	public LoadedLibrariesPanel(Consumer<ICodeNodeRef> onNavigate, Consumer<String> onLibraryExpanded,
			FunctionReader functionReader) {
		this(onNavigate, onLibraryExpanded, functionReader, null);
	}

	private LoadedLibrariesPanel(Consumer<ICodeNodeRef> onNavigate, Consumer<String> onLibraryExpanded,
			FunctionReader functionReader, LibraryTreePanel.DebounceScheduler scheduler) {
		super(new BorderLayout(0, 4));
		this.onNavigate = onNavigate;
		this.onLibraryExpanded = onLibraryExpanded;
		this.functionReader = functionReader;
		this.countDebounce = scheduler != null ? scheduler
				: new LibraryTreePanel.SwingTimerDebounceScheduler(COUNT_DEBOUNCE_MS, this::recomputeFunctionCount);

		tree.setRootVisible(false);
		tree.setShowsRootHandles(true);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		// while a filter is active, the resolved-library node and the two honesty buckets render
		// bold when they actually have a match (see isMatchingCategoryNode), so the user can see at
		// a glance which categories have hits without expanding every one
		tree.setCellRenderer(new javax.swing.tree.DefaultTreeCellRenderer() {
			private static final long serialVersionUID = 1L;

			@Override
			public java.awt.Component getTreeCellRendererComponent(JTree t, Object value, boolean sel,
					boolean expanded, boolean leaf, int row, boolean focus) {
				Object shown = value;
				boolean bold = false;
				if (value instanceof DefaultMutableTreeNode n) {
					String label = labelFor(n.getUserObject());
					if (label != null) {
						shown = label;
					} else if (leaf && n.getUserObject() instanceof String name
							&& LibraryTreePanel.isFunctionNameLeaf(n)) {
						// same matched-span highlight LibraryTreePanel uses for its function leaves
						// (see LibraryTreePanel.highlightMatch); reused rather than duplicated, the
						// same way isJniEntryPoint already is below in rebuildFunctionChildren
						String highlighted = LibraryTreePanel.highlightMatch(name, query());
						if (highlighted != null) {
							shown = highlighted;
						}
					}
					bold = isMatchingCategoryNode(n);
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
				return c;
			}
		});

		tree.addTreeWillExpandListener(new TreeWillExpandListener() {
			@Override
			public void treeWillExpand(TreeExpansionEvent e) {
				Object last = e.getPath().getLastPathComponent();
				if (last instanceof DefaultMutableTreeNode n && n.getUserObject() instanceof ResolvedLibrary lib
						&& lib.inApk()) {
					if (!functionsBySoId.containsKey(lib.soId()) && onLibraryExpanded != null) {
						onLibraryExpanded.accept(lib.soId());
					}
					rebuildFunctionChildren(n, lib);
				}
			}

			@Override
			public void treeWillCollapse(TreeExpansionEvent e) {
				// nothing to do
			}
		});

		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					activateSelection();
				}
			}
		});
		tree.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateSelection();
				}
			}
		});

		// The honesty disclaimer this whole window exists to make good on: static detection of
		// loadLibrary/load call sites cannot see reflection or a name assembled at runtime, so the
		// picture below -- however complete it looks -- is a best-effort lower bound, not a proof.
		JLabel disclaimer = new JLabel(
				"<html>Detected from <code>System.loadLibrary</code>/<code>load</code> call sites in the "
						+ "decompiled Java. This is best-effort static analysis -- it cannot see libraries "
						+ "loaded via reflection or a name/path computed at runtime.</html>");
		disclaimer.setFont(disclaimer.getFont().deriveFont(Font.PLAIN, disclaimer.getFont().getSize2D() - 1f));
		disclaimer.setBorder(new EmptyBorder(4, 6, 4, 6));
		disclaimer.setEnabled(false);

		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				rebuildTree();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				rebuildTree();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				rebuildTree();
			}
		});

		JPanel filterRow = new JPanel(new BorderLayout(4, 0));
		filterRow.setBorder(new EmptyBorder(2, 2, 2, 2));
		filterRow.add(new JLabel("Filter:"), BorderLayout.WEST);
		filterRow.add(filterField, BorderLayout.CENTER);

		// filter goes up top, same placement as LibraryTreePanel's -- it's the field the user reaches
		// for first; the disclaimer sits below it, still above the tree it qualifies
		JPanel north = new JPanel(new BorderLayout());
		north.add(filterRow, BorderLayout.NORTH);
		north.add(disclaimer, BorderLayout.SOUTH);

		JPanel bottom = new JPanel(new BorderLayout());
		bottom.setBorder(new EmptyBorder(2, 4, 2, 4));
		bottom.add(countLabel, BorderLayout.WEST);

		add(north, BorderLayout.NORTH);
		add(new JScrollPane(tree), BorderLayout.CENTER);
		// same placement as LibraryTreePanel's: filter/disclaimer up top, count label at the
		// bottom as a status line
		add(bottom, BorderLayout.SOUTH);
	}

	/** Replace the whole tree's data (resolved libraries, unresolved calls, unloaded .so's). */
	public void setResult(Result result) {
		this.result = result == null ? new Result(List.of(), List.of(), List.of()) : result;
		rebuildTree();
	}

	/** Shown right when the window opens, while the whole-input bytecode scan for load calls runs
	 * off the EDT (see {@code JexrayPlugin#showLoadedLibraries}) -- so an empty tree never briefly
	 * reads as "this app loads nothing" before the real (first-open-only; later opens reuse the
	 * cached scan) result arrives. */
	public void setScanning() {
		root.removeAllChildren();
		root.add(new DefaultMutableTreeNode("Scanning all classes for load calls…"));
		model.reload();
	}

	/** Supply the exported function names for one library; shown when it is expanded. */
	public void setFunctions(String soId, List<String> names) {
		functionsBySoId.put(soId, names == null ? List.of() : new ArrayList<>(names));
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
			if (n.getUserObject() instanceof ResolvedLibrary lib && soId.equals(lib.soId())) {
				rebuildFunctionChildren(n, lib);
			}
		}
	}

	/**
	 * Rebuild the whole tree, applying the current filter query (if any). Mirrors
	 * {@link LibraryTreePanel}'s approach: an empty query reproduces the unfiltered tree exactly (so
	 * every existing "no filter" test/behaviour is unaffected); a non-empty query drops non-matching
	 * entries from each of the three buckets, and drops a bucket entirely once it has no survivors --
	 * but a resolved library, an unresolved call, or an unloaded .so that DOES match is never dropped,
	 * upholding the same honesty contract the unfiltered tree already keeps.
	 */
	private void rebuildTree() {
		String query = query();
		List<String> previouslyExpanded = expandedSoIds();
		java.util.Set<String> expandedGroups = expandedGroupKeys();

		root.removeAllChildren();
		for (ResolvedLibrary lib : result.resolved()) {
			if (!query.isEmpty() && !libraryMatches(lib, query)) {
				continue;
			}
			DefaultMutableTreeNode node = new DefaultMutableTreeNode(lib);
			DefaultMutableTreeNode sites = new DefaultMutableTreeNode("Loaded by (" + lib.loadSites().size() + ")");
			for (LoadSite site : lib.loadSites()) {
				sites.add(new DefaultMutableTreeNode(site));
			}
			node.add(sites);
			if (lib.inApk()) {
				node.add(new DefaultMutableTreeNode("…")); // placeholder; real function groups on expand
			}
			root.add(node);
		}
		List<UnresolvedCall> unresolvedShown = query.isEmpty() ? result.unresolved() : filterUnresolved(query);
		if (!unresolvedShown.isEmpty()) {
			DefaultMutableTreeNode bucket = new DefaultMutableTreeNode(
					"Unresolved load calls (" + unresolvedShown.size() + ") — argument could not be read");
			for (UnresolvedCall c : unresolvedShown) {
				bucket.add(new DefaultMutableTreeNode(c));
			}
			root.add(bucket);
		}
		List<UnloadedLibrary> unloadedShown = query.isEmpty() ? result.unloaded() : filterUnloaded(query);
		if (!unloadedShown.isEmpty()) {
			DefaultMutableTreeNode bucket = new DefaultMutableTreeNode(
					"In the APK but never loaded by a detected call (" + unloadedShown.size() + ")");
			for (UnloadedLibrary u : unloadedShown) {
				bucket.add(new DefaultMutableTreeNode(u));
			}
			root.add(bucket);
		}
		model.reload();

		// re-expand libraries that were already open (a filter edit must not collapse the user's
		// view), and also expand any library the query matches purely on its (already-cached, never
		// eagerly loaded) function names -- same as LibraryTreePanel: a library whose functions match
		// stays visible and open, without decompiling/expanding anything not already loaded.
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
			if (n.getUserObject() instanceof ResolvedLibrary lib && lib.inApk()) {
				boolean shouldExpand = previouslyExpanded.contains(lib.soId())
						|| (!query.isEmpty() && functionsMatch(lib, query));
				if (shouldExpand) {
					rebuildFunctionChildren(n, lib);
					tree.expandPath(new TreePath(new Object[] { root, n }));
					// re-open the groups ("Loaded by"/"JNI methods"/"Functions") that were open, keyed
					// by title so narrowing the filter doesn't re-collapse them under the user
					for (int j = 0; j < n.getChildCount(); j++) {
						DefaultMutableTreeNode grp = (DefaultMutableTreeNode) n.getChildAt(j);
						if (grp.getUserObject() instanceof String s
								&& expandedGroups.contains(lib.soId() + GROUP_KEY_SEP + groupTitle(s))) {
							tree.expandPath(new TreePath(new Object[] { root, n, grp }));
						}
					}
				}
			}
		}
		// the bottom count label totals matches across every resolved-in-APK library, not just the
		// ones rebuilt above (that set is only what already matches by name/site/cached-functions) --
		// see scheduleCountUpdate.
		scheduleCountUpdate();
	}

	/**
	 * Debounces the eager function count the same way {@link LibraryTreePanel#scheduleCountUpdate}
	 * debounces its own: a filter edit (or a result refresh while a filter is active) restarts a
	 * quiet-period timer instead of counting immediately, so a burst of keystrokes settles into one
	 * batch of per-library symbol reads. An empty query needs no counting -- "N libraries" is
	 * already exact -- so that case is handled immediately and also cancels any read still in
	 * flight for the query just abandoned.
	 */
	private void scheduleCountUpdate() {
		if (query().isEmpty()) {
			countDebounce.stop();
			countEpoch++; // invalidate any pending async reads; nothing to count now
			countLabel.setText(resolvedInApkLibraryCount() + " libraries");
			return;
		}
		countDebounce.restart();
	}

	/** How many resolved libraries are actually in the APK -- the population the bottom count
	 * label totals functions across (see {@link #recomputeFunctionCount}), and what the label
	 * falls back to showing, unfiltered, when there is no query to count matches for. */
	private int resolvedInApkLibraryCount() {
		int n = 0;
		for (ResolvedLibrary lib : result.resolved()) {
			if (lib.inApk()) {
				n++;
			}
		}
		return n;
	}

	/**
	 * Runs once the filter has been quiet for {@link #COUNT_DEBOUNCE_MS}. Totals matches across
	 * every resolved library that is actually in the APK -- a library the app merely asks to load
	 * but that isn't present (downloaded at runtime, or a system library) has no .so to read and no
	 * functions to speak of, so it is excluded from the total the same way a non-READY library is
	 * excluded from {@link LibraryTreePanel}'s, and likewise called out by count rather than
	 * silently dropped (see below). A library whose functions are already cached (expanded before,
	 * or read by an earlier pass of this same method) is counted locally for free, with the exact
	 * same {@link FunctionFilter} the tree filter itself uses; one that isn't cached asks
	 * {@link #functionReader}, off the EDT.
	 *
	 * <p>Mirrors {@link LibraryTreePanel#recomputeTotal()}'s two-pass shape: every library needing
	 * {@link #functionReader} is collected into {@code toRead} first, and only queried in a second
	 * pass, after the accumulator fields are already set for {@code myEpoch} -- a
	 * {@link FunctionReader} answering inline (as a test deliberately does, to stay deterministic)
	 * must never run {@link #onLibraryRead} while this method is still partway through
	 * initializing those fields.
	 */
	private void recomputeFunctionCount() {
		String query = query();
		if (query.isEmpty()) {
			countLabel.setText(resolvedInApkLibraryCount() + " libraries");
			return;
		}
		long myEpoch = ++countEpoch;
		int matches = 0;
		int total = 0;
		int uncountable = 0;
		List<String> toRead = new ArrayList<>();
		for (ResolvedLibrary lib : result.resolved()) {
			if (!lib.inApk()) {
				// no .so in the input to read symbols from at all -- not a zero, an unknown
				uncountable++;
				continue;
			}
			List<String> names = functionsBySoId.get(lib.soId());
			if (names != null) {
				int libMatches = FunctionFilter.filter(names, query).size();
				total += names.size();
				matches += libMatches;
				continue;
			}
			if (functionReader == null) {
				// nothing to ask and no local list either -- can't count this one
				uncountable++;
				continue;
			}
			toRead.add(lib.soId());
		}
		if (toRead.isEmpty()) {
			finishFunctionCount(myEpoch, matches, total, uncountable);
			return;
		}
		countAccumMatches = matches;
		countAccumTotal = total;
		countAccumUncountable = uncountable;
		countPendingRemaining = toRead.size();
		// never show a number that isn't fully established yet -- not even a partial sum, since
		// that reads as final.
		countLabel.setText("counting…");
		for (String soId : toRead) {
			functionReader.read(soId,
					names -> SwingUtilities.invokeLater(() -> onLibraryRead(myEpoch, soId, query, names)));
		}
	}

	/**
	 * One pending {@link FunctionReader} result has landed, already on the EDT. A successful read
	 * is cached directly into {@link #functionsBySoId} -- not via {@link #setFunctions}, which
	 * would call back into {@link #scheduleCountUpdate} and risk this very read restarting the
	 * debounce it was answering -- so a later expand of the same library (or a later recompute
	 * pass) reuses it instead of reading the .so a second time. A null {@code names} means the
	 * read failed (see {@link FunctionReader#read}): counted as uncountable, never as a fabricated
	 * zero.
	 *
	 * <p>A successful read also re-runs {@link #rebuildTree()}, not merely a repaint: unlike
	 * {@link LibraryTreePanel}, whose tree always keeps every library as a top-level node and only
	 * changes bold/dim state under a filter, {@link #rebuildTree()} here actually DROPS a resolved
	 * library that fails to match (see the {@code continue} in its loop) -- so a library whose only
	 * match is in the functions this read just supplied would otherwise stay invisible forever
	 * (excluded by the filtering pass that ran before this data existed), even though the bottom
	 * count label now honestly reports a match inside it. Rebuilding is what lets the tree agree
	 * with the count. Safe to call from here: {@link #rebuildTree()}'s own call to
	 * {@link #scheduleCountUpdate()} only restarts the debounce for a non-empty query (it does not
	 * touch {@link #countEpoch} or the accumulator fields this method is still using), and this
	 * always runs on a fresh EDT dispatch (via the {@code invokeLater} in
	 * {@link #recomputeFunctionCount()}), never while that method is still on the stack.
	 */
	private void onLibraryRead(long epoch, String soId, String query, List<String> names) {
		if (epoch != countEpoch) {
			return; // superseded by a newer query; this result is stale
		}
		if (names == null) {
			countAccumUncountable++;
		} else {
			functionsBySoId.put(soId, new ArrayList<>(names));
			countAccumTotal += names.size();
			countAccumMatches += FunctionFilter.filter(names, query).size();
			rebuildTree();
		}
		countPendingRemaining--;
		if (countPendingRemaining == 0) {
			finishFunctionCount(epoch, countAccumMatches, countAccumTotal, countAccumUncountable);
		}
	}

	private void finishFunctionCount(long epoch, int matches, int total, int uncountableLibs) {
		if (epoch != countEpoch) {
			return; // superseded while this result was landing
		}
		String base = matches + " / " + total + " functions";
		countLabel.setText(uncountableLibs == 0 ? base
				: base + " (" + uncountableLibs + " librar" + (uncountableLibs == 1 ? "y" : "ies") + " not readable)");
	}

	/**
	 * Rebuild everything after the (always-present) "Loaded by" group -- index 0 -- with the
	 * function groups for {@code lib}, from whatever {@link #functionsBySoId} currently holds.
	 *
	 * <p>Uses {@link DefaultTreeModel}'s incremental mutators ({@code removeNodeFromParent} /
	 * {@code insertNodeInto}) rather than a blanket {@code nodeStructureChanged(node)} on the
	 * library node: that fires a broad {@code treeStructureChanged} event covering the WHOLE
	 * node, including the untouched "Loaded by" group at index 0 -- and Swing's default
	 * {@code expandsSelectedPaths} behavior (auto-expanding a node to reveal a path being
	 * selected under it) means expanding this very node can happen as a side effect of selecting
	 * one of its "Loaded by" load-site leaves, which a structure-changed event on an ancestor of
	 * that selection silently clears. Fine-grained insert/remove events only describe the
	 * children that actually changed, so a sibling selection under "Loaded by" survives.
	 */
	private void rebuildFunctionChildren(DefaultMutableTreeNode node, ResolvedLibrary lib) {
		while (node.getChildCount() > 1) {
			model.removeNodeFromParent((DefaultMutableTreeNode) node.getChildAt(1));
		}
		List<String> names = functionsBySoId.get(lib.soId());
		if (names == null) {
			model.insertNodeInto(new DefaultMutableTreeNode("(reading symbols…)"), node, node.getChildCount());
			return;
		}
		if (names.isEmpty()) {
			model.insertNodeInto(new DefaultMutableTreeNode("(no exported symbols found)"), node, node.getChildCount());
			return;
		}
		String query = query();
		List<String> shown = query.isEmpty() ? names : FunctionFilter.filter(names, query);
		if (shown.isEmpty()) {
			// names is non-empty here, so this is "the filter matched nothing", not "nothing to load"
			model.insertNodeInto(new DefaultMutableTreeNode("(no matching functions)"), node, node.getChildCount());
			return;
		}
		List<String> jni = new ArrayList<>();
		List<String> other = new ArrayList<>();
		for (String n : shown) {
			(LibraryTreePanel.isJniEntryPoint(n) ? jni : other).add(n);
		}
		if (!jni.isEmpty()) {
			model.insertNodeInto(group("JNI methods", jni), node, node.getChildCount());
		}
		if (!other.isEmpty()) {
			model.insertNodeInto(group("Functions", other), node, node.getChildCount());
		}
	}

	private static DefaultMutableTreeNode group(String title, List<String> names) {
		DefaultMutableTreeNode g = new DefaultMutableTreeNode(title + " (" + names.size() + ")");
		for (String n : names) {
			g.add(new DefaultMutableTreeNode(n));
		}
		return g;
	}

	private void activateSelection() {
		TreePath path = tree.getSelectionPath();
		if (path == null) {
			return;
		}
		Object userObject = ((DefaultMutableTreeNode) path.getLastPathComponent()).getUserObject();
		ICodeNodeRef ref = refOf(userObject);
		if (ref != null && onNavigate != null) {
			onNavigate.accept(ref);
		}
	}

	private static ICodeNodeRef refOf(Object userObject) {
		if (userObject instanceof LoadSite site) {
			return site.ref();
		}
		if (userObject instanceof UnresolvedCall c) {
			return c.site().ref();
		}
		return null;
	}

	private static String labelFor(Object userObject) {
		if (userObject instanceof ResolvedLibrary lib) {
			return libraryLabel(lib);
		}
		if (userObject instanceof LoadSite site) {
			return "loaded by " + site.classBinaryName() + "." + site.methodName();
		}
		if (userObject instanceof UnresolvedCall c) {
			return unresolvedLabel(c);
		}
		if (userObject instanceof UnloadedLibrary u) {
			return (u.soFileName() == null ? u.soId() : u.soFileName())
					+ "   " + HumanFormat.formatSize(u.sizeBytes());
		}
		return null; // not one of ours -- default toString applies (group headers, placeholders)
	}

	private static String libraryLabel(ResolvedLibrary lib) {
		StringBuilder sb = new StringBuilder(lib.requestedName());
		if (lib.inApk()) {
			sb.append("  →  ").append(lib.soFileName()).append("   ").append(HumanFormat.formatSize(lib.sizeBytes()));
		} else {
			sb.append("   (not in the loaded input — downloaded at runtime, or a system library)");
		}
		return sb.toString();
	}

	private static String unresolvedLabel(UnresolvedCall c) {
		String call = c.kind() == Kind.LOAD_LIBRARY ? "System.loadLibrary(?)" : "System.load(?)";
		return call + "  —  " + c.site().classBinaryName() + "." + c.site().methodName();
	}

	private String query() {
		return filterField.getText().trim();
	}

	/**
	 * A resolved library matches a non-empty query if the requested name, the .so file it resolved
	 * to, any of its load sites' class/method, or (only when already known -- see
	 * {@link #functionsMatch}) one of its exported function names contains it, case-insensitively.
	 * Matching on requested/resolved name and load-site class covers the fields every library has
	 * regardless of whether its functions are known; function names are the one field that is
	 * genuinely useful to search but can only ever be checked once {@link #functionsBySoId} has an
	 * entry for it -- populated either by the user expanding it (functions are loaded lazily -- see
	 * the class javadoc) or by the bottom count label's own eager read (see
	 * {@link #recomputeFunctionCount}) -- so a library whose functions would match but haven't been
	 * read yet, by either path, is honestly not counted as a match rather than silently treated as
	 * one.
	 */
	private boolean libraryMatches(ResolvedLibrary lib, String query) {
		if (contains(lib.requestedName(), query) || contains(lib.soFileName(), query)) {
			return true;
		}
		for (LoadSite site : lib.loadSites()) {
			if (siteMatches(site, query)) {
				return true;
			}
		}
		return functionsMatch(lib, query);
	}

	/** True only if this library's function names are already cached (i.e. it has been expanded at
	 * least once) and at least one matches; never triggers loading them. */
	private boolean functionsMatch(ResolvedLibrary lib, String query) {
		List<String> names = functionsBySoId.get(lib.soId());
		return names != null && !FunctionFilter.filter(names, query).isEmpty();
	}

	private static boolean siteMatches(LoadSite site, String query) {
		return contains(site.classBinaryName(), query) || contains(site.methodName(), query);
	}

	private List<UnresolvedCall> filterUnresolved(String query) {
		List<UnresolvedCall> out = new ArrayList<>();
		for (UnresolvedCall c : result.unresolved()) {
			if (siteMatches(c.site(), query)) {
				out.add(c);
			}
		}
		return out;
	}

	/**
	 * True for a "category" node -- a resolved library, or one of the two honesty buckets
	 * ("Unresolved load calls…" / "In the APK but never loaded…") -- whose subtree contains at
	 * least one filter match, so the renderer can bold it. Reuses the exact predicates
	 * {@link #rebuildTree} already used to decide what survives filtering ({@link #libraryMatches},
	 * {@link #filterUnresolved}, {@link #filterUnloaded}) rather than a second, separate match test
	 * that could disagree with what the tree actually shows.
	 *
	 * <p>Deliberately scoped to root's direct children only: the "Loaded by (n)" group is context,
	 * not a category (left normal, per the design), and every other node (load sites, function
	 * names, unresolved/unloaded entries) is a leaf that IS the match, not a category containing
	 * one -- both stay unbolded.
	 */
	private boolean isMatchingCategoryNode(DefaultMutableTreeNode n) {
		String query = query();
		if (query.isEmpty() || n.getParent() != root) {
			return false;
		}
		Object obj = n.getUserObject();
		if (obj instanceof ResolvedLibrary lib) {
			return libraryMatches(lib, query);
		}
		if (obj instanceof String && n.getChildCount() > 0) {
			Object firstChild = ((DefaultMutableTreeNode) n.getChildAt(0)).getUserObject();
			if (firstChild instanceof UnresolvedCall) {
				return !filterUnresolved(query).isEmpty();
			}
			if (firstChild instanceof UnloadedLibrary) {
				return !filterUnloaded(query).isEmpty();
			}
		}
		return false;
	}

	private List<UnloadedLibrary> filterUnloaded(String query) {
		List<UnloadedLibrary> out = new ArrayList<>();
		for (UnloadedLibrary u : result.unloaded()) {
			if (contains(u.soFileName(), query) || contains(u.soId(), query)) {
				out.add(u);
			}
		}
		return out;
	}

	private static boolean contains(String haystack, String query) {
		return haystack != null && haystack.toLowerCase(java.util.Locale.ROOT)
				.contains(query.toLowerCase(java.util.Locale.ROOT));
	}

	private List<String> expandedSoIds() {
		List<String> open = new ArrayList<>();
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
			if (n.getUserObject() instanceof ResolvedLibrary lib
					&& tree.isExpanded(new TreePath(new Object[] { root, n }))) {
				open.add(lib.soId());
			}
		}
		return open;
	}

	/** Separates a library soId from a group title in an expansion key; NUL never appears in either. */
	private static final String GROUP_KEY_SEP = "\u0000";

	/**
	 * Keys ({@code soId + NUL + groupTitle}) for every currently-open group ("Loaded by"/"JNI
	 * methods"/"Functions"), so {@link #rebuildTree()} can re-open the same groups afterwards. Keyed
	 * by title, not the full label, because the label's count changes as the filter narrows.
	 */
	private java.util.Set<String> expandedGroupKeys() {
		java.util.Set<String> keys = new java.util.HashSet<>();
		for (int i = 0; i < root.getChildCount(); i++) {
			DefaultMutableTreeNode lib = (DefaultMutableTreeNode) root.getChildAt(i);
			if (!(lib.getUserObject() instanceof ResolvedLibrary le)
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

	/** "JNI methods (5)" -> "JNI methods": the stable part of a group label, without its match count. */
	private static String groupTitle(String label) {
		int p = label.lastIndexOf(" (");
		return p < 0 ? label : label.substring(0, p);
	}

	/** Focus the filter box (called when the window is surfaced, and on Ctrl+F/⌘+F). */
	public void focusFilter() {
		filterField.requestFocusInWindow();
	}

}
