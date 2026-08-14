package com.jexray.jadx;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.Timer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.metadata.ICodeNodeRef;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;

import com.jexray.jadx.NativeMethodResolver.NativeMethod;
import com.jexray.jadx.apk.SoExtractor.ExtractedSo;
import com.jexray.jadx.apk.SoManager;
import com.jexray.jadx.bridge.BridgeException;
import com.jexray.jadx.bridge.BridgeMessages;
import com.jexray.jadx.bridge.BridgeModels.CacheStatsResult;
import com.jexray.jadx.bridge.BridgeModels.CallerRef;
import com.jexray.jadx.bridge.BridgeModels.ClearCacheResult;
import com.jexray.jadx.bridge.BridgeModels.DecompileResult;
import com.jexray.jadx.bridge.BridgeModels.DisassembleResult;
import com.jexray.jadx.bridge.BridgeModels.FunctionRef;
import com.jexray.jadx.bridge.BridgeModels.RegNative;
import com.jexray.jadx.bridge.BridgeModels.RegisterNativesResult;
import com.jexray.jadx.bridge.BridgeModels.SearchResult;
import com.jexray.jadx.bridge.BridgeModels.StatusResult;
import com.jexray.jadx.bridge.BridgeModels.XrefsResult;
import com.jexray.jadx.bridge.GhidraBridgeClient;
import com.jexray.jadx.bridge.LoadDeadline;
import com.jexray.jadx.bridge.PrewarmProgress;
import com.jexray.jadx.bridge.PrewarmProgress.LibState;
import com.jexray.jadx.apk.LoadedLibrariesModel;
import com.jexray.jadx.ghidra.EmbeddedGhidraBridge;
import com.jexray.jadx.nav.SyncDebouncer;
import com.jexray.jadx.symbols.NativeSymbols;
import com.jexray.jadx.ui.CacheDialog;
import com.jexray.jadx.ui.FunctionListDialog;
import com.jexray.jadx.ui.LibraryEntry;
import com.jexray.jadx.ui.LoadedLibrariesDialog;
import com.jexray.jadx.ui.NativeFunctionView;
import com.jexray.jadx.ui.NativeViewDialog;
import com.jexray.jadx.ui.XrefEntry;
import com.jexray.jadx.ui.XrefsView;
import com.jexray.jadx.util.HumanFormat;

/**
 * Jexray plugin entry point: detects native (JNI) methods in a loaded APK and shows the
 * corresponding native function's Ghidra pseudocode/disassembly in a side dialog.
 */
public class JexrayPlugin implements JadxPlugin {

	public static final String PLUGIN_ID = "jexray-native-view";

	private static final Logger LOG = LoggerFactory.getLogger(JexrayPlugin.class);
	private static final int SYNC_POLL_MS = 350;
	private static final long SYNC_DEBOUNCE_MS = 400;
	private static final long LOAD_POLL_MS = 400;
	/**
	 * How long to keep waiting when the bridge stops answering status requests. This is not an
	 * analysis timeout: analysis can legitimately run for an hour on a large library, and the bridge
	 * itself decides when one has stalled. Every status reply refreshes this, so it only fires if
	 * the bridge has actually gone away.
	 */
	private static final long LOAD_TIMEOUT_MS = 60_000;

	private final JexrayOptions options = new JexrayOptions();
	private final NativeMethodPass nativeMethodPass = new NativeMethodPass();

	// symbol -> resolved view, so revisiting a function never re-hits the bridge
	private final Map<String, NativeFunctionView> viewCache = new ConcurrentHashMap<>();
	private final SyncDebouncer syncDebouncer = new SyncDebouncer(SYNC_DEBOUNCE_MS);
	// soId -> (Ghidra function symbol -> the Java native method that registers it dynamically),
	// for RegisterNatives targets that have no exported JNI symbol of their own and therefore
	// can't be found in NativeMethodPass's forward jniSymbol index. Built lazily (one bridge call
	// per soId, the first time it's needed) and kept forever after, mirroring readySoIds -- the
	// underlying RegisterNatives table doesn't change without a re-analysis, which already clears
	// viewCache for the .so, so this is cleared alongside it there.
	private final Map<String, Map<String, NativeMethod>> registeredNativeRefsBySoId = new ConcurrentHashMap<>();

	private JadxPluginContext context;
	private Path cacheDir;

	// multi-.so state: lazily built index of the input's native libs + which are bridge-ready
	private volatile SoManager soManager;
	// Loaded Libraries window: the whole-input raw-bytecode scan (see LoadLibraryBytecodeScanner)
	// is memoized like soManager above -- the input's classes never change after project load, so
	// a second window open reuses this instead of re-scanning.
	private volatile List<LoadLibraryDetector.LoadLibraryCall> loadLibraryCalls;
	// jniSymbol -> NativeMethod, built by scanning every class's method METADATA (access flags +
	// declaring class/method names/types) directly -- no decompiling needed, since
	// NativeMethodResolver.resolve only reads facts jadx already has after parsing. This closes
	// the SAME lazy-decompile gap loadLibraryCalls/LoadLibraryBytecodeScanner closes for
	// loadLibrary calls: nativeMethodPass (a JadxDecompilePass) only records a native method once
	// its class has actually been decompiled -- in jadx-gui, only classes the user has opened --
	// even though "native" is a bytecode-level fact that doesn't require decompiling to know.
	// Lazily built (see getEagerNativeMethodIndex) and memoized like loadLibraryCalls above, since
	// the input's classes never change after project load.
	private volatile Map<String, NativeMethod> eagerNativeMethodIndex;
	private final java.util.Set<String> readySoIds = java.util.concurrent.ConcurrentHashMap.newKeySet();
	// soIds with a force-reanalyze in flight, so describeLibraries() can show
	// ANALYZING for them even though they've been dropped from readySoIds for the duration.
	private final java.util.Set<String> reanalyzingSoIds = java.util.concurrent.ConcurrentHashMap.newKeySet();
	// soId -> true function count, from the bridge's own status report -- never computed or
	// approximated here. Always written before the matching readySoIds.add(soId) (see
	// ensureBridgeLoaded/prewarmAll) so a reader that observes the soId as ready always finds its
	// count already present.
	private final Map<String, Integer> functionCountBySoId = new ConcurrentHashMap<>();
	// One global lock, not one per .so: an on-demand load holds it for its whole submit-and-poll
	// loop, so a second library's on-demand load waits behind it. That prevents duplicate
	// concurrent loads of the same .so, at the cost of serializing different ones.
	private final Object loadLock = new Object();
	private volatile String currentSoId; // soId of the most recently opened function (picker default)

	private NativeViewDialog dialog;
	private FunctionListDialog functionListDialog;

	/**
	 * Per library, which listed names are linked in from elsewhere. Filled when a library's
	 * listing is fetched and handed to the browser so those entries render apart from the ones
	 * that can actually be opened.
	 */
	private final Map<String, Set<String>> externalNamesBySoId = new ConcurrentHashMap<>();

	/** Per library, which listed names it publishes in its dynamic symbol table. */
	private final Map<String, Set<String>> exportedNamesBySoId = new ConcurrentHashMap<>();

	/** Per library, which listed names are bound to a Java method by {@code RegisterNatives}. */
	private final Map<String, Set<String>> registeredNamesBySoId = new ConcurrentHashMap<>();

	/** Cache behind {@link #registeredSymbolsOf}; the table cannot change without a re-analysis. */
	private final Map<String, Set<String>> registeredSymbolsBySoId = new ConcurrentHashMap<>();

	/** Guards against stacking up analyze-all sweeps when several windows are opened in a row. */
	private final java.util.concurrent.atomic.AtomicBoolean analyzeAllInFlight =
			new java.util.concurrent.atomic.AtomicBoolean();
	private LoadedLibrariesDialog loadedLibrariesDialog;
	private Timer syncTimer;
	private EmbeddedGhidraBridge embeddedBridge;
	private volatile boolean versionWarningShown;

	@Override
	public JadxPluginInfo getPluginInfo() {
		// requiredJadxVersion is the floor JADX enforces at load time (VerifyRequiredVersion).
		// Set to 1.5.3 -- the plugin compiles unchanged against jadx-core 1.5.3/1.5.4/1.5.5, while
		// 1.5.1 and older changed the plugin-facing internals this uses. Format is
		// "<release>, r<dev-revision>": stable runtimes compare the release, dev builds the
		// revision. Newer JADX releases load too; there is no upper bound.
		return JadxPluginInfoBuilder.pluginId(PLUGIN_ID)
				.name("Jexray Native View")
				.description("Browse native (JNI) methods and view Ghidra pseudocode/disassembly")
				.homepage("https://github.com/cys7885/jexray")
				.requiredJadxVersion("1.5.3, r2576")
				.build();
	}

	@Override
	public void init(JadxPluginContext context) {
		this.context = context;
		context.registerOptions(options);
		// "analyze everything up front" is off by default, so this normally does nothing
		nativeMethodPass.setOnInputLoaded(() -> {
			if (options.isAnalyzeAllOnOpen()) {
				analyzeAllLibraries();
			}
		});
		context.addPass(nativeMethodPass);

		this.cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), "jexray-so");

		startEmbeddedBridge();

		JadxGuiContext gui = context.getGuiContext();
		if (gui == null) {
			return; // running under CLI: detection pass still active, no UI
		}

		gui.addPopupMenuAction(
				"Show in Native View",
				ref -> NativeMethodResolver.resolveFromRef(ref) != null,
				null,
				this::onShowInNativeView);

		// Immediately kick off full library analysis in the background (not just an empty
		// window) so browsing is instant once the user asks for it -- but without popping the
		// All Functions picker open uninvited; just show the dialog with a ready/progress state.
		gui.addMenuAction("Jexray - Open Native View", () -> gui.uiRun(this::openNativeViewEager));
	}

	@Override
	public void unload() {
		if (syncTimer != null) {
			syncTimer.stop();
		}
		if (embeddedBridge != null) {
			embeddedBridge.stop();
			embeddedBridge = null;
		}
	}

	/**
	 * Start the in-process Ghidra bridge on a background thread so jadx-gui startup is never
	 * blocked (unless the user opted for an external bridge). Idempotent: won't double-start.
	 */
	private synchronized void startEmbeddedBridge() {
		if (!options.isEmbeddedBridge()) {
			LOG.info("Embedded bridge disabled; using external bridge at {}", options.getBridgeUrl());
			return;
		}
		if (embeddedBridge != null) {
			return; // already started
		}
		File home = new File(System.getProperty("user.home"), ".jexray");
		int preferredPort = portFromUrl(GhidraBridgeClient.DEFAULT_BASE_URL, 8791);
		EmbeddedGhidraBridge bridge = new EmbeddedGhidraBridge(home, options.getGhidraInstallDir(), preferredPort);
		this.embeddedBridge = bridge;
		Thread starter = new Thread(() -> {
			try {
				bridge.start();
				LOG.info("Embedded Ghidra bridge started at {}", bridge.getBaseUrl());
				// Change: if the dialog was already opened before the bridge finished starting,
				// its toolbar label is showing "Ghidra ?" (see getOrCreateDialog) -- now that the
				// version is known (or confirmed unreadable), refresh it. No-op if no dialog
				// exists yet; the dialog's own creation pushes the then-current value.
				NativeViewDialog d = dialog;
				if (d != null) {
					maybeWarnGhidraVersion(d);
				}
			} catch (Exception e) {
				LOG.warn("Failed to start embedded Ghidra bridge; falling back to external bridge URL", e);
				embeddedBridge = null;
			}
		}, "jexray-bridge-starter");
		starter.setDaemon(true);
		starter.start();
	}

	/**
	 * URL the client should target: the embedded bridge if running, else the configured
	 * external one. Called from worker threads, so it briefly waits for the async start to
	 * finish (avoids racing the first request against a still-starting server).
	 */
	private String resolveBridgeUrl() {
		EmbeddedGhidraBridge bridge = embeddedBridge;
		if (bridge != null) {
			for (int i = 0; i < 50 && !bridge.isRunning() && embeddedBridge != null; i++) {
				try {
					Thread.sleep(100); // up to ~5s for the HTTP server to bind
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				}
			}
			if (bridge.isRunning()) {
				return bridge.getBaseUrl();
			}
		}
		return options.getBridgeUrl();
	}

	private static int portFromUrl(String url, int fallback) {
		try {
			int p = java.net.URI.create(url).getPort();
			return p > 0 ? p : fallback;
		} catch (Exception e) {
			return fallback;
		}
	}

	private void onShowInNativeView(ICodeNodeRef ref) {
		NativeMethod nm = NativeMethodResolver.resolveFromRef(ref);
		if (nm != null) {
			// native method from Java: owning .so unknown -> resolve by exported-symbol scan,
			// with a RegisterNatives fallback when there's no exported JNI symbol. openSymbol
			// itself reopens the window if it was previously dismissed (see its javadoc).
			openSymbol(nm.jniSymbol(), nm.ref(), false, null, nm);
		}
	}

	private static String cacheKey(String soId, String symbol) {
		return soId + " " + symbol;
	}

	/**
	 * Show a symbol.
	 *
	 * @param soIdHint       when non-null, the .so this symbol belongs to is already known
	 *                       (e.g. picked from the All Functions list of a specific library, or
	 *                       a call inside the currently-viewed .so) — query that .so directly
	 *                       instead of re-resolving via the exported-symbol scan (which cannot
	 *                       locate non-exported / synthetic functions like {@code _helper} or
	 *                       {@code FUN_...}). When null (a native method opened from Java) the
	 *                       owning .so is resolved by scanning exported symbols.
	 * @param silentNotFound when true (a speculative pseudocode-call click), a not-found is
	 *                       reported via a transient status line instead of replacing the view
	 */
	private void openSymbol(String symbol, ICodeNodeRef javaRef, boolean silentNotFound, String soIdHint) {
		openSymbol(symbol, javaRef, silentNotFound, soIdHint, null);
	}

	/**
	 * @param nativeCtx when non-null, this open came from a Java {@code native} method; if the
	 *                  exported-symbol scan can't find it, a {@code RegisterNatives} fallback is
	 *                  attempted (dynamically-registered methods have no exported JNI symbol).
	 */
	private void openSymbol(String symbol, ICodeNodeRef javaRef, boolean silentNotFound, String soIdHint,
			NativeMethod nativeCtx) {
		JadxGuiContext gui = context.getGuiContext();
		NativeViewDialog d = getOrCreateDialog(gui);
		// Every caller of openSymbol is a direct user action (the "Show in Native View" menu, a
		// function picked from All Functions, following a call inside pseudocode that's already on
		// screen, or a caret-sync tick the caller already gated on the dialog being visible) -- never
		// a background progress path (those surface the dialog through NativeViewDialog's own
		// surface(), which stays silent for a user-dismissed window). So a closed Native View must
		// reopen here, same as the explicit menu path always has, without reintroducing the
		// re-popup-on-every-progress-tick bug presentForUserAction/surface's split exists to prevent.
		d.presentForUserAction();

		// Entry paths that don't already know the originating Java method (All Functions / the
		// library tree, following a pseudocode call) arrive here with a null javaRef. Resolve one
		// from the jniSymbol index NativeMethodPass already built during decompilation, so "Go to
		// Java Source" works no matter how the function was reached. This is a lookup against
		// known native methods, never a guess: a synthetic Ghidra name or an
		// internal helper simply has no entry and correctly stays unresolved. Cheap (an in-memory
		// map get), so it's safe to do here even when called from the EDT.
		final ICodeNodeRef resolvedJavaRef;
		if (javaRef != null) {
			resolvedJavaRef = javaRef;
		} else {
			NativeMethod known = nativeMethodPass.getNativeMethods().get(symbol);
			if (known == null) {
				// The lazy pass hasn't decompiled this method's class (unopened in jadx-gui) --
				// fall back to the eager metadata-only scan, which has no such gap. Still a
				// lookup against known native methods, never a guess: see
				// getEagerNativeMethodIndex.
				known = getEagerNativeMethodIndex().get(symbol);
			}
			resolvedJavaRef = known == null ? null : known.ref();
		}

		// instant cache serve is only possible when the owning .so is already known
		if (soIdHint != null) {
			NativeFunctionView cached = viewCache.get(cacheKey(soIdHint, symbol));
			if (cached != null) {
				if (resolvedJavaRef != null && cached.javaRef() == null) {
					cached = withJavaRef(cached, resolvedJavaRef);
					viewCache.put(cacheKey(soIdHint, symbol), cached);
				}
				currentSoId = soIdHint;
				d.showFunction(cached);
				return;
			}
		}

		d.showLoading(symbol);
		Thread worker = new Thread(
				() -> fetchAndShow(symbol, resolvedJavaRef, silentNotFound, soIdHint, nativeCtx, d),
				"jexray-native-view");
		worker.setDaemon(true);
		worker.start();
	}

	private static NativeFunctionView withJavaRef(NativeFunctionView v, ICodeNodeRef ref) {
		return new NativeFunctionView(v.soId(), v.symbol(), v.address(), v.pseudocode(), v.disassembly(), ref);
	}

	private void fetchAndShow(String symbol, ICodeNodeRef javaRef, boolean silentNotFound, String soIdHint,
			NativeMethod nativeCtx, NativeViewDialog d) {
		GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
		try {
			SoManager mgr = getSoManager();
			if (!mgr.hasNativeLibraries()) {
				d.showError(symbol, "No native library (lib/*/*.so) found in the loaded input.");
				return;
			}
			// Known .so (from the function list / current view) -> query it directly.
			// Unknown -> locally scan exported symbols to find the owning lib.
			String soId = soIdHint != null ? soIdHint : mgr.findSoForSymbol(symbol);
			boolean nameGuess = false;
			if (soId == null && nativeCtx != null) {
				// Not an exported symbol in any .so: it may be registered dynamically via
				// RegisterNatives. Resolve it to the real (obscure) function and query that.
				RegMatch m = resolveViaRegisterNatives(client, mgr, nativeCtx, d);
				if (m != null) {
					soId = m.soId;
					symbol = m.symbol; // Ghidra's name for the registered function (e.g. FUN_...)
				}
			}
			if (soId == null && nativeCtx != null) {
				// Neither an exported JNI symbol nor a resolvable RegisterNatives entry (e.g. the
				// registration array is built at runtime, or Ghidra couldn't recover the slot call).
				// Last resort: if exactly one already-analyzed library has a function whose name is
				// exactly the Java method name, offer it -- but flag it as an ESTIMATE below, since
				// RegisterNatives imposes no naming rule and a name match is only app convention.
				RegMatch guess = resolveByNameHeuristic(client, nativeCtx);
				if (guess != null) {
					soId = guess.soId;
					symbol = guess.symbol;
					nameGuess = true;
				}
			}
			if (soId == null) {
				// Say what was tried, not just that it failed. Every route has its own reason for
				// coming up empty -- no exported symbol under the mangled name, no registration
				// table to consult, no library exporting the plain method name -- and which one it
				// was decides what to do next. Without this the user sees the same sentence
				// whatever the cause, and so does anyone they report it to.
				String tried = describeResolutionAttempts(mgr, symbol, nativeCtx);
				if (silentNotFound) {
					d.showUnresolved(symbol, "No native function named " + symbol + " was found in "
							+ "any library of the chosen ABI. " + tried);
				} else {
					d.showError(symbol, BridgeMessages.forFailure(BridgeException.Kind.NOT_FOUND,
							symbol, client.getBaseUrl()) + "\n// " + tried);
				}
				return;
			}

			NativeFunctionView cachedView = viewCache.get(cacheKey(soId, symbol));
			if (cachedView != null) {
				if (javaRef != null && cachedView.javaRef() == null) {
					cachedView = withJavaRef(cachedView, javaRef);
					viewCache.put(cacheKey(soId, symbol), cachedView);
				}
				currentSoId = soId;
				d.showFunction(cachedView);
				if (nameGuess) {
					d.flashStatus(NAME_GUESS_STATUS);
				}
				return;
			}

			ensureBridgeLoaded(client, soId, d);
			DecompileResult dec;
			try {
				dec = decompileWithRetry(client, soId, symbol);
			} catch (BridgeException e) {
				// The hint's .so didn't have it (e.g. a cross-.so pseudocode call). Fall back to
				// an exported-symbol scan to locate the real owning .so before giving up.
				if (e.getKind() == BridgeException.Kind.NOT_FOUND && soIdHint != null) {
					String alt = mgr.findSoForSymbol(symbol);
					if (alt != null && !alt.equals(soId)) {
						soId = alt;
						ensureBridgeLoaded(client, soId, d);
						dec = decompileWithRetry(client, soId, symbol);
					} else {
						throw e;
					}
				} else {
					throw e;
				}
			}
			String disasm;
			try {
				DisassembleResult dis = client.disassemble(soId, symbol);
				disasm = dis == null ? null : dis.disassembly;
			} catch (BridgeException e) {
				disasm = "; disassembly unavailable: " + BridgeMessages.forFailure(e.getKind(), symbol, client.getBaseUrl());
			}
			if (javaRef == null) {
				javaRef = reverseJavaRef(client, soId, symbol);
			}
			NativeFunctionView view = new NativeFunctionView(soId, symbol, dec.address, dec.pseudocode, disasm, javaRef);
			viewCache.put(cacheKey(soId, symbol), view);
			currentSoId = soId;
			d.showFunction(view);
			if (nameGuess) {
				d.flashStatus(NAME_GUESS_STATUS);
			}
			maybeWarnGhidraVersion(d);
		} catch (BridgeException e) {
			if (e.getKind() == BridgeException.Kind.EXTERNAL_SYMBOL) {
				// Not a failure: the user clicked an import (libc, liblog, ...). Say where the code
				// actually lives instead of reporting a lookup that "failed".
				LOG.debug("External symbol requested: {}", symbol);
				d.showToast("↗", "External function",
						symbol + " is imported from another library, so this APK carries only a "
								+ "stub for it — there is no code here to decompile.");
				return;
			}
			LOG.warn("Native view fetch failed for {} [{}]", symbol, e.getKind(), e);
			if (silentNotFound && e.getKind() == BridgeException.Kind.NOT_FOUND) {
				d.showUnresolved(symbol, "The library holds no function named " + symbol + ". It may "
						+ "belong to a different library or ABI, or have been inlined or stripped.");
			} else {
				d.showError(symbol, BridgeMessages.forFailure(e.getKind(), symbol, client.getBaseUrl(), e.getMessage()));
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (IOException e) {
			LOG.warn("Native lib extraction failed for {}", symbol, e);
			d.showError(symbol, "Failed to extract native library: " + e.getMessage());
		}
	}

	/**
	 * Single entry point for every "Report Bug" control (global menu, Native View toolbar button,
	 * and the error-only button): map whatever the dialog was showing onto a prefilled issue.
	 */
	private void reportBug(BugReportContext ctx) {
		String pv = PluginVersion.get();
		String gv = currentGhidraVersion();
		String title;
		String body;
		switch (ctx.kind()) {
			case ERROR -> {
				title = BugReportUtil.errorTitle(ctx.symbol());
				body = BugReportUtil.errorBody(ctx.symbol(), ctx.message(), currentSoId, pv, gv);
			}
			case FUNCTION -> {
				title = BugReportUtil.functionTitle(ctx.symbol());
				body = BugReportUtil.functionBody(ctx.symbol(), ctx.address(), currentSoId, pv, gv);
			}
			default -> {
				title = BugReportUtil.blankTitle();
				body = BugReportUtil.blankBody(pv, gv);
			}
		}
		fileIssue(title, body);
	}

	private String currentGhidraVersion() {
		return embeddedBridge == null ? null : embeddedBridge.getGhidraVersion();
	}

	/** Build the prefilled issue URL, open it in the browser, and tell the user what happened. */
	private void fileIssue(String title, String body) {
		String url = BugReportUtil.issueUrl(title, body);
		BugReportUtil.Outcome outcome = BugReportUtil.open(url, BugReportUtil.DESKTOP_OPENER);
		JFrame parent = context.getGuiContext() == null ? null : context.getGuiContext().getMainFrame();
		switch (outcome) {
			case OPENED_IN_BROWSER -> {
				// browser opened; nothing more to say
			}
			case COPIED_TO_CLIPBOARD -> JOptionPane.showMessageDialog(parent,
					"Couldn't open a browser automatically.\nThe prefilled issue URL was copied to your clipboard — paste it into your browser to submit.",
					"Jexray — Report a Bug", JOptionPane.INFORMATION_MESSAGE);
			case FAILED -> JOptionPane.showMessageDialog(parent,
					"Couldn't open a browser or copy to the clipboard.\nPlease file an issue manually at:\nhttps://github.com/cys7885/jexray/issues",
					"Jexray — Report a Bug", JOptionPane.WARNING_MESSAGE);
			default -> {
			}
		}
	}

	/** Show plugin + Ghidra version in the dialog, warning once (status flash) if untested. */
	private void maybeWarnGhidraVersion(NativeViewDialog d) {
		String gver = embeddedBridge == null ? null : embeddedBridge.getGhidraVersion();
		String warning = embeddedBridge == null ? null : embeddedBridge.getVersionWarning();
		d.setVersionInfo(PluginVersion.get(), gver, warning != null, warning);
		if (warning != null && !versionWarningShown) {
			versionWarningShown = true;
			d.flashStatus(warning);
		}
	}

	/** Lazily build the multi-.so index from the loaded input(s). */
	private SoManager getSoManager() {
		SoManager m = soManager;
		if (m == null) {
			synchronized (this) {
				m = soManager;
				if (m == null) {
					List<File> inputs = context.getArgs().getInputFiles();
					m = new SoManager(inputs, options.getAbiPreference(), cacheDir);
					soManager = m;
				}
			}
		}
		return m;
	}

	/**
	 * Ensure a specific .so is imported+analyzed in the bridge: submit it (async 202) then
	 * poll {@code /status} until {@code ready}, reporting progress. No-op once ready.
	 */
	private void ensureBridgeLoaded(GhidraBridgeClient client, String soId, NativeViewDialog d)
			throws IOException, InterruptedException, BridgeException {
		if (readySoIds.contains(soId)) {
			return;
		}
		synchronized (loadLock) {
			if (readySoIds.contains(soId)) {
				return;
			}
			ExtractedSo es = getSoManager().extractedForId(soId);
			if (es == null) {
				throw new IOException("no native library found for id " + soId);
			}
			String soName = es.entry().soName();
			client.load(es.path().toAbsolutePath().toString(), soId); // 202 accepted

			// time spent queued behind another library must not count against this one
			LoadDeadline deadline = new LoadDeadline(LOAD_TIMEOUT_MS, System.currentTimeMillis());
			while (true) {
				StatusResult st = client.status(soId);
				String status = st.status == null ? "" : st.status;
				if ("ready".equals(status)) {
					functionCountBySoId.put(soId, st.total);
					readySoIds.add(soId);
					LOG.info("Native lib {} (abi={}) ready in bridge as soId={} ({} functions)",
							soName, es.entry().abi(), soId, st.total);
					return;
				}
				if ("error".equals(status)) {
					throw new BridgeException(BridgeException.Kind.HTTP_ERROR,
							st.message == null || st.message.isEmpty() ? "library analysis failed" : st.message);
				}
				deadline.onStatus(status, System.currentTimeMillis());
				if (d != null) {
					d.showLoadProgress(soName, status, st.completed, st.total, st.message);
				}
				if (deadline.isExpired(System.currentTimeMillis())) {
					// not an analysis timeout: the analysis may well still be running. This only
					// means the bridge stopped answering, so say that rather than blaming the
					// library's analysis for a failure it didn't have.
					throw new BridgeException(BridgeException.Kind.CONNECTION_FAILED,
							"The analysis bridge stopped responding (no reply for "
									+ (LOAD_TIMEOUT_MS / 1000) + "s). The analysis itself may still be running.");
				}
				Thread.sleep(LOAD_POLL_MS);
			}
		}
	}

	/** One-shot retry for the rare 409 race (query fired just before ready propagated). */
	private DecompileResult decompileWithRetry(GhidraBridgeClient client, String soId, String symbol)
			throws BridgeException, InterruptedException {
		try {
			return client.decompile(soId, symbol);
		} catch (BridgeException e) {
			if (e.getKind() != BridgeException.Kind.STILL_LOADING) {
				throw e;
			}
			Thread.sleep(LOAD_POLL_MS);
			return client.decompile(soId, symbol);
		}
	}

	private record RegMatch(String soId, String symbol) {
	}

	// Shown when a native method is resolved only by the name-match heuristic (resolveByNameHeuristic):
	// the mapping is a guess, so the UI must not present it as a confirmed Java<->native binding.
	private static final String NAME_GUESS_STATUS =
			"Estimated by name match (not a confirmed mapping) — RegisterNatives was not resolvable, "
			+ "so this is the only library function whose name equals the Java method.";

	/**
	 * Last-resort ESTIMATE when a native method resolves neither to an exported JNI symbol nor to a
	 * RegisterNatives entry: if exactly one already-analyzed library defines a function whose name is
	 * exactly the Java method name, return it. RegisterNatives imposes no naming rule -- many apps
	 * merely happen to name the implementation after the Java method -- so this is a heuristic guess;
	 * callers MUST surface it as an estimate (see {@link #NAME_GUESS_STATUS}), never as a confirmed
	 * mapping. Auto-selects only on a unique match: 0 or 2+ exact-name matches return {@code null}
	 * rather than fabricate one. Searches only libraries already loaded ({@link #readySoIds}) so it
	 * never triggers fresh analysis merely to guess -- by this point {@code resolveViaRegisterNatives}
	 * has already loaded every {@code JNI_OnLoad} library, the likely home of a dynamic registration.
	 */
	/** Two names for the same function, allowing for a single leading underscore on either side. */
	private static boolean sameNativeName(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		return a.equals(b) || ("_" + a).equals(b) || a.equals("_" + b);
	}

	/**
	 * The Java {@code native} method a function reached by its native name implements, or null when
	 * nothing claims it. Tries the library's registration table first -- the only authoritative
	 * answer for a dynamically bound method -- then the by-name fallback.
	 *
	 * <p>Never throws. Its answer decides one thing, whether "Go to Java Source" is enabled, so it
	 * must not be able to cost the user the pseudocode as well: the caller builds and shows the view
	 * only after this returns, and its catch list covers the bridge's own failures, so an unexpected
	 * one escaping this far would end the worker and leave the dialog loading with no explanation.
	 */
	private ICodeNodeRef reverseJavaRef(GhidraBridgeClient client, String soId, String symbol) {
		try {
			// This symbol isn't any Java method's exported JNI name (the index checked in
			// openSymbol), but it may be a RegisterNatives target reached by its Ghidra name -- e.g.
			// following a call from a JNI_OnLoad registrar, or picking it straight from All
			// Functions. Reverse-match it against the same table resolveViaRegisterNatives uses
			// going the other way.
			NativeMethod registered = lookupRegistered(registeredNativeRefs(client, soId), symbol);
			return registered != null ? registered.ref() : javaRefByName(symbol);
		} catch (RuntimeException e) {
			LOG.warn("Could not look up a Java method for a function in {}; leaving it unlinked", soId, e);
			return null;
		}
	}

	/**
	 * Every {@code native} method in the input, keyed by JNI export symbol.
	 *
	 * <p>The decompile pass only records the methods it has visited -- in jadx-gui, the classes the
	 * user has opened -- so on its own it answers differently depending on where the user has been.
	 * Unioning it with the metadata-only scan of the whole input removes that dependence: a lookup
	 * gives the same answer whether the function is reached from its Java method or picked straight
	 * out of the browser. The pass's entry wins on overlap, being the one built from a node the GUI
	 * has already materialised.
	 */
	private Map<String, NativeMethod> allNativeMethods() {
		Map<String, NativeMethod> merged = new HashMap<>(getEagerNativeMethodIndex());
		merged.putAll(nativeMethodPass.getNativeMethods());
		return merged;
	}

	/**
	 * The Java {@code native} method a symbol implements, found by name.
	 *
	 * <p>Only reached when the registration table could not answer -- which includes every library
	 * that binds its methods without a {@code JNI_OnLoad} of its own, where that table is never
	 * consulted at all. Without this, opening such a function from the browser leaves it with no
	 * way back to Java even though navigating from Java reaches it perfectly well.
	 *
	 * <p>Returns null when more than one Java method could claim the symbol: a guess that picks
	 * arbitrarily between them would send the user somewhere false, which is worse than leaving
	 * the button disabled. Two entries of {@link #allNativeMethods} are always two different Java
	 * methods -- the map is keyed by export symbol -- so a second match is reason enough to stop,
	 * including when both declare the same method name in different classes.
	 */
	private ICodeNodeRef javaRefByName(String symbol) {
		if (symbol == null || symbol.isEmpty()) {
			return null;
		}
		NativeMethod unique = null;
		for (NativeMethod nm : allNativeMethods().values()) {
			if (nm == null || !sameNativeName(nm.methodName(), symbol)) {
				continue;
			}
			if (unique != null) {
				LOG.info("Name-match for {} is ambiguous across Java methods; not guessing", symbol);
				return null;
			}
			unique = nm;
		}
		return unique == null ? null : unique.ref();
	}

	/**
	 * What each resolution route was asked and what it answered, in one line fit for an error
	 * message. Counts only -- the routes themselves are named, the symbols are not, so this can be
	 * pasted into a report without carrying the name of whatever was being analysed.
	 */
	private String describeResolutionAttempts(SoManager mgr, String mangled, NativeMethod nativeCtx) {
		StringBuilder sb = new StringBuilder("Tried: exported symbol (")
				.append(mgr.soIdsWithExport(mangled).size()).append(" libraries)");
		int registrars = mgr.soIdsWithExport("JNI_OnLoad").size();
		sb.append("; RegisterNatives table (").append(registrars)
				.append(registrars == 1 ? " library exports JNI_OnLoad)" : " libraries export JNI_OnLoad)");
		if (nativeCtx != null && nativeCtx.methodName() != null) {
			String want = nativeCtx.methodName();
			sb.append("; name match (").append(mgr.soIdsWithExport(want).size())
					.append(" for the method name, ").append(mgr.soIdsWithExport("_" + want).size())
					.append(" with a leading underscore)");
		} else {
			sb.append("; name match (skipped: opened without a Java method)");
		}
		return sb.append('.').toString();
	}

	/**
	 * Which of several same-named candidates actually implements {@code nm}.
	 *
	 * <p>The name alone cannot say -- more than one library can export it -- but the runtime does
	 * not decide by name either: a class's {@code native} methods are served by the library that
	 * class loads. That load site is already known from the bytecode scan, so narrow the candidates
	 * to the libraries the declaring class asks for.
	 *
	 * <p>Null when that still leaves a choice (the class loads several candidates, or none of them),
	 * so the caller can ask rather than pick arbitrarily.
	 */
	private String pickOwningLibrary(NativeMethod nm, List<String> candidates) {
		String declaring = nm == null ? null : nm.classBinaryName();
		if (declaring == null) {
			return null;
		}
		Set<String> loadedNames = new HashSet<>();
		for (LoadLibraryDetector.LoadLibraryCall call : getLoadLibraryCalls()) {
			if (call == null || call.rawArg() == null || !declaring.equals(call.classBinaryName())) {
				continue;
			}
			loadedNames.add("lib" + call.rawArg() + ".so"); // Android resolves loadLibrary(x) to libx.so
		}
		if (loadedNames.isEmpty()) {
			return null;
		}
		Map<String, String> soNames = getSoManager().soIdToName();
		List<String> narrowed = new ArrayList<>();
		for (String soId : candidates) {
			if (loadedNames.contains(soNames.get(soId))) {
				narrowed.add(soId);
			}
		}
		return narrowed.size() == 1 ? narrowed.get(0) : null;
	}

	/**
	 * Offer the matching functions in a list and let the user open one.
	 *
	 * <p>Reached only when the app itself does not say which is right: several libraries carry a
	 * function of this name and the declaring class loads them all.
	 *
	 * <p>A vertical list rather than a dropdown or a row of buttons: every candidate stays visible
	 * and is read the same way, nothing is pre-selected as though it were recommended -- the very
	 * thing this dialog exists to say it cannot judge -- and the list still reads sensibly if a
	 * library count larger than a handful ever turns up. Double-clicking a row opens it.
	 *
	 * <p>Blocks the calling worker until answered; the open cannot proceed without it. Dismissing
	 * opens nothing, which is not an error -- the user declined to guess, as the plugin did.
	 */
	private String askWhichCandidate(String methodName, String symbol, List<String> soIds) {
		Map<String, String> soNames = getSoManager().soIdToName();
		String[] labels = new String[soIds.size()];
		for (int i = 0; i < soIds.size(); i++) {
			String lib = soNames.get(soIds.get(i));
			labels[i] = lib == null ? soIds.get(i) : lib;
		}
		final int[] chosen = { -1 };
		Runnable ask = () -> {
			JFrame parent = context.getGuiContext() == null ? null : context.getGuiContext().getMainFrame();

			javax.swing.JList<String> list = new javax.swing.JList<>(labels);
			list.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
			list.setVisibleRowCount(Math.min(labels.length, 8));
			javax.swing.JScrollPane scroller = new javax.swing.JScrollPane(list);

			javax.swing.JPanel panel = new javax.swing.JPanel(new java.awt.BorderLayout(0, 8));
			panel.add(new javax.swing.JLabel("<html><body style='width:360px'>"
					+ "<b>" + soIds.size() + " libraries define <code>" + symbol + "</code>.</b>"
					+ "<br><br>The class declaring <code>" + methodName + "</code> loads them all, so "
					+ "nothing in the app identifies which one implements it — the match is by name "
					+ "alone.<br><br>Open it from:</body></html>"), java.awt.BorderLayout.NORTH);
			panel.add(scroller, java.awt.BorderLayout.CENTER);

			javax.swing.JOptionPane pane = new javax.swing.JOptionPane(panel,
					JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
			javax.swing.JDialog dialog = pane.createDialog(parent, "Jexray — more than one match");
			list.addMouseListener(new java.awt.event.MouseAdapter() {
				@Override
				public void mouseClicked(java.awt.event.MouseEvent e) {
					if (e.getClickCount() == 2 && list.getSelectedIndex() >= 0) {
						pane.setValue(JOptionPane.OK_OPTION);
						dialog.setVisible(false);
					}
				}
			});
			dialog.setVisible(true);
			dialog.dispose();
			Object v = pane.getValue();
			boolean ok = v instanceof Integer && (Integer) v == JOptionPane.OK_OPTION;
			chosen[0] = ok ? list.getSelectedIndex() : -1;
		};
		try {
			if (javax.swing.SwingUtilities.isEventDispatchThread()) {
				ask.run();
			} else {
				javax.swing.SwingUtilities.invokeAndWait(ask);
			}
		} catch (Exception e) {
			LOG.warn("Could not offer the matching functions for {}", methodName, e);
			return null;
		}
		int idx = chosen[0];
		boolean valid = idx >= 0 && idx < soIds.size();
		LOG.info("Name-match for {}: {} candidates, opened {}", methodName, soIds.size(),
				valid ? soIds.get(idx) : "none (dismissed)");
		return valid ? soIds.get(idx) : null;
	}

	private RegMatch resolveByNameHeuristic(GhidraBridgeClient client, NativeMethod nm) {
		String want = nm.methodName();
		if (want == null || want.isEmpty()) {
			return null;
		}
		// The symbol table answers without Ghidra, so a library that has not been analysed yet can
		// still be identified -- the scan below only sees analysed ones, and a method opened before
		// its library's turn would otherwise come back unresolved.
		LOG.info("Name-match heuristic: Java method {} -> trying exports {} and _{}", want, want, want);
		for (String candidate : new String[] { want, "_" + want }) {
			List<String> owners = getSoManager().soIdsWithExport(candidate);
			LOG.info("Name-match heuristic: {} exported by {} librar{}", candidate, owners.size(),
					owners.size() == 1 ? "y" : "ies");
			if (owners.size() == 1) {
				LOG.info("Name-match heuristic resolved {} -> {} in {}", want, candidate, owners.get(0));
				return new RegMatch(owners.get(0), candidate);
			}
			if (owners.size() > 1) {
				// Found, more than once -- so reporting it missing would be the opposite of what
				// happened. The runtime settles this by which library the declaring class loads,
				// so narrow by that first, and only ask when even that leaves a choice.
				String picked = pickOwningLibrary(nm, owners);
				if (picked == null) {
					// Even the load sites do not separate them -- a class that loads both leaves the
					// name as the only link, and the name is what is ambiguous. The user knows which
					// they meant; nothing in the binaries does.
					picked = askWhichCandidate(want, candidate, owners);
				}
				if (picked != null) {
					return new RegMatch(picked, candidate);
				}
				LOG.info("Name-match ambiguous for {}: {} libraries, left unresolved", want, owners.size());
				return null;
			}
		}
		RegMatch unique = null;
		for (String soId : readySoIds) {
			try {
				SearchResult sr = client.search(soId, want);
				if (sr == null || sr.functions == null) {
					continue;
				}
				for (FunctionRef fr : sr.functions) {
					// search is substring + case-insensitive; require a whole-name match here,
					// allowing the leading underscore some toolchains add -- the same tolerance the
					// symbol lookup already applies, without which a library that prefixes its
					// names matches nothing at all.
					if (fr == null || fr.name == null || !sameNativeName(want, fr.name)) {
						continue;
					}
					if (unique != null && !(unique.soId().equals(soId) && unique.symbol().equals(fr.name))) {
						// more than one distinct library function is named exactly this -> ambiguous,
						// refuse to guess rather than pick arbitrarily.
						LOG.info("Name-match heuristic ambiguous for {}: multiple functions named {}", want, want);
						return null;
					}
					unique = new RegMatch(soId, fr.name);
				}
			} catch (BridgeException e) {
				// one library's search failing shouldn't abort the guess across the others
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return null;
			}
		}
		if (unique != null) {
			LOG.info("Name-match heuristic (ESTIMATE) resolved {} -> {} in {}",
					want, unique.symbol(), unique.soId());
		}
		return unique;
	}

	/**
	 * Fallback for a native method with no exported JNI symbol: scan the RegisterNatives
	 * mapping of each .so that exports {@code JNI_OnLoad} for an entry matching this method's
	 * name (and signature when available), returning the owning .so + the real function name.
	 */
	private RegMatch resolveViaRegisterNatives(GhidraBridgeClient client, SoManager mgr, NativeMethod nm,
			NativeViewDialog d) throws IOException, InterruptedException, BridgeException {
		for (String soId : mgr.soIdsWithExport("JNI_OnLoad")) {
			ensureBridgeLoaded(client, soId, d);
			RegisterNativesResult rn = client.registerNatives(soId);
			if (rn == null || rn.methods == null) {
				continue;
			}
			for (RegNative e : rn.methods) {
				if (e == null || e.name == null || e.symbol == null) {
					continue;
				}
				boolean nameMatch = nm.methodName().equals(e.name);
				boolean sigOk = nm.signature() == null || e.signature == null
						|| nm.signature().equals(e.signature);
				if (nameMatch && sigOk) {
					LOG.info("RegisterNatives resolved {}{} -> {} in {}",
							nm.methodName(), nm.signature(), e.symbol, soId);
					return new RegMatch(soId, e.symbol);
				}
			}
		}
		return null;
	}

	/**
	 * Reverse of {@link #resolveViaRegisterNatives}: map {@code soId}'s RegisterNatives table
	 * back onto the Java native methods that register each entry, so a function reached by its
	 * Ghidra name (All Functions, following a call) -- rather than by clicking the Java method
	 * itself -- can still resolve a "Go to Java Source" target even though it has no exported
	 * JNI symbol to be found by the forward index in {@link NativeMethodPass}.
	 *
	 * <p>Costs one bridge call, so it's only attempted for .so's that export {@code JNI_OnLoad}
	 * (RegisterNatives is meaningless otherwise) and only from the already-backgrounded fetch
	 * path -- never from the synchronous cache-hit branch in {@code openSymbol}, which can run on
	 * the EDT. The result is cached per soId (matching {@link #readySoIds}'s lifetime: cleared
	 * alongside {@link #viewCache} on {@link #forceReanalyze}), so this bridge round trip happens
	 * at most once per library rather than once per unresolved open.
	 */
	/**
	 * The registration entry for {@code symbol}, tolerating a single leading-underscore difference.
	 *
	 * <p>The forward direction already does this -- a request for a name finds the symbol whether
	 * or not a toolchain prefixed it with '_'. Going the other way used to demand an exact match,
	 * so opening the prefixed form of a registered function found nothing and left it without a
	 * link back to Java, even though navigating from Java had just reached it.
	 */
	private static NativeMethod lookupRegistered(Map<String, NativeMethod> bySymbol, String symbol) {
		if (bySymbol.isEmpty() || symbol == null || symbol.isEmpty()) {
			return null;
		}
		NativeMethod hit = bySymbol.get(symbol);
		if (hit != null) {
			return hit;
		}
		hit = bySymbol.get("_" + symbol);
		if (hit != null) {
			return hit;
		}
		return symbol.startsWith("_") ? bySymbol.get(symbol.substring(1)) : null;
	}

	private Map<String, NativeMethod> registeredNativeRefs(GhidraBridgeClient client, String soId) {
		// An empty result is not memoised: it means the registration table itself could not be read
		// (a bridge call that failed or came back before analysis settled), and caching that would
		// keep the link to Java missing for the rest of the session even once the table is readable.
		Map<String, NativeMethod> known = registeredNativeRefsBySoId.get(soId);
		if (known != null && !known.isEmpty()) {
			return known;
		}
		Map<String, NativeMethod> computed = computeRegisteredNativeRefs(client, soId);
		if (!computed.isEmpty()) {
			registeredNativeRefsBySoId.put(soId, computed);
		}
		return computed;
	}

	private Map<String, NativeMethod> computeRegisteredNativeRefs(GhidraBridgeClient client, String soId) {
		return ((java.util.function.Function<String, Map<String, NativeMethod>>) (id -> {
			if (!getSoManager().soIdsWithExport("JNI_OnLoad").contains(id)) {
				return Map.of();
			}
			try {
				RegisterNativesResult rn = client.registerNatives(id);
				if (rn == null || rn.methods == null) {
					return Map.of();
				}
				Map<String, NativeMethod> out = new java.util.HashMap<>();
				// Whole-input, so which classes the user has opened cannot change the answer.
				Collection<NativeMethod> candidates = allNativeMethods().values();
				for (RegNative e : rn.methods) {
					if (e == null || e.name == null || e.symbol == null) {
						continue;
					}
					for (NativeMethod nm : candidates) {
						boolean nameMatch = nm.methodName().equals(e.name);
						boolean sigOk = nm.signature() == null || e.signature == null
								|| nm.signature().equals(e.signature);
						if (nameMatch && sigOk) {
							out.put(e.symbol, nm);
							break;
						}
					}
				}
				return out;
			} catch (BridgeException ex) {
				LOG.warn("RegisterNatives reverse lookup failed [{}] for {}", ex.getKind(), id, ex);
				return Map.of();
			} catch (InterruptedException ex) {
				Thread.currentThread().interrupt();
				return Map.of();
			}
		})).apply(soId);
	}

	private synchronized NativeViewDialog getOrCreateDialog(JadxGuiContext gui) {
		if (dialog == null) {
			JFrame parent = gui == null ? null : gui.getMainFrame();
			dialog = new NativeViewDialog(
					parent,
					// Go to Java Source: jump to the declaration and raise the main window
					this::openInJadx,
					// Ctrl/Cmd-click a call in pseudocode: follow it within the current .so
					// (no Java ref, 404 is silent). Cross-.so calls fall back to a symbol scan.
					// follow a call using the library the displayed pseudocode belongs to
					(viewSoId, symbol) -> openSymbol(symbol, null, true,
							viewSoId != null ? viewSoId : currentSoId),
					// Sync toggle: start/stop caret polling
					this::setSyncEnabled,
					// All Functions: browse the whole library
					this::showAllFunctions,
					// Report Bug (toolbar, always) / Report this error: prefilled GitHub issue
					gui == null ? null : this::reportBug,
					// Cache: disk usage + clear
					this::showCacheDialog,
					// Xrefs ("who calls this?"): scoped to the library the displayed function
					// came from, same soId source as the call-following callback above
					this::showXrefs,
					// Loaded Libraries: which .so's the app asks the VM to load (Native-View-only)
					this::showLoadedLibraries,
					// jadx's own SVG icons (null under CLI / when unavailable -> text-only buttons)
					gui == null ? null : gui::getSVGIcon);
			// Change: populate the toolbar version label the moment the dialog exists, not only
			// after the first successful decompile (previously the only caller of setVersionInfo
			// was fetchAndShow's maybeWarnGhidraVersion). The Ghidra version may still be null
			// here if the embedded bridge hasn't finished starting -- setVersionInfo shows the
			// plugin version with an honest "Ghidra ?" placeholder in that case (never a fabricated
			// number), and the bridge-starter thread above refreshes the label once the version is
			// actually known.
			maybeWarnGhidraVersion(dialog);
		}
		return dialog;
	}

	/**
	 * "Open Native View" entry point: show the dialog and pre-warm the bridge for the current
	 * (or first available) .so in the background, so the first real lookup is instant -- but
	 * without popping the All Functions picker open uninvited.
	 */
	private void openNativeViewEager() {
		JadxGuiContext gui = context.getGuiContext();
		NativeViewDialog d = getOrCreateDialog(gui);
		d.presentForUserAction(); // explicit menu action: reopen even if previously dismissed
		SoManager mgr = getSoManager();
		if (!mgr.hasNativeLibraries()) {
			return; // nothing to pre-warm; leave the empty-state dialog as is
		}
		List<String> ids = mgr.soIds();
		if (readySoIds.containsAll(ids)) {
			return; // every library already warm; code area already in a settled state
		}
		d.beginPrewarm(ids.size());
		Thread worker = new Thread(() -> prewarmAll(ids, d), "jexray-eager-load");
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * Submit every library at once and then poll them together. The bridge analyzes several at a
	 * time on a bounded pool, so there is no single "current" library to step through -- throttling
	 * is the bridge's job and progress is aggregated across all of them here.
	 */
	private void prewarmAll(List<String> ids, NativeViewDialog d) {
		GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
		SoManager mgr = getSoManager();
		Map<String, String> soNames = mgr.soIdToName();
		Map<String, Long> soSizes = mgr.soIdToSize();
		Map<String, LoadDeadline> deadlines = new LinkedHashMap<>();
		Map<String, LibState> latest = new LinkedHashMap<>();
		Set<String> pending = new LinkedHashSet<>();
		// first moment each soId was observed past "queued" -- real wall-clock, not an invented
		// analysis start time, since the bridge doesn't report one
		Map<String, Long> analyzingSinceMs = new LinkedHashMap<>();
		int totalFunctions = 0;
		int failed = 0;

		for (String soId : ids) {
			try {
				ExtractedSo es = mgr.extractedForId(soId);
				if (es == null) {
					throw new IOException("no native library found for id " + soId);
				}
				client.load(es.path().toAbsolutePath().toString(), soId); // 202 accepted
				deadlines.put(soId, new LoadDeadline(LOAD_TIMEOUT_MS, System.currentTimeMillis()));
				latest.put(soId, new LibState("queued", 0, 0));
				pending.add(soId);
			} catch (Exception e) {
				failed++;
				latest.put(soId, new LibState("error", 0, 0));
				LOG.warn("Eager pre-warm: could not submit {}", soId, e);
			}
		}
		d.showPrewarmProgress(PrewarmProgress.of(new ArrayList<>(latest.values())));

		// polling cost, so the rate can be judged rather than guessed (see prewarm poll log below)
		long polls = 0;
		long pollNanos = 0;

		while (!pending.isEmpty()) {
			for (String soId : new ArrayList<>(pending)) {
				try {
					long t0 = System.nanoTime();
					StatusResult st = client.status(soId);
					pollNanos += System.nanoTime() - t0;
					polls++;

					String status = st.status == null ? "" : st.status;
					latest.put(soId, toLibState(soId, status, st.completed, st.total, soNames, soSizes, analyzingSinceMs));
					if ("ready".equals(status)) {
						functionCountBySoId.put(soId, st.total);
						readySoIds.add(soId);
						totalFunctions += st.total;
						pending.remove(soId);
						continue;
					}
					if ("error".equals(status)) {
						failed++;
						pending.remove(soId);
						LOG.warn("Eager pre-warm failed for {}: {}", soId, st.message);
						d.flashStatus(BridgeMessages.forFailure(BridgeException.Kind.HTTP_ERROR,
								"(pre-warm)", client.getBaseUrl(), st.message));
						continue;
					}
					LoadDeadline dl = deadlines.get(soId);
					dl.onStatus(status, System.currentTimeMillis());
					if (dl.isExpired(System.currentTimeMillis())) {
						failed++;
						pending.remove(soId);
						latest.put(soId, new LibState("error", 0, 0));
						LOG.warn("Eager pre-warm timed out for {}", soId);
					}
				} catch (BridgeException e) {
					failed++;
					pending.remove(soId);
					latest.put(soId, new LibState("error", 0, 0));
					LOG.warn("Eager pre-warm status failed [{}] for {}", e.getKind(), soId, e);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return;
				}
			}
			d.showPrewarmProgress(PrewarmProgress.of(new ArrayList<>(latest.values())));
			if (pending.isEmpty()) {
				break;
			}
			try {
				Thread.sleep(LOAD_POLL_MS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return;
			}
		}

		if (polls > 0) {
			LOG.info("Pre-warm polling: {} status calls, mean {} ms/call across {} libraries",
					polls, String.format("%.2f", pollNanos / 1_000_000.0 / polls), ids.size());
		}

		int loaded = ids.size() - failed;
		String summary = loaded > 0
				? readySummary(loaded, totalFunctions)
						+ (failed == 0 ? "" : " (" + failed + " librar" + (failed == 1 ? "y" : "ies") + " failed)")
				: "Analysis failed for " + failed + " librar" + (failed == 1 ? "y" : "ies")
						+ " — check the Ghidra install directory in Preferences.";
		d.showReady(summary); // guarded: won't clobber a function the user opened mid-load
	}

	/**
	 * Build the {@link LibState} for one polled status, attaching name/size/start-time only for
	 * the "analyzing" bucket (anything not queued/ready/error) -- that's the only case
	 * {@link PrewarmProgress#analyzingLine()} uses it for, and the other states have no analysis
	 * in progress to describe.
	 */
	private static LibState toLibState(String soId, String status, int completed, int total,
			Map<String, String> soNames, Map<String, Long> soSizes, Map<String, Long> analyzingSinceMs) {
		if ("queued".equals(status) || "ready".equals(status) || "error".equals(status)) {
			return new LibState(status, completed, total);
		}
		long since = analyzingSinceMs.computeIfAbsent(soId, id -> System.currentTimeMillis());
		return new LibState(status, completed, total, soNames.get(soId), soSizes.getOrDefault(soId, 0L), since);
	}

	private static String readySummary(int libraries, int functions) {
		return "Ready — " + functions + " function" + (functions == 1 ? "" : "s")
				+ " across " + libraries + " librar" + (libraries == 1 ? "y" : "ies") + " analyzed.";
	}

	/** Open the All Functions picker for the current .so (or the first available). */
	private void showAllFunctions() {
		JadxGuiContext gui = context.getGuiContext();
		NativeViewDialog d = getOrCreateDialog(gui);
		SoManager mgr = getSoManager();
		if (!mgr.hasNativeLibraries()) {
			d.showError("(all functions)", "No native library (lib/*/*.so) found in the loaded input.");
			return;
		}
		List<String> ids = mgr.soIds();
		String soId = (currentSoId != null && ids.contains(currentSoId)) ? currentSoId : ids.get(0);
		loadFunctionsAndShowPicker(soId);
	}

	/** Load a specific .so (on demand) and (re)populate the function picker with its functions. */
	/**
	 * Analyze every native library in the APK, one after another on a single background thread.
	 *
	 * <p>Sequential on purpose: {@code analyzeHeadless} is CPU- and memory-hungry, and running one
	 * per library at once would starve the machine and the UI along with it. Libraries already
	 * analyzed are skipped by {@link #ensureBridgeLoaded}, so calling this repeatedly costs nothing
	 * beyond the walk, and a failure on one library must not stop the rest -- the user asked for
	 * everything, not for everything up to the first problem.
	 */
	/**
	 * Start a full sweep when a Jexray window is opened, if the user left that on. Fire-and-forget:
	 * the window opens immediately and libraries become browsable as each finishes, rather than the
	 * window waiting on the whole APK.
	 */
	private void maybeAnalyzeAllOnBrowse() {
		if (options.isAnalyzeAllOnBrowse()) {
			analyzeAllLibraries();
		}
	}

	private void analyzeAllLibraries() {
		if (!analyzeAllInFlight.compareAndSet(false, true)) {
			return; // one sweep at a time; a second request would only queue behind the first
		}
		Thread worker = new Thread(() -> {
			try {
				GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
				for (String soId : getSoManager().soIds()) {
					if (readySoIds.contains(soId)) {
						continue;
					}
					try {
						ensureBridgeLoaded(client, soId, null);
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						return;
					} catch (Exception e) {
						LOG.warn("Analyze-all: {} failed, continuing", soId, e);
					}
				}
			} catch (Exception e) {
				LOG.warn("Analyze-all could not start", e);
			} finally {
				analyzeAllInFlight.set(false);
			}
		}, "jexray-analyze-all");
		worker.setDaemon(true);
		worker.start();
	}

	private void loadFunctionsAndShowPicker(String soId) {
		maybeAnalyzeAllOnBrowse();
		JadxGuiContext gui = context.getGuiContext();
		NativeViewDialog d = getOrCreateDialog(gui);
		Thread worker = new Thread(() -> {
			GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
			try {
				ensureBridgeLoaded(client, soId, d);
				// empty query returns every function (substring match against "")
				SearchResult res = client.search(soId, "");
				List<String> names = new ArrayList<>();
				Set<String> external = new HashSet<>();
				if (res.functions != null) {
					for (FunctionRef f : res.functions) {
						if (f != null && f.name != null) {
							names.add(f.name);
							if (f.external) {
								external.add(f.name);
							}
						}
					}
				}
				Collections.sort(names);
				externalNamesBySoId.put(soId, external);
				exportedNamesBySoId.put(soId, dynamicExportsOf(soId));
				registeredNamesBySoId.put(soId, registeredSymbolsOf(client, soId));
				showFunctionPicker(gui, soId, names);
			} catch (BridgeException e) {
				LOG.warn("All-functions listing failed [{}]", e.getKind(), e);
				d.showError("(all functions)", BridgeMessages.forFailure(e.getKind(), "(all)", client.getBaseUrl(), e.getMessage()));
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			} catch (IOException e) {
				LOG.warn("All-functions listing: extraction failed", e);
				d.showError("(all functions)", "Failed to extract native library: " + e.getMessage());
			}
		}, "jexray-all-functions");
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * {@link com.jexray.jadx.ui.LibraryTreePanel.MatchCounter}: how many of {@code soId}'s
	 * functions match {@code query}, for the "All Functions" total. Reuses the bridge's existing
	 * server-side substring search rather than pulling the whole (possibly very large) function
	 * list to the client just to count it locally. Runs on its own thread, same as every other
	 * bridge call from this class -- {@code onResult} is documented to tolerate being invoked from
	 * any thread, so no extra marshaling is needed here.
	 */
	private void countMatches(String soId, String query, java.util.function.IntConsumer onResult) {
		Thread worker = new Thread(() -> {
			GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
			try {
				SearchResult res = client.search(soId, query);
				onResult.accept(res.functions == null ? 0 : res.functions.size());
			} catch (BridgeException e) {
				// transient failure: report nothing rather than a wrong count. The label stays on
				// "counting…" for this library, which remains true, instead of settling on a total
				// that silently omitted it.
				LOG.warn("Match count failed for {} (query={}) [{}]", soId, query, e.getKind(), e);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}, "jexray-count-" + soId);
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * discard {@code soId}'s cache and re-run Ghidra on it, even though the bridge
	 * already has a (possibly stale, possibly suspect) result cached. Runs on its own thread with
	 * no shared lock, so it proceeds independently of whatever else is analyzing -- unlike
	 * {@link #ensureBridgeLoaded}, which serializes through {@link #loadLock} to avoid duplicate
	 * concurrent loads of the *same* .so, that guard doesn't apply here (this soId is deliberately
	 * being reloaded) and reusing it would block this on an unrelated library's on-demand load.
	 */
	private void forceReanalyze(String soId) {
		SoManager mgr = getSoManager();
		JadxGuiContext gui = context.getGuiContext();
		NativeViewDialog d = getOrCreateDialog(gui);

		reanalyzingSoIds.add(soId);
		readySoIds.remove(soId);
		functionCountBySoId.remove(soId);
		// the old cache's pseudocode/disassembly must never be served again once the user asked
		// to discard it, even for functions already resolved into viewCache
		viewCache.keySet().removeIf(k -> k.startsWith(soId + " "));
		// the RegisterNatives table this indexed may itself change across a re-analysis
		registeredNativeRefsBySoId.remove(soId);
		refreshLibraryTree();

		Thread worker = new Thread(() -> {
			GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
			try {
				ExtractedSo es = mgr.extractedForId(soId);
				if (es == null) {
					throw new IOException("no native library found for id " + soId);
				}
				String soName = es.entry().soName();
				client.load(es.path().toAbsolutePath().toString(), soId, true); // force

				LoadDeadline deadline = new LoadDeadline(LOAD_TIMEOUT_MS, System.currentTimeMillis());
				while (true) {
					StatusResult st = client.status(soId);
					String status = st.status == null ? "" : st.status;
					if ("ready".equals(status)) {
						functionCountBySoId.put(soId, st.total);
						readySoIds.add(soId);
						LOG.info("Force re-analyze complete: soId={} ({} functions)", soId, st.total);
						break;
					}
					if ("error".equals(status)) {
						LOG.warn("Force re-analyze failed for {}: {}", soId, st.message);
						d.flashStatus(BridgeMessages.forFailure(BridgeException.Kind.HTTP_ERROR,
								"(re-analyze) " + soName, client.getBaseUrl(), st.message));
						break;
					}
					deadline.onStatus(status, System.currentTimeMillis());
					d.showLoadProgress(soName, status, st.completed, st.total, st.message);
					refreshLibraryTree();
					if (deadline.isExpired(System.currentTimeMillis())) {
						LOG.warn("Force re-analyze: bridge stopped responding for {}", soId);
						d.flashStatus("The analysis bridge stopped responding while re-analyzing "
								+ soName + ". The analysis itself may still be running.");
						break;
					}
					Thread.sleep(LOAD_POLL_MS);
				}
			} catch (BridgeException e) {
				LOG.warn("Force re-analyze request failed [{}] for {}", e.getKind(), soId, e);
				d.flashStatus(BridgeMessages.forFailure(e.getKind(), "(re-analyze)", client.getBaseUrl(), e.getMessage()));
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			} catch (IOException e) {
				LOG.warn("Force re-analyze: extraction failed for {}", soId, e);
				d.flashStatus("Failed to extract native library for re-analysis: " + e.getMessage());
			} finally {
				reanalyzingSoIds.remove(soId);
				refreshLibraryTree();
			}
		}, "jexray-reanalyze-" + soId);
		worker.setDaemon(true);
		worker.start();
	}

	/** Push the current library list to the open "All Functions" picker, if any (no-op otherwise). */
	private void refreshLibraryTree() {
		if (functionListDialog == null) {
			return;
		}
		List<LibraryEntry> libs = describeLibraries();
		JadxGuiContext gui = context.getGuiContext();
		Runnable r = () -> functionListDialog.setLibraries(libs);
		if (gui != null) {
			gui.uiRun(r);
		} else {
			r.run();
		}
	}

	/**
	 * show the on-disk analysis cache's size and let the user clear it. Reads
	 * through the bridge (not direct filesystem access from here) so the number always reflects
	 * what the bridge would actually reuse, and so clearing it also drops whatever the bridge is
	 * still holding in memory -- see {@code EmbeddedGhidraBridge}'s {@code /cache/clear} handler.
	 */
	private void showCacheDialog() {
		JadxGuiContext gui = context.getGuiContext();
		JFrame parent = gui == null ? null : gui.getMainFrame();
		Thread worker = new Thread(() -> {
			GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
			try {
				CacheStatsResult stats = client.cacheStats();
				Runnable show = () -> new CacheDialog(parent, stats, this::onCacheClearRequested).setVisible(true);
				if (gui != null) {
					gui.uiRun(show);
				} else {
					show.run();
				}
			} catch (Exception e) {
				LOG.warn("Failed to read cache stats", e);
				NativeViewDialog d = getOrCreateDialog(gui);
				d.flashStatus("Could not read the analysis cache: " + e.getMessage());
			}
		}, "jexray-cache-stats");
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * @param clearAll true clears every cached analysis (active + legacy); false clears only the
	 *                 unused legacy (pre-content-hash) entries.
	 */
	private void onCacheClearRequested(boolean clearAll) {
		GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
		try {
			ClearCacheResult r = client.clearCache(!clearAll);
			if (clearAll) {
				// every cached result this process knows about is gone on disk and in the
				// bridge's memory (see /cache/clear); nothing here is valid to keep either
				readySoIds.clear();
				functionCountBySoId.clear();
				viewCache.clear();
				registeredNativeRefsBySoId.clear();
			}
			LOG.info("Cache clear ({}): freed {}", clearAll ? "all" : "legacy", HumanFormat.formatSize(r.freedBytes));
			refreshLibraryTree();
		} catch (Exception e) {
			LOG.warn("Cache clear failed", e);
			getOrCreateDialog(context.getGuiContext()).flashStatus("Cache clear failed: " + e.getMessage());
		}
	}

	/**
	 * "Show xrefs" (toolbar "X" / right-click): fetch the callers of {@code symbol} within
	 * {@code soId} and hand them to the dialog. {@code soId} always names an already-loaded
	 * library here -- it comes from the function the dialog is currently displaying, which can
	 * only be on screen after {@link #ensureBridgeLoaded} already ran for it -- so this queries
	 * directly rather than repeating that load/poll dance.
	 */
	private void showXrefs(String soId, String symbol) {
		if (soId == null || symbol == null) {
			return;
		}
		NativeViewDialog d = getOrCreateDialog(context.getGuiContext());
		Thread worker = new Thread(() -> {
			GhidraBridgeClient client = new GhidraBridgeClient(resolveBridgeUrl());
			try {
				XrefsResult res = client.xrefs(soId, symbol);
				List<XrefEntry> callers = new ArrayList<>();
				if (res.callers != null) {
					for (CallerRef c : res.callers) {
						if (c != null && c.name != null) {
							callers.add(new XrefEntry(c.name, c.address));
						}
					}
				}
				d.showXrefs(new XrefsView(soId, symbol, res.xrefsKnown, callers));
			} catch (BridgeException e) {
				if (e.getKind() == BridgeException.Kind.EXTERNAL_SYMBOL) {
					// Same answer the decompile path gives: an import has no body here, so it has
					// no callers here either. Not a lookup failure.
					LOG.debug("Xrefs requested for external symbol: {}", symbol);
					d.showToast("↗", "External function",
							symbol + " is imported from another library, so this APK carries only a "
									+ "stub for it — there are no callers to list here.");
					return;
				}
				LOG.warn("Xrefs lookup failed [{}] for {} in {}", e.getKind(), symbol, soId, e);
				d.flashStatus("Xrefs lookup failed: "
						+ BridgeMessages.forFailure(e.getKind(), symbol, client.getBaseUrl(), e.getMessage()));
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}, "jexray-xrefs-" + soId);
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * Jump to {@code ref} in the main jadx window and raise it. Shared by "Go to Java Source" and
	 * a Loaded Libraries load-site click -- both just want the same "show me this Java method" jump.
	 */
	private void openInJadx(ICodeNodeRef ref) {
		JadxGuiContext gui = context.getGuiContext();
		if (gui != null && ref != null) {
			gui.uiRun(() -> {
				gui.open(ref);
				JFrame main = gui.getMainFrame();
				if (main != null) {
					main.toFront();
					main.requestFocus();
				}
			});
		}
	}

	/**
	 * "Loaded Libraries" (Native View toolbar): show
	 * which .so's this app asks the VM to load, correlated against what's actually in the APK --
	 * see {@link LoadedLibrariesModel} for the resolved/unresolved/unloaded split.
	 *
	 * <p>Deliberately does NOT source this from {@link NativeMethodPass}'s per-method call sites:
	 * that pass only runs (via jadx's {@code JadxDecompilePass} machinery) for classes the user has
	 * already opened, so a {@code loadLibrary} call in an unopened class -- typically a
	 * {@code <clinit>} nobody ever browses to -- would silently be missing from a window whose
	 * whole point is completeness. Instead this scans every class's raw dex instructions directly
	 * ({@link LoadLibraryBytecodeScanner}), which needs no class to have been decompiled. That scan
	 * (memoized in {@link #loadLibraryCalls} after the first run) is still real work across a large
	 * app's whole method set, so it runs off the EDT with a "scanning…" placeholder shown in the
	 * meantime; {@link SoManager}'s APK metadata this correlates against needs no Ghidra bridge
	 * either, so none of this depends on any library having been analyzed.
	 */
	private void showLoadedLibraries() {
		maybeAnalyzeAllOnBrowse();
		JadxGuiContext gui = context.getGuiContext();
		JFrame parent = gui == null ? null : gui.getMainFrame();
		if (loadedLibrariesDialog == null) {
			loadedLibrariesDialog = new LoadedLibrariesDialog(parent, this::openInJadx, this::loadLoadedLibraryFunctions,
					this::readLoadedLibraryFunctionsForCount);
			// Same handler the All Functions browser uses: open against the library the node sits
			// under, not whatever was last viewed.
			loadedLibrariesDialog.setOnPickFunction(
					(pickedSoId, name) -> openSymbol(name, null, false, pickedSoId));
		}
		loadedLibrariesDialog.surface();

		List<LoadLibraryDetector.LoadLibraryCall> cached = loadLibraryCalls;
		if (cached != null) {
			loadedLibrariesDialog.setResult(LoadedLibrariesModel.build(cached, getSoManager()));
			return;
		}
		loadedLibrariesDialog.setScanning();
		Thread worker = new Thread(() -> {
			LoadedLibrariesModel.Result result = LoadedLibrariesModel.build(getLoadLibraryCalls(), getSoManager());
			JadxGuiContext gui2 = context.getGuiContext();
			Runnable push = () -> {
				if (loadedLibrariesDialog != null) {
					loadedLibrariesDialog.setResult(result);
				}
			};
			if (gui2 != null) {
				gui2.uiRun(push);
			} else {
				push.run();
			}
		}, "jexray-loaded-libraries-scan");
		worker.setDaemon(true);
		worker.start();
	}

	/** Lazily scan the whole input's raw dex instructions for load-call sites (see
	 * {@link LoadLibraryBytecodeScanner}); memoized like {@link #getSoManager()} since the input's
	 * classes never change after project load. */
	private List<LoadLibraryDetector.LoadLibraryCall> getLoadLibraryCalls() {
		List<LoadLibraryDetector.LoadLibraryCall> c = loadLibraryCalls;
		if (c == null) {
			synchronized (this) {
				c = loadLibraryCalls;
				if (c == null) {
					c = LoadLibraryBytecodeScanner.scanAll(context.getDecompiler().getRoot());
					loadLibraryCalls = c;
				}
			}
		}
		return c;
	}

	/**
	 * Lazily build the jniSymbol -> NativeMethod index by walking every class's methods and
	 * resolving the native ones straight from metadata (access flags, declaring class/method
	 * names and types) -- the same facts {@link NativeMethodResolver#resolve} already uses, all
	 * available without decompiling a single method body. Mirrors
	 * {@link LoadLibraryBytecodeScanner#scanAll} in spirit (a raw, un-decompiled pass over
	 * {@code root.getClasses()}), though this one doesn't even need to read bytecode: "native" is
	 * an access flag on the method itself.
	 *
	 * <p>Built once, on the first javaRef lookup that {@link #nativeMethodPass}'s lazy map cannot
	 * answer -- in either direction, from a Java method or back from a native one (see
	 * {@code openSymbol} and {@link #allNativeMethods}) -- and memoized like
	 * {@link #getLoadLibraryCalls()}, so a session pays this at most once. Being a lazy singleton
	 * guarded by the plugin monitor, whichever thread builds it holds that monitor for the walk;
	 * the other holders are short (see {@link #getSoManager()}, {@link #getOrCreateDialog}), and
	 * the walk itself takes no further lock, so it cannot deadlock against them.
	 */
	private Map<String, NativeMethod> getEagerNativeMethodIndex() {
		Map<String, NativeMethod> idx = eagerNativeMethodIndex;
		if (idx == null) {
			synchronized (this) {
				idx = eagerNativeMethodIndex;
				if (idx == null) {
					Map<String, NativeMethod> built = new HashMap<>();
					for (ClassNode cls : context.getDecompiler().getRoot().getClasses()) {
						for (MethodNode mth : cls.getMethods()) {
							if (NativeMethodResolver.isNative(mth)) {
								NativeMethod nm = NativeMethodResolver.resolve(mth);
								built.put(nm.jniSymbol(), nm);
							}
						}
					}
					idx = built;
					eagerNativeMethodIndex = idx;
				}
			}
		}
		return idx;
	}

	/**
	 * Lazy-expand callback for the Loaded Libraries tree: read {@code soId}'s exported function
	 * names and push them to the dialog, off the EDT (extraction touches disk). Deliberately never
	 * touches the Ghidra bridge -- see {@link #readLoadedLibraryFunctions} for the actual read,
	 * which is a local ELF/Mach-O symbol-table parse only.
	 */
	private void loadLoadedLibraryFunctions(String soId) {
		Thread worker = new Thread(() -> {
			List<String> names;
			try {
				names = readLoadedLibraryFunctions(soId);
			} catch (IOException e) {
				LOG.warn("Loaded Libraries: failed to read symbols for {}", soId, e);
				names = List.of();
			}
			List<String> finalNames = names;
			JadxGuiContext gui = context.getGuiContext();
			// Read locally, off the EDT, alongside the names they classify. Whatever the bridge has
			// already told us about registrations is folded in; a library it has not analysed simply
			// contributes none, and groups on the two facts the file itself can answer.
			Set<String> imported = importedSymbolsOf(soId);
			Set<String> exported = dynamicExportsOf(soId);
			Set<String> registered = registeredNamesBySoId.getOrDefault(soId, Set.of());
			Runnable push = () -> {
				if (loadedLibrariesDialog != null) {
					loadedLibrariesDialog.setSymbolFacts(soId, imported, exported, registered);
					loadedLibrariesDialog.setFunctions(soId, finalNames);
				}
			};
			if (gui != null) {
				gui.uiRun(push);
			} else {
				push.run();
			}
		}, "jexray-loaded-libs-" + soId);
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * {@link com.jexray.jadx.ui.LoadedLibrariesPanel.FunctionReader}: reads {@code soId}'s exported
	 * function names for the Loaded Libraries bottom count label, off the EDT. Reuses
	 * {@link #readLoadedLibraryFunctions} -- the same local ELF/Mach-O symbol-table parse the lazy
	 * tree-expand path ({@link #loadLoadedLibraryFunctions}) already uses -- rather than a second
	 * read path, so the count and the tree can never disagree about what a library exports.
	 * Reports a null list on failure rather than swallowing it into an empty one: unlike the
	 * tree-expand path, which treats "couldn't read" and "genuinely no exports" the same for a
	 * placeholder label, the count label must tell those apart to avoid folding a real failure into
	 * a fabricated zero (see {@link com.jexray.jadx.ui.LoadedLibrariesPanel.FunctionReader}).
	 */
	private void readLoadedLibraryFunctionsForCount(String soId, java.util.function.Consumer<List<String>> onResult) {
		Thread worker = new Thread(() -> {
			try {
				onResult.accept(readLoadedLibraryFunctions(soId));
			} catch (IOException e) {
				LOG.warn("Loaded Libraries count: failed to read symbols for {}", soId, e);
				onResult.accept(null);
			}
		}, "jexray-loaded-libs-count-" + soId);
		worker.setDaemon(true);
		worker.start();
	}

	/**
	 * What {@code soId} publishes in its dynamic symbol table, read straight from the extracted
	 * library. Read here rather than taken from the analysis cache because it is a linkage fact
	 * about the file, not something the decompiler determines. An unreadable library yields an
	 * empty set, which groups everything defined as internal -- the behaviour before this existed.
	 */
	/**
	 * The names {@code soId} links against but does not define, read from the file itself.
	 *
	 * <p>The All Functions browser learns this from the bridge's own listing, which needs the
	 * library analysed first. The Loaded Libraries window shows libraries before any of that has
	 * happened, so it reads the symbol table directly -- the same fact by a cheaper route, so the
	 * two windows can group a symbol the same way without one of them waiting on Ghidra.
	 */
	private Set<String> importedSymbolsOf(String soId) {
		try {
			ExtractedSo es = getSoManager().extractedForId(soId);
			return es == null ? Set.of() : NativeSymbols.importedSymbols(es.path().toFile());
		} catch (IOException e) {
			LOG.warn("Could not read imported symbols for {}", soId, e);
			return Set.of();
		}
	}

	private Set<String> dynamicExportsOf(String soId) {
		try {
			ExtractedSo es = getSoManager().extractedForId(soId);
			return es == null ? Set.of() : NativeSymbols.dynamicExports(es.path().toFile());
		} catch (IOException e) {
			LOG.warn("Could not read dynamic exports for {}", soId, e);
			return Set.of();
		}
	}

	/**
	 * The functions a library binds to Java through {@code RegisterNatives}, by symbol.
	 *
	 * <p>Deliberately not {@link #registeredNativeRefs}: that one keeps only the entries it can pair
	 * with a Java method, because its job is to hand back a reference to navigate to. Grouping needs
	 * no such reference -- the registration table alone establishes that a function is an entry
	 * point -- so an entry belongs in this set even when no Java method claims it.
	 */
	private Set<String> registeredSymbolsOf(GhidraBridgeClient client, String soId) {
		return registeredSymbolsBySoId.computeIfAbsent(soId, id -> {
			if (!getSoManager().soIdsWithExport("JNI_OnLoad").contains(id)) {
				return Set.of(); // nothing registers without a JNI_OnLoad to do it in
			}
			try {
				RegisterNativesResult rn = client.registerNatives(id);
				if (rn == null || rn.methods == null) {
					return Set.of();
				}
				Set<String> out = new HashSet<>();
				for (RegNative e : rn.methods) {
					if (e != null && e.symbol != null && !e.symbol.isEmpty()) {
						out.add(e.symbol);
					}
				}
				return out;
			} catch (BridgeException ex) {
				LOG.warn("RegisterNatives listing failed [{}] for {}", ex.getKind(), id, ex);
				return Set.of();
			} catch (InterruptedException ex) {
				Thread.currentThread().interrupt();
				return Set.of();
			}
		});
	}

	private synchronized void showFunctionPicker(JadxGuiContext gui, String soId, List<String> names) {
		List<LibraryEntry> libraries = describeLibraries();
		Runnable show = () -> {
			if (functionListDialog == null) {
				JFrame parent = gui == null ? null : gui.getMainFrame();
				functionListDialog = new FunctionListDialog(parent, libraries, soId, new ArrayList<>(names),
						// picked from a specific library's list -> open against THAT .so directly
						(pickedSoId, name) -> openSymbol(name, null, false, pickedSoId),
						this::loadFunctionsAndShowPicker,
						this::forceReanalyze,
						this::countMatches);
			} else {
				functionListDialog.setLibraries(libraries);
				functionListDialog.update(soId, names);
			}
			// after the names, so the browser already has the entries these apply to
			functionListDialog.setExternalNames(soId, externalNamesBySoId.get(soId));
			functionListDialog.setExportedNames(soId, exportedNamesBySoId.get(soId));
			functionListDialog.setRegisteredNativeNames(soId, registeredNamesBySoId.get(soId));
			functionListDialog.surface();
		};
		if (gui != null) {
			gui.uiRun(show);
		} else {
			show.run();
		}
	}

	/**
	 * Current state of every native library, for the library tree. Sizes come from the APK entry so
	 * they are known without extracting or analyzing anything.
	 */
	private List<LibraryEntry> describeLibraries() {
		SoManager mgr = getSoManager();
		Map<String, String> names = mgr.soIdToName();
		Map<String, Long> sizes = mgr.soIdToSize();
		List<LibraryEntry> out = new ArrayList<>();
		for (Map.Entry<String, String> e : names.entrySet()) {
			String id = e.getKey();
			long size = sizes.getOrDefault(id, 0L);
			LibraryEntry.Status status = readySoIds.contains(id)
					? LibraryEntry.Status.READY
					: reanalyzingSoIds.contains(id)
							? LibraryEntry.Status.ANALYZING
							: LibraryEntry.Status.NOT_ANALYZED;
			// -1 (unknown, not 0) is what LibraryEntry.statusLabel renders as "ready" with no
			// count -- it should never actually hit that path since functionCountBySoId is always
			// filled before a soId is marked ready, but a fabricated 0 would be worse if it did
			int functionCount = functionCountBySoId.getOrDefault(id, -1);
			out.add(new LibraryEntry(id, e.getValue(), size, status, functionCount, 0));
		}
		return out;
	}

	private void setSyncEnabled(boolean enabled) {
		JadxGuiContext gui = context.getGuiContext();
		if (gui == null) {
			return;
		}
		if (enabled) {
			syncDebouncer.reset();
			if (syncTimer == null) {
				syncTimer = new Timer(SYNC_POLL_MS, e -> pollCaretForSync());
				syncTimer.setRepeats(true);
			}
			syncTimer.start();
		} else if (syncTimer != null) {
			syncTimer.stop();
		}
	}

	/**
	 * Runs on the EDT (Swing Timer). Opens the native method under the caret only once it
	 * has rested there long enough (debounced) and it differs from what is shown.
	 */
	private void pollCaretForSync() {
		JadxGuiContext gui = context.getGuiContext();
		if (gui == null || dialog == null || !dialog.isVisible() || !dialog.isSyncEnabled()) {
			return;
		}
		ICodeNodeRef ref = gui.getEnclosingNodeUnderCaret();
		NativeMethod nm = NativeMethodResolver.resolveFromRef(ref);
		String candidate = nm == null ? null : nm.jniSymbol();
		String toOpen = syncDebouncer.onPoll(dialog.currentSymbol(), candidate, System.currentTimeMillis());
		if (toOpen != null) {
			// silentNotFound = true: sync is a passive "follow my caret" feature, so a caret landing
			// on a native method whose symbol isn't in a loaded library (dynamically registered via
			// RegisterNatives, in a different .so, etc.) must NOT dump a "function not found" error
			// over the function the user is looking at -- the user didn't ask to open it. A miss just
			// flashes a brief status and leaves the current view intact. An explicit click still
			// reports not-found loudly (silentNotFound = false on those paths).
			openSymbol(toOpen, nm == null ? null : nm.ref(), true, null, nm);
		}
	}

	/**
	 * The exported function names for {@code soId}, read directly from its extracted .so's
	 * ELF/Mach-O symbol table via {@link NativeSymbols#exportedSymbols} -- no Ghidra analysis, no
	 * bridge call of any kind, so this is safe to run before (or without ever) analyzing the
	 * library.
	 */
	List<String> readLoadedLibraryFunctions(String soId) throws IOException {
		SoManager mgr = getSoManager();
		ExtractedSo es = mgr.extractedForId(soId);
		List<String> names = es == null ? new ArrayList<>() : new ArrayList<>(NativeSymbols.exportedSymbols(es.path().toFile()));
		Collections.sort(names);
		return names;
	}
}
