package com.jexray.jadx.export;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import com.jexray.jadx.bridge.BridgeException;
import com.jexray.jadx.bridge.BridgeModels.FunctionRef;
import com.jexray.jadx.ui.LibraryTreePanel;

/**
 * Writes the analyzed native libraries out to disk as a browsable project: one folder per
 * library, mirroring the <b>exact</b> group structure the Native View's "All Functions" tree
 * shows ({@code JNI methods} / {@code Functions} / {@code Exports} / {@code Imports}), and one
 * file per function holding its Ghidra pseudocode ({@code .c}) and/or disassembly
 * ({@code .asm}).
 *
 * <p>Grouping is not re-derived here: {@link LibraryTreePanel#groupFor} is the single place the
 * tree decides what a symbol <em>is</em>, and this exporter calls that very method, so a file can
 * never land under one heading on disk when the tree would show it under another.
 *
 * <p>Imports (symbols linked in from another library) have no body in this {@code .so}, so there
 * is nothing real to export for them -- but leaving them out would silently amputate one of the
 * tree's four groups. They are written as stub files that say so, so the exported structure stays
 * complete and self-explanatory.
 *
 * <p>Deliberately free of Swing: the caller (the plugin) drives it from a worker thread and
 * surfaces {@link Progress} however it likes. One failure never stops the run -- a function that
 * won't decompile, or a library whose analysis fails, is counted and listed in the manifest while
 * everything else keeps exporting. A run that is cancelled mid-way writes an honest
 * "cancelled" manifest describing what did get out.
 */
public final class ProjectExporter {

	/** One native library to export: its bridge id and its display file name. */
	public record Library(String soId, String name) {
		public String displayName() {
			return name == null || name.isEmpty() ? soId : name;
		}
	}

	/**
	 * How the exported tree is laid out. The default is {@link #SINGLE_FILES}: most people just
	 * want the code in a text editor or an LLM context, and one file per library reads straight
	 * through. {@link #SPLIT} is the exact mirror of the All Functions browser, for browsing a
	 * large project on disk file-by-file.
	 */
	public enum Layout {
		/** One {@code <library>.c} / {@code <library>.asm} per library; banner per function. */
		SINGLE_FILES("Single file per library"),
		/** One folder per library mirroring the tree's groups; one file per function. */
		SPLIT("Split by category and method");

		private final String label;

		Layout(String label) {
			this.label = label;
		}

		/** The name as the export dialog shows it. */
		public String label() {
			return label;
		}
	}

	/** What the user asked for: where to write, which views, and in which layout. */
	public record Options(Path rootDir, boolean pseudocode, boolean disassembly, Layout layout) {
		public Options {
			if (rootDir == null) {
				throw new IllegalArgumentException("rootDir");
			}
			if (!pseudocode && !disassembly) {
				throw new IllegalArgumentException("at least one of pseudocode/disassembly is required");
			}
			if (layout == null) {
				throw new IllegalArgumentException("layout");
			}
		}

		/** Convenience for the default layout: one file per library ({@link Layout#SINGLE_FILES}). */
		public Options(Path rootDir, boolean pseudocode, boolean disassembly) {
			this(rootDir, pseudocode, disassembly, Layout.SINGLE_FILES);
		}
	}

	/** The per-library content this exporter reads. One implementation adapts the bridge. */
	public interface FunctionSource {
		/** Every function the library lists, with {@code external} set for linked-in imports. */
		List<FunctionRef> listFunctions(String soId) throws BridgeException, InterruptedException;

		/** Ghidra's decompiled pseudocode for {@code name}. */
		String pseudocode(String soId, String name) throws BridgeException, InterruptedException;

		/** Ghidra's disassembly for {@code name}. */
		String disassembly(String soId, String name) throws BridgeException, InterruptedException;

		/** What {@code soId} publishes in its dynamic symbol table (a linkage fact, grouping only). */
		Set<String> exportedSymbols(String soId);

		/** The functions {@code soId} binds to Java via {@code RegisterNatives} (grouping only). */
		Set<String> registeredSymbols(String soId);
	}

	/** Makes sure a library is analyzed in the bridge before its functions are fetched. */
	@FunctionalInterface
	public interface Analyzer {
		/**
		 * Blocks until {@code soId} is ready. The {@link AnalysisWatch} keeps the run live while
		 * that happens: it forwards the bridge's own status (so the analyzing phase can show
		 * function-level progress instead of a frozen bar) and it is polled for cancellation, so
		 * Cancel takes effect while Ghidra is still working -- not merely between libraries.
		 */
		void ensureAnalyzed(String soId, AnalysisWatch watch)
				throws IOException, InterruptedException, BridgeException;
	}

	/** Progress + cancellation for one library's analysis phase; see {@link Analyzer}. */
	public interface AnalysisWatch {
		/** True the moment the user asked the run to stop; implementations poll this and throw
		 * {@link InterruptedException} as soon as they see it. */
		boolean cancelled();

		/** The bridge's own status for the library under analysis: its state, how many functions
		 * it has analyzed so far (0/0 while unknown, e.g. queued), and its current task text. */
		void onStatus(String status, int completed, int total, String message);
	}

	/** Where a run currently is. Called from the exporter's own thread, once per function. */
	public interface ProgressListener {
		void onProgress(Progress p);

		/**
		 * One library reached its final outcome (exported, or why it produced nothing).
		 * {@code index} is its position in the run's library list, so a UI can keep one status
		 * row per library and finalize the right one.
		 */
		default void onLibraryDone(int index, LibraryResult r) {
		}
	}

	/**
	 * One progress sample. {@code phase} is {@code "analyzing"} while Ghidra is still working on
	 * the library -- {@code doneFunctions}/{@code totalFunctions} then carry the bridge's own
	 * analysis counts (0/0 while unknown, e.g. queued), which makes even that phase determinate;
	 * {@code "exporting"} while files are being written, counting the listed functions of the
	 * current library, imports included. {@code detail} is the bridge's current task text, if any.
	 */
	public record Progress(int libIndex, int libCount, String libraryName, String phase,
			int doneFunctions, int totalFunctions, String detail) {
		/** Overall determinate percentage across all libraries, or -1 while nothing is measurable. */
		public int overallPercent() {
			if (libCount <= 0 || totalFunctions <= 0
					|| (!"exporting".equals(phase) && !"analyzing".equals(phase))) {
				return -1;
			}
			int idx = Math.max(0, Math.min(libIndex, libCount - 1));
			double within = Math.min(1.0, (double) doneFunctions / totalFunctions);
			return Math.max(0, Math.min(100, (int) Math.round((idx + within) / libCount * 100.0)));
		}
	}

	/** What one library produced (or why it produced nothing). */
	public record LibraryResult(String name, int functions, int filesWritten, int failedFunctions,
			String error) {
		public boolean failed() {
			return error != null;
		}
	}

	/** The whole run: counts, per-library outcomes, and everything worth telling the user. */
	public record Result(boolean cancelled, int filesWritten, int functions, int failedFunctions,
			List<Library> libraries, List<LibraryResult> libraryResults, List<String> problems,
			Path rootDir) {

		public String summary() {
			String where = " to " + rootDir;
			if (cancelled) {
				return "Export cancelled — " + filesWritten + " file" + (filesWritten == 1 ? "" : "s")
						+ " written" + where + ".";
			}
			int failedLibs = 0;
			for (LibraryResult r : libraryResults) {
				if (r.failed()) {
					failedLibs++;
				}
			}
			String base = "Exported " + filesWritten + " file" + (filesWritten == 1 ? "" : "s")
					+ " from " + libraryResults.size() + " librar"
					+ (libraryResults.size() == 1 ? "y" : "ies") + where;
			if (failedLibs == 0 && failedFunctions == 0 && problems.isEmpty()) {
				return base + ".";
			}
			List<String> bits = new ArrayList<>();
			if (failedLibs > 0) {
				bits.add(failedLibs + " librar" + (failedLibs == 1 ? "y" : "ies") + " failed");
			}
			if (failedFunctions > 0) {
				bits.add(failedFunctions + " function" + (failedFunctions == 1 ? "" : "s") + " failed");
			}
			// "with problems (...)" needs something to put inside the parentheses; when the only
			// issue is recorded elsewhere (e.g. the root itself was unwritable), name the manifest.
			return bits.isEmpty()
					? base + " — see " + MANIFEST_NAME + " for details."
					: base + " with problems (" + String.join(", ", bits) + ") — see "
							+ MANIFEST_NAME + " for details.";
		}

		/**
		 * True only when nothing went wrong: not cancelled, no failed library, no failed function,
		 * and no recorded problem -- an unwritable export root included. This is the exact rule
		 * the dialog auto-closes on. Checking the library list alone is not enough: a run-level
		 * failure (the output folder could not be created) has an <em>empty</em> library list and
		 * must still stay open, and a library whose functions all failed to fetch has no library
		 * error either but must also stay open.
		 */
		public boolean isClean() {
			if (cancelled || failedFunctions > 0 || !problems.isEmpty()) {
				return false;
			}
			for (LibraryResult r : libraryResults) {
				if (r.failed()) {
					return false;
				}
			}
			return true;
		}
	}

	/** Folder name of each group, exactly as the All Functions tree spells them, in tree order. */
	public static final List<String> GROUPS = List.of(
			LibraryTreePanel.GROUP_JNI,
			LibraryTreePanel.GROUP_FUNCTIONS,
			LibraryTreePanel.GROUP_EXPORTS,
			LibraryTreePanel.GROUP_IMPORTS);

	/** The manifest written at the export root, tying the on-disk tree back to Jexray. */
	public static final String MANIFEST_NAME = "jexray-project.txt";

	/** Longer than any plausible symbol; leaves room for a collision suffix and the extension. */
	private static final int MAX_NAME_LENGTH = 150;

	/** Bridge 409 (query raced ahead of "ready") gets one retry, same as the browse path. */
	private static final long RETRY_DELAY_MS = 400;

	/** Cap on problems carried in the manifest, so a pathological run can't write a megabyte of it. */
	private static final int MAX_MANIFEST_PROBLEMS = 200;

	private static final String PSEUDO_EXT = ".c";
	private static final String DISASM_EXT = ".asm";
	/** Suffix of the single-file layout's temp file, moved into place only when complete. */
	private static final String PART_SUFFIX = ".part";

	private final String pluginVersion;
	private final String ghidraVersion;
	private final FunctionSource source;
	private final Analyzer analyzer;

	public ProjectExporter(String pluginVersion, String ghidraVersion, FunctionSource source,
			Analyzer analyzer) {
		this.pluginVersion = pluginVersion == null ? "?" : pluginVersion;
		this.ghidraVersion = ghidraVersion == null || ghidraVersion.isEmpty() ? "unknown" : ghidraVersion;
		this.source = source;
		this.analyzer = analyzer;
	}

	/**
	 * Run the export on the calling thread. Cancellation is checked between libraries and between
	 * functions, and polled continuously while a library is still being analyzed (worst case: the
	 * analysis of one library notices within a poll interval -- the run never waits for Ghidra to
	 * finish just to be allowed to stop). A cancellation during analysis is reported as a
	 * cancelled run, never as a library failure.
	 */
	public Result run(Options options, List<Library> libraries, AtomicBoolean cancelled,
			ProgressListener progress) {
		Path root = options.rootDir();
		List<LibraryResult> results = new ArrayList<>();
		List<String> problems = new ArrayList<>();
		AtomicBoolean stop = cancelled == null ? new AtomicBoolean(false) : cancelled;
		int filesTotal = 0;
		int functionsTotal = 0;
		int failedTotal = 0;
		boolean wasCancelled = false;

		DirNamer libraryDirs = new DirNamer();
		try {
			Files.createDirectories(root);
			int libCount = libraries == null ? 0 : libraries.size();
			for (int i = 0; i < libCount; i++) {
				Library lib = libraries.get(i);
				if (stop.get()) {
					wasCancelled = true;
					break;
				}
				final int libIndex = i;
				String libName = lib.displayName();
				report(progress, new Progress(i, libCount, libName, "analyzing", 0, 0, null));
				// The watch turns the blocking analysis call into a live phase: the bridge's own
				// completed/total counts feed the progress bar, and a Cancel lands within a poll
				// interval instead of after Ghidra's whole run over the library.
				AnalysisWatch watch = new AnalysisWatch() {
					@Override
					public boolean cancelled() {
						return stop.get();
					}

					@Override
					public void onStatus(String status, int completed, int total, String message) {
						report(progress, new Progress(libIndex, libCount, libName, "analyzing",
								completed, total,
								message != null && !message.isEmpty() ? message : status));
					}
				};
				try {
					analyzer.ensureAnalyzed(lib.soId(), watch);
				} catch (Exception e) {
					if (stop.get()) {
						// the watch asked for this stop: a cancelled run, not a failed library
						wasCancelled = true;
						break;
					}
					String why = "analysis failed: " + messageOf(e);
					problems.add(libName + " — " + why);
					LibraryResult failed = new LibraryResult(libName, 0, 0, 0, why);
					results.add(failed);
					reportLibrary(progress, i, failed);
					continue;
				}
				if (stop.get()) {
					wasCancelled = true;
					break;
				}
				report(progress, new Progress(i, libCount, libName, "exporting", 0, 0, null));
				// One reserved name per library: a folder in the split layout, a file base in
				// the single-file one -- either way collisions are handled once, at the root.
				String targetName = libraryDirs.reserve(sanitizeFileName(libName));
				LibraryResult r = exportLibrary(root, targetName, lib, i, libCount, options, stop,
						progress, problems);
				results.add(r);
				reportLibrary(progress, i, r);
				filesTotal += r.filesWritten();
				functionsTotal += r.functions();
				failedTotal += r.failedFunctions();
			}
			if (stop.get()) {
				wasCancelled = true;
			}
			writeManifest(root, options, results, problems, wasCancelled);
		} catch (IOException e) {
			problems.add("could not write to " + root + ": " + e.getMessage());
		}
		return new Result(wasCancelled, filesTotal, functionsTotal, failedTotal,
				libraries == null ? List.of() : List.copyOf(libraries), List.copyOf(results),
				List.copyOf(problems), root);
	}

	/**
	 * Export one already-analyzed library; never throws, always reports its outcome. The layout
	 * decides where a function's content lands: {@link SplitSink} writes one file per function
	 * under the tree's group folders, {@link SingleSink} accumulates every function into one file
	 * per library. Both see the functions in the same order -- groups in tree order, names sorted.
	 */
	private LibraryResult exportLibrary(Path root, String targetName, Library lib, int libIndex,
			int libCount, Options options, AtomicBoolean stop, ProgressListener progress,
			List<String> problems) {
		String libName = lib.displayName();
		List<FunctionRef> functions;
		try {
			functions = source.listFunctions(lib.soId());
		} catch (Exception e) {
			String why = "function listing failed: " + messageOf(e);
			problems.add(libName + " — " + why);
			return new LibraryResult(libName, 0, 0, 0, why);
		}

		// Same three facts rebuildChildren groups the tree by; the external set comes straight
		// from the bridge's listing, the other two from the caller's symbol readers. The grouping
		// drives the split layout's folders directly and the single-file layout's banners, so
		// both stay tied to what the tree would show.
		Set<String> external = new HashSet<>();
		for (FunctionRef f : functions) {
			if (f.external) {
				external.add(f.name);
			}
		}
		Set<String> exported = safe(source.exportedSymbols(lib.soId()));
		Set<String> registered = safe(source.registeredSymbols(lib.soId()));

		// Grouped like the tree, sorted like the tree's (sorted) name list.
		Map<String, List<FunctionRef>> byGroup = new LinkedHashMap<>();
		for (String group : GROUPS) {
			byGroup.put(group, new ArrayList<>());
		}
		for (FunctionRef f : functions) {
			String group = LibraryTreePanel.groupFor(f.name, external, exported, registered);
			List<FunctionRef> bucket = byGroup.get(group);
			(bucket != null ? bucket : byGroup.get(LibraryTreePanel.GROUP_FUNCTIONS)).add(f);
		}
		for (List<FunctionRef> bucket : byGroup.values()) {
			bucket.sort(Comparator.comparing(f -> f.name));
		}

		FunctionSink sink;
		if (options.layout() == Layout.SINGLE_FILES) {
			sink = new SingleSink(root, targetName, lib.soId(), libName, options, problems, external);
		} else {
			Path libDir = root.resolve(targetName);
			try {
				Files.createDirectories(libDir);
			} catch (IOException e) {
				String why = "could not create " + libDir + ": " + e.getMessage();
				problems.add(libName + " — " + why);
				return new LibraryResult(libName, 0, 0, 0, why);
			}
			sink = new SplitSink(libDir, lib.soId(), libName, options, problems, external);
		}

		int total = functions.size();
		int done = 0;
		int crashed = 0;
		for (Map.Entry<String, List<FunctionRef>> entry : byGroup.entrySet()) {
			if (stop.get()) {
				break;
			}
			for (FunctionRef f : entry.getValue()) {
				if (stop.get()) {
					break;
				}
				try {
					sink.accept(f, entry.getKey());
				} catch (RuntimeException e) {
					// nothing should get this far -- every bridge error and every write error is
					// handled on the spot -- but "one broken function never stops a run" has to
					// hold even against a surprise, so count it, record it, and carry on.
					problems.add(libName + "/" + f.name + " — " + messageOf(e));
					crashed++;
				}
				done++;
				report(progress, new Progress(libIndex, libCount, libName, "exporting", done, total, null));
			}
		}
		int files = sink.finish(done, total);
		if (done < total) {
			problems.add(libName + " — cancelled after " + done + " of " + total + " functions");
		}
		return new LibraryResult(libName, total, files, sink.failures() + crashed, null);
	}

	/** Receives a library's functions in tree order; see {@link #exportLibrary}. */
	private interface FunctionSink {
		/** Handle one function (fetching its views lazily). */
		void accept(FunctionRef f, String group);

		/**
		 * Called once after the last accepted function; writes anything held back (the single-file
		 * layout's accumulated content -- the split layout writes as it goes).
		 *
		 * @param done how many functions were accepted, {@code total} how many the library listed
		 * @return files written by this call plus any written while accepting
		 */
		int finish(int done, int total);

		/** Functions where at least one requested view could not be fetched. */
		int failures();
	}

	/**
	 * Split layout: one file per function under {@code <library>/<group>/}, exactly as the All
	 * Functions tree browses it. Writes as it goes, so a cancelled run leaves every finished
	 * function already on disk.
	 */
	private final class SplitSink implements FunctionSink {
		private final Path libDir;
		private final String soId;
		private final String libName;
		private final Options options;
		private final List<String> problems;
		private final Set<String> external;
		private final Map<String, DirNamer> namers = new HashMap<>();
		private int files;
		private int failures;

		SplitSink(Path libDir, String soId, String libName, Options options, List<String> problems,
				Set<String> external) {
			this.libDir = libDir;
			this.soId = soId;
			this.libName = libName;
			this.options = options;
			this.problems = problems;
			this.external = external;
		}

		@Override
		public void accept(FunctionRef f, String group) {
			// One file-namer per group directory: collisions are a directory-scoped concern.
			DirNamer names = namers.computeIfAbsent(group, g -> new DirNamer());
			Path groupDir = libDir.resolve(group);
			String base = names.reserve(sanitizeFileName(f.name));
			// The listing's external flag routes to the stub without a fetch -- an import has no
			// body here, so a request would only come back 410 (which writeSplit also handles,
			// for names the listing failed to mark).
			WriteOutcome outcome = external.contains(f.name)
					? exportImportStub(groupDir, base, libName, f, options)
					: writeSplit(groupDir, base, soId, libName, f, options, problems);
			files += outcome.files();
			if (outcome.failures() > 0) {
				failures++; // one failed function, however many of its views were requested
			}
		}

		@Override
		public int finish(int done, int total) {
			return files; // everything was written while accepting
		}

		@Override
		public int failures() {
			return failures;
		}
	}

	/**
	 * Single-file layout: one {@code <library>.c} / {@code <library>.asm} holding every function
	 * in the tree's order, each behind a banner header (symbol, address, group) so the file still
	 * carries the structure the split layout expresses with folders. Streams each view straight
	 * into a {@code .part} temp file as functions arrive -- nothing accumulates in memory, which
	 * matters on the libraries where the single file runs to megabytes -- and moves the finished
	 * file into place in {@link #finish}, so neither a failure nor a cancel ever leaves a
	 * half-written {@code .c} that looks like a complete export.
	 */
	private final class SingleSink implements FunctionSink {
		private final Path root;
		private final String targetName;
		private final String soId;
		private final String libName;
		private final Options options;
		private final List<String> problems;
		private final Set<String> external;
		/** One streaming writer per requested view, opened on first use; keys are extensions. */
		private final Map<String, BufferedWriter> writers = new HashMap<>();
		private int failures;
		private boolean ioFailed;

		SingleSink(Path root, String targetName, String soId, String libName, Options options,
				List<String> problems, Set<String> external) {
			this.root = root;
			this.targetName = targetName;
			this.soId = soId;
			this.libName = libName;
			this.options = options;
			this.problems = problems;
			this.external = external;
		}

		@Override
		public void accept(FunctionRef f, String group) {
			if (ioFailed) {
				return; // the disk gave up earlier; that failure is already recorded
			}
			// The listing's external flag decides first (same routing the split layout uses):
			// an import has no body here, so there is nothing worth fetching.
			Views v = external.contains(f.name)
					? new Views(null, null, true, false)
					: fetchViews(soId, libName, f, options, problems);
			if (!v.external() && v.failed()) {
				failures++; // one failed function, however many of its views were requested
			}
			try {
				if (options.pseudocode()) {
					Writer w = writer(PSEUDO_EXT);
					banner(w, f, group, libName, "//");
					if (v.external()) {
						w.write("// Imported by " + libName
								+ " — linked in from another library, so this APK's copy has no body.\n\n");
					} else if (v.pseudo() == null) {
						w.write("// (pseudocode unavailable — see " + MANIFEST_NAME + ")\n\n");
					} else {
						w.write(v.pseudo());
						w.write("\n\n");
					}
				}
				if (options.disassembly()) {
					Writer w = writer(DISASM_EXT);
					banner(w, f, group, libName, ";");
					if (v.external()) {
						w.write("; Imported by " + libName
								+ " — linked in from another library, so this APK's copy has no body.\n\n");
					} else if (v.disasm() == null) {
						w.write("; (disassembly unavailable — see " + MANIFEST_NAME + ")\n\n");
					} else {
						w.write(v.disasm());
						w.write("\n\n");
					}
				}
			} catch (IOException e) {
				ioFailed = true;
				failures++; // this function's content did not make it out
				problems.add(libName + " — could not write " + targetName + ": " + e.getMessage());
				closeAll();
				deleteTemps();
			}
		}

		/** The requested view's streaming writer into its {@code .part} temp file. */
		private Writer writer(String ext) throws IOException {
			BufferedWriter w = writers.get(ext);
			if (w == null) {
				Files.createDirectories(root);
				w = Files.newBufferedWriter(root.resolve(targetName + ext + PART_SUFFIX),
						StandardCharsets.UTF_8);
				writers.put(ext, w);
			}
			return w;
		}

		@Override
		public int finish(int done, int total) {
			int written = 0;
			// A run stopped before its first function has nothing worth keeping: no files at all,
			// rather than empty ones that pretend to be an export.
			if (done > 0 && !ioFailed) {
				if (done < total) {
					appendNote(PSEUDO_EXT, "//", done, total);
					appendNote(DISASM_EXT, ";", done, total);
				}
				closeAll(); // before the move: Windows cannot move a file that is still open
				if (options.pseudocode()) {
					written += moveIntoPlace(PSEUDO_EXT);
				}
				if (options.disassembly()) {
					written += moveIntoPlace(DISASM_EXT);
				}
			} else {
				closeAll();
			}
			if (ioFailed) {
				deleteTemps();
			}
			return written;
		}

		/** The trailing "cancelled" note, if that view got as far as a writer at all. */
		private void appendNote(String ext, String comment, int done, int total) {
			Writer w = writers.get(ext);
			if (w == null) {
				return;
			}
			try {
				partialNote(w, done, total, comment);
			} catch (IOException e) {
				problems.add(libName + " — could not finish " + targetName + ext + ": " + e.getMessage());
			}
		}

		/** Close the temp file into its final name; 0 (with the reason recorded) on failure. */
		private int moveIntoPlace(String ext) {
			String name = targetName + ext;
			Path tmp = root.resolve(name + PART_SUFFIX);
			if (!Files.exists(tmp)) {
				return 0; // no function ever wrote to this view
			}
			Path target = root.resolve(name);
			try {
				try {
					Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING,
							StandardCopyOption.ATOMIC_MOVE);
				} catch (AtomicMoveNotSupportedException e) {
					Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
				}
				return 1;
			} catch (IOException e) {
				problems.add(libName + " — could not write " + name + ": " + e.getMessage());
				failures++;
				deleteTemp(ext);
				return 0;
			}
		}

		private void closeAll() {
			for (Writer w : writers.values()) {
				try {
					w.close();
				} catch (IOException e) {
					// nothing sensible to do here; a close failure surfaces as a missing move
				}
			}
		}

		private void deleteTemps() {
			for (String ext : List.copyOf(writers.keySet())) {
				deleteTemp(ext);
			}
		}

		private void deleteTemp(String ext) {
			try {
				Files.deleteIfExists(root.resolve(targetName + ext + PART_SUFFIX));
			} catch (IOException e) {
				// best effort: a leftover .part is noise, never mistaken for exported output
			}
		}

		@Override
		public int failures() {
			return failures;
		}
	}

	/** One banner per function in the single-file layout; {@code comment} is "//" (C) or ";" (asm). */
	private static void banner(Writer b, FunctionRef f, String group, String libName,
			String comment) throws IOException {
		String rule = comment + " ============================================================\n";
		b.write(rule);
		b.write(comment + ' ' + f.name);
		if (f.address != null && !f.address.isEmpty()) {
			b.write(" @ " + f.address);
		}
		b.write('\n');
		b.write(comment + " Group: " + group + " | Library: " + libName + '\n');
		b.write(rule);
		b.write('\n');
	}

	/** Trailing honesty note when a single file holds fewer functions than the library listed. */
	private static void partialNote(Writer b, int done, int total, String comment) throws IOException {
		b.write(comment + " … export cancelled: only " + done + " of "
				+ total + " functions are included here.\n");
	}

	/** Files written, and how many of the selected contents could not be fetched at all. */
	private record WriteOutcome(int files, int failures) {
	}

	/** What the bridge returned for one function's requested views. */
	private record Views(String pseudo, String disasm, boolean external, boolean failed) {
	}

	/** One fetch's outcome: a payload, or why there isn't one. */
	private record Fetch(String text, boolean external, boolean failed) {
		static final Fetch FAILED = new Fetch(null, false, true);
	}

	/**
	 * Fetch whichever views the options selected for one function. {@code external} short-circuits:
	 * the bridge's own "no body here" answer overrides the listing, and no further view is worth
	 * asking for. Anything else that fails is recorded in {@code problems} and flagged
	 * {@code failed} -- never thrown, so one broken function can't stop a library.
	 */
	private Views fetchViews(String soId, String libName, FunctionRef f, Options options,
			List<String> problems) {
		String pseudo = null;
		String disasm = null;
		boolean failed = false;
		if (options.pseudocode()) {
			Fetch r = fetch(() -> source.pseudocode(soId, f.name), f.name, libName, problems);
			if (r.external()) {
				return new Views(null, null, true, false);
			}
			if (r.failed()) {
				failed = true;
			} else {
				pseudo = r.text();
			}
		}
		if (options.disassembly()) {
			Fetch r = fetch(() -> source.disassembly(soId, f.name), f.name, libName, problems);
			if (r.external()) {
				if (pseudo == null) {
					return new Views(null, null, true, false);
				}
				// a body came back for pseudocode but not disassembly: the listing and the
				// bridge disagreeing; fetch already recorded it as a problem
				failed = true;
			} else if (r.failed()) {
				failed = true;
			} else {
				disasm = r.text();
			}
		}
		return new Views(pseudo, disasm, false, failed);
	}

	/** Split layout's per-function write; a body the bridge says doesn't exist becomes a stub. */
	private WriteOutcome writeSplit(Path groupDir, String base, String soId, String libName,
			FunctionRef f, Options options, List<String> problems) {
		Views v = fetchViews(soId, libName, f, options, problems);
		if (v.external()) {
			// the bridge's own answer overrides the listing: this name has no body here
			return exportImportStub(groupDir, base, libName, f, options);
		}
		int files = 0;
		int failures = 0;
		if (options.pseudocode()) {
			if (v.pseudo() == null) {
				failures++;
			} else if (write(fileFor(groupDir, base, PSEUDO_EXT),
					v.pseudo().isEmpty() ? "// (no pseudocode)\n" : v.pseudo()) == 0) {
				problems.add(libName + "/" + f.name + " — could not write " + base + PSEUDO_EXT);
				failures++;
			} else {
				files++;
			}
		}
		if (options.disassembly()) {
			if (v.disasm() == null) {
				failures++;
			} else if (write(fileFor(groupDir, base, DISASM_EXT),
					v.disasm().isEmpty() ? "; (no disassembly)\n" : v.disasm()) == 0) {
				problems.add(libName + "/" + f.name + " — could not write " + base + DISASM_EXT);
				failures++;
			} else {
				files++;
			}
		}
		return new WriteOutcome(files, failures);
	}

	/**
	 * One bridge fetch. Returns {@code failed} on anything but a payload; a
	 * {@code STILL_LOADING} race (409) gets one retry first, same as the browse path. An
	 * {@code EXTERNAL_SYMBOL} answer (410) means the bridge knows this name has no body here --
	 * recorded as a problem so a listing that disagreed with the bridge is visible in the
	 * manifest rather than silently swallowed.
	 */
	private Fetch fetch(BridgeCall call, String name, String libName, List<String> problems) {
		for (int attempt = 0; ; attempt++) {
			try {
				return new Fetch(call.get(), false, false);
			} catch (BridgeException e) {
				if (e.getKind() == BridgeException.Kind.STILL_LOADING && attempt == 0) {
					try {
						Thread.sleep(RETRY_DELAY_MS);
					} catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						problems.add(libName + "/" + name + " — interrupted while loading");
						return Fetch.FAILED;
					}
					continue;
				}
				problems.add(libName + "/" + name + " — " + e.getKind() + ": " + e.getMessage());
				return e.getKind() == BridgeException.Kind.EXTERNAL_SYMBOL
						? new Fetch(null, true, false)
						: Fetch.FAILED;
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				problems.add(libName + "/" + name + " — interrupted");
				return Fetch.FAILED;
			} catch (RuntimeException e) {
				problems.add(libName + "/" + name + " — " + messageOf(e));
				return Fetch.FAILED;
			}
		}
	}

	@FunctionalInterface
	private interface BridgeCall {
		String get() throws BridgeException, InterruptedException;
	}

	/** Write the per-symbol stubs that keep the Imports group (no body in this .so) honest. */
	private WriteOutcome exportImportStub(Path groupDir, String base, String libName, FunctionRef f,
			Options options) {
		int files = 0;
		int failures = 0;
		if (options.pseudocode()) {
			if (write(fileFor(groupDir, base, PSEUDO_EXT),
					"// " + f.name + "\n"
							+ "// Imported by " + libName + " — linked in from another library, so this\n"
							+ "// APK's copy has no body. There is no pseudocode to export here.\n") == 0) {
				failures++;
			} else {
				files++;
			}
		}
		if (options.disassembly()) {
			if (write(fileFor(groupDir, base, DISASM_EXT),
					"; " + f.name + "\n"
							+ "; Imported by " + libName + " — linked in from another library, so this\n"
							+ "; APK's copy has no body. There is no disassembly to export here.\n") == 0) {
				failures++;
			} else {
				files++;
			}
		}
		return new WriteOutcome(files, failures);
	}

	// ------------------------------------------------------------------ writing

	private static Path fileFor(Path dir, String base, String ext) {
		return dir.resolve(base + ext);
	}

	private static int write(Path file, String content) {
		try {
			Files.createDirectories(file.getParent());
			String text = content == null ? "" : content;
			if (!text.isEmpty() && !text.endsWith("\n")) {
				text += "\n";
			}
			Files.write(file, text.getBytes(StandardCharsets.UTF_8));
			return 1;
		} catch (IOException e) {
			return 0;
		}
	}

	/**
	 * The manifest: what this export is, the structure's legend, and an honest per-library
	 * account -- including everything that failed, so a partial export never reads as a complete
	 * one.
	 */
	private void writeManifest(Path root, Options options, List<LibraryResult> results,
			List<String> problems, boolean cancelled) {
		StringBuilder sb = new StringBuilder();
		sb.append("Jexray native project export\n");
		sb.append("============================\n");
		sb.append("Exported : ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append('\n');
		sb.append("Jexray   : ").append(pluginVersion).append('\n');
		sb.append("Ghidra   : ").append(ghidraVersion).append('\n');
		sb.append("Content  : ").append(contentLabel(options)).append('\n');
		sb.append("Layout   : ").append(layoutLabel(options)).append('\n');
		sb.append("Status   : ").append(cancelled ? "CANCELLED (partial)" : "complete").append('\n');
		sb.append('\n');
		if (options.layout() == Layout.SINGLE_FILES) {
			sb.append("Structure (one file per library)\n");
			sb.append("-------------------------------\n");
			sb.append("<library>.c / <library>.asm\n");
			sb.append("    every function, in this tree's order: JNI methods first, then Functions,\n");
			sb.append("    Exports, Imports — a banner header (symbol, address, group) precedes each\n");
			sb.append("    function; imports carry a banner saying they have no body in this copy\n");
		} else {
			sb.append("Structure (mirrors the Native View \"All Functions\" tree)\n");
			sb.append("---------------------------------------------------------\n");
			sb.append("<library>/JNI methods/   entry points a Java native method binds to\n");
			sb.append("                         (Java_* exports and RegisterNatives targets)\n");
			sb.append("<library>/Functions/     functions internal to the library\n");
			sb.append("<library>/Exports/       the library's remaining published symbol surface\n");
			sb.append("<library>/Imports/       symbols linked in from elsewhere — stub files only,\n");
			sb.append("                         since this APK's copy carries no body for them\n");
		}
		sb.append('\n');
		sb.append("Libraries\n");
		sb.append("---------\n");
		if (results.isEmpty()) {
			sb.append("(none exported)\n");
		}
		for (LibraryResult r : results) {
			if (r.failed()) {
				sb.append(r.name()).append(" — FAILED: ").append(r.error()).append('\n');
			} else {
				sb.append(r.name()).append(" — ").append(r.functions()).append(" functions, ")
						.append(r.filesWritten()).append(" files")
						.append(r.failedFunctions() > 0
								? " (" + r.failedFunctions() + " function"
										+ (r.failedFunctions() == 1 ? "" : "s") + " failed)"
								: "")
						.append('\n');
			}
		}
		if (!problems.isEmpty()) {
			sb.append('\n');
			sb.append("Problems\n");
			sb.append("--------\n");
			int shown = 0;
			for (String p : problems) {
				if (shown++ >= MAX_MANIFEST_PROBLEMS) {
					sb.append("… and ").append(problems.size() - MAX_MANIFEST_PROBLEMS)
							.append(" more (see the Jexray log)\n");
					break;
				}
				sb.append(p).append('\n');
			}
		}
		write(root.resolve(MANIFEST_NAME), sb.toString());
	}

	private static String contentLabel(Options options) {
		if (options.pseudocode() && options.disassembly()) {
			return "pseudocode (.c) and disassembly (.asm)";
		}
		return options.pseudocode() ? "pseudocode (.c)" : "disassembly (.asm)";
	}

	private static String layoutLabel(Options options) {
		return options.layout() == Layout.SINGLE_FILES
				? "single file per library (<library>.c / <library>.asm, banner per function)"
				: "split by category and method (<library>/<group>/<function>.c …)";
	}

	private static void report(ProgressListener listener, Progress p) {
		if (listener != null) {
			listener.onProgress(p);
		}
	}

	private static void reportLibrary(ProgressListener listener, int index, LibraryResult r) {
		if (listener != null) {
			listener.onLibraryDone(index, r);
		}
	}

	/**
	 * The folder one run writes into, inside the folder the user picked: a fresh
	 * {@code Jexray Export yyyy-MM-dd HH.mm.ss} subfolder, so exporting into a shared folder can
	 * never overwrite an earlier run or leave its stale files mixed in with this one's -- every
	 * run is a self-contained snapshot. Collisions (two exports in one second) get a {@code (2)}
	 * suffix rather than sharing a folder.
	 */
	public static Path newRunDir(Path chosen) {
		String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH.mm.ss"));
		Path candidate = chosen.resolve("Jexray Export " + stamp);
		for (int n = 2; Files.exists(candidate); n++) {
			candidate = chosen.resolve("Jexray Export " + stamp + " (" + n + ")");
		}
		return candidate;
	}

	private static Set<String> safe(Set<String> s) {
		return s == null ? Set.of() : s;
	}

	private static String messageOf(Throwable t) {
		String m = t.getMessage();
		return m == null || m.isEmpty() ? t.getClass().getSimpleName() : m;
	}

	// ------------------------------------------------------------------ naming

	/**
	 * Turn a symbol into something safe as a file name on Windows, macOS and Linux: replaces the
	 * characters no filesystem accepts, strips what Windows additionally refuses at a name's ends
	 * (trailing dot/space), guards the reserved device names, and bounds the length. Different
	 * symbols can sanitize to the same string -- {@code a/b} and {@code a?b} both become
	 * {@code a_b} -- so callers obtain names through a {@link DirNamer}, which disambiguates.
	 */
	public static String sanitizeFileName(String name) {
		if (name == null || name.isEmpty()) {
			return "unnamed";
		}
		StringBuilder sb = new StringBuilder(name.length());
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			sb.append(isIllegal(c) ? '_' : c);
		}
		String s = sb.toString().trim();
		while (s.endsWith(".") || s.endsWith(" ")) {
			s = s.substring(0, s.length() - 1);
		}
		if (s.length() > MAX_NAME_LENGTH) {
			s = s.substring(0, MAX_NAME_LENGTH);
		}
		// Windows treats these as device names with or without an extension ("CON" and "CON.c"
		// both fail), so the check is on the part before the first dot.
		int dot = s.indexOf('.');
		String head = (dot < 0 ? s : s.substring(0, dot)).toUpperCase(Locale.ROOT);
		if (RESERVED.contains(head)) {
			s = "_" + s;
		}
		return s.isEmpty() ? "unnamed" : s;
	}

	private static boolean isIllegal(char c) {
		return c < 0x20 || c == '<' || c == '>' || c == ':' || c == '"' || c == '/'
				|| c == '\\' || c == '|' || c == '?' || c == '*';
	}

	private static final Set<String> RESERVED = Set.of(
			"CON", "PRN", "AUX", "NUL",
			"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9");

	/**
	 * Hands out unique names within one directory. Compared case-insensitively, because a name
	 * that differs only in case is still one file on Windows and macOS -- exporting there would
	 * otherwise silently drop one of the two functions.
	 */
	private static final class DirNamer {
		private final Set<String> used = new HashSet<>();

		String reserve(String wanted) {
			String candidate = wanted;
			int n = 2;
			while (!used.add(candidate.toLowerCase(Locale.ROOT))) {
				candidate = wanted + " (" + n++ + ")";
			}
			return candidate;
		}
	}
}
