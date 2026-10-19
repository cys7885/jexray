package com.jexray.jadx.export;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.jexray.jadx.bridge.BridgeException;
import com.jexray.jadx.bridge.BridgeModels.FunctionRef;
import com.jexray.jadx.export.ProjectExporter.FunctionSource;
import com.jexray.jadx.export.ProjectExporter.Library;
import com.jexray.jadx.export.ProjectExporter.LibraryResult;
import com.jexray.jadx.export.ProjectExporter.Options;
import com.jexray.jadx.export.ProjectExporter.Progress;
import com.jexray.jadx.export.ProjectExporter.Result;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the exporter's contract: the on-disk tree mirrors the All Functions browser's exact
 * grouping, naming survives hostile symbols, one failure never stops the run, and a cancelled
 * run says so.
 */
class ProjectExporterTest {

	@TempDir
	Path temp;

	// -------------------------------------------------------------- structure

	@Test
	void mirrorsTheAllFunctionsTreeOnDisk() throws Exception {
		FakeSource src = new FakeSource();
		// JNI entry point (also exported -- claimed by JNI first, exactly like the tree)
		src.add("so1", "Java_com_example_Foo_bar", false);
		src.exported("so1", "Java_com_example_Foo_bar");
		// plain internal function
		src.add("so1", "internal_helper", false);
		// published surface (not an entry point)
		src.add("so1", "published_api", false);
		src.exported("so1", "published_api");
		// linked in from elsewhere
		src.add("so1", "ext_memcmp", true);

		Result r = run(src, (soId, watch) -> { }, split(temp, true, true), List.of(new Library("so1", "libfake.so")));

		assertFalse(r.cancelled());
		assertEquals(0, r.failedFunctions());
		assertEquals(8, r.filesWritten());
		Path lib = temp.resolve("libfake.so");
		assertEquals("// pseudo of Java_com_example_Foo_bar\n",
				read(lib.resolve("JNI methods").resolve("Java_com_example_Foo_bar.c")));
		assertEquals("; disasm of Java_com_example_Foo_bar\n",
				read(lib.resolve("JNI methods").resolve("Java_com_example_Foo_bar.asm")));
		assertTrue(Files.exists(lib.resolve("Functions").resolve("internal_helper.c")));
		assertTrue(Files.exists(lib.resolve("Exports").resolve("published_api.c")));
		// imports have no body here: stub files keep the group present and say why
		assertTrue(read(lib.resolve("Imports").resolve("ext_memcmp.c")).contains("Imported by libfake.so"));
		assertTrue(read(lib.resolve("Imports").resolve("ext_memcmp.asm")).contains("no body"));
		// nothing lands under a heading the tree would not use
		assertFalse(Files.exists(lib.resolve("JNI methods").resolve("internal_helper.c")));
		assertFalse(Files.exists(lib.resolve("Functions").resolve("Java_com_example_Foo_bar.c")));

		String manifest = read(temp.resolve(ProjectExporter.MANIFEST_NAME));
		assertTrue(manifest.contains("libfake.so — 4 functions, 8 files"), manifest);
		assertTrue(manifest.contains("Status   : complete"), manifest);
		assertTrue(r.summary().startsWith("Exported 8 files from 1 library"), r.summary());
	}

	@Test
	void registeredNativesGroupUnderJniMethodsLikeTheTree() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "FUN_001234", false); // obfuscated, but registered to a Java method
		src.registered("so1", "FUN_001234");

		run(src, (soId, watch) -> { }, split(temp, true, false), List.of(new Library("so1", "libfake.so")));

		assertTrue(Files.exists(temp.resolve("libfake.so").resolve("JNI methods").resolve("FUN_001234.c")));
	}

	@Test
	void pseudocodeOnlyLeavesNoDisassemblyAnywhere() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "Java_a_b_c", false);
		src.add("so1", "helper", false);
		src.add("so1", "ext_open", true);

		run(src, (soId, watch) -> { }, split(temp, true, false), List.of(new Library("so1", "libfake.so")));

		try (Stream<Path> walk = Files.walk(temp)) {
			assertTrue(walk.noneMatch(p -> p.getFileName().toString().endsWith(".asm")),
					"a pseudocode-only export must not write .asm files");
		}
	}

	// -------------------------------------------------------------- naming

	@Test
	void hostileSymbolsAreSanitizedAndCollisionsDeduped() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "a/b", false);   // both sanitize to "a_b"...
		src.add("so1", "a?b", false);   // ...so the second must not overwrite the first
		src.add("so1", "CON", false);   // a Windows device name: not a legal file name
		src.add("so1", "trailing.", false);

		Result r = run(src, (soId, watch) -> { }, split(temp, true, false), List.of(new Library("so1", "libfake.so")));

		Path functions = temp.resolve("libfake.so").resolve("Functions");
		assertTrue(Files.exists(functions.resolve("a_b.c")));
		assertTrue(Files.exists(functions.resolve("a_b (2).c")));
		assertTrue(Files.exists(functions.resolve("_CON.c")));
		assertTrue(Files.exists(functions.resolve("trailing.c")));
		assertEquals(4, r.filesWritten());
	}

	@Test
	void sanitizeFileNameHandlesWhatFilesystemsRefuse() {
		assertEquals("unnamed", ProjectExporter.sanitizeFileName(null));
		assertEquals("unnamed", ProjectExporter.sanitizeFileName(""));
		assertEquals("a_b__c", ProjectExporter.sanitizeFileName("a<b>:c")); // '<', '>' and ':' each -> '_'
		assertEquals("_nul.c", ProjectExporter.sanitizeFileName("nul.c")); // reserved, with extension
		assertEquals("FUN_1", ProjectExporter.sanitizeFileName("  FUN_1  "));
		String long150 = "x".repeat(200);
		assertEquals(150, ProjectExporter.sanitizeFileName(long150).length());
	}

	// -------------------------------------------------------------- resilience

	@Test
	void oneBrokenFunctionNeverStopsTheRun() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "good_one", false);
		src.add("so1", "broken_one", false);
		src.add("so1", "good_two", false);
		src.failPseudo("broken_one");

		Result r = run(src, (soId, watch) -> { }, split(temp, true, false), List.of(new Library("so1", "libfake.so")));

		assertEquals(1, r.failedFunctions());
		assertTrue(r.problems().stream().anyMatch(p -> p.contains("broken_one")));
		assertTrue(Files.exists(temp.resolve("libfake.so").resolve("Functions").resolve("good_one.c")));
		assertTrue(Files.exists(temp.resolve("libfake.so").resolve("Functions").resolve("good_two.c")));
		assertFalse(Files.exists(temp.resolve("libfake.so").resolve("Functions").resolve("broken_one.c")));
		assertTrue(r.summary().contains("with problems"), r.summary());
		// the manifest says the library had 3 functions, 2 files, 1 failure
		assertTrue(read(temp.resolve(ProjectExporter.MANIFEST_NAME))
				.contains("libfake.so — 3 functions, 2 files (1 function failed)"));
	}

	@Test
	void bridgeSayingExternalOverridesTheListingAndWritesAStub() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "looks_defined", false); // listing claims a body...
		src.externalFromBridge("looks_defined"); // ...the bridge says otherwise

		Result r = run(src, (soId, watch) -> { }, split(temp, true, false), List.of(new Library("so1", "libfake.so")));

		assertEquals(0, r.failedFunctions());
		assertTrue(read(temp.resolve("libfake.so").resolve("Functions").resolve("looks_defined.c"))
				.contains("no body"));
	}

	@Test
	void aFailedLibraryIsRecordedAndTheOthersStillExport() throws Exception {
		FakeSource src = new FakeSource();
		src.add("soA", "Java_a_b_c", false);
		src.add("soB", "helper", false);

		Result r = run(src, (soId, watch) -> {
			if ("soA".equals(soId)) {
				throw new IOException("no native library found for id soA");
			}
		}, split(temp, true, false), List.of(new Library("soA", "liba.so"), new Library("soB", "libb.so")));

		assertEquals(2, r.libraryResults().size());
		LibraryResult failed = r.libraryResults().get(0);
		assertTrue(failed.failed());
		assertTrue(failed.error().contains("no native library found"), failed.error());
		assertFalse(Files.exists(temp.resolve("liba.so")));
		assertTrue(Files.exists(temp.resolve("libb.so").resolve("Functions").resolve("helper.c")));
		assertTrue(read(temp.resolve(ProjectExporter.MANIFEST_NAME)).contains("liba.so — FAILED:"));
		assertTrue(r.summary().contains("1 library failed"), r.summary());
	}

	@Test
	void cancelledBeforeFirstFunctionWritesNoCodeButSaysSo() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);

		Result r = run(src, (soId, watch) -> { }, split(temp, true, true),
				List.of(new Library("so1", "libfake.so")), new AtomicBoolean(true));

		assertTrue(r.cancelled());
		assertEquals(0, r.filesWritten());
		assertTrue(read(temp.resolve(ProjectExporter.MANIFEST_NAME)).contains("CANCELLED"));
		try (Stream<Path> walk = Files.walk(temp)) {
			assertTrue(walk.noneMatch(p -> p.getFileName().toString().endsWith(".c")));
		}
	}

	@Test
	void cancellingDuringAnalysisIsACancelledRunNotAFailedLibrary() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);
		AtomicBoolean cancel = new AtomicBoolean(false);
		List<Progress> seen = new ArrayList<>();
		// mimics the real bridge-backed analyzer: the analysis reports counts, the user presses
		// Cancel while Ghidra is still working, the watch sees the flag, and the call ends in an
		// InterruptedException -- exactly what ensureBridgeLoaded does on a cancelled watch
		ProjectExporter.Analyzer an = (soId, watch) -> {
			watch.onStatus("analyzing", 10, 100, "Analyzing functions");
			cancel.set(true);
			assertTrue(watch.cancelled(), "the watch must observe the run's cancelled flag");
			throw new InterruptedException("cancelled");
		};

		Result r = exporter(src, an).run(split(temp, true, false),
				List.of(new Library("so1", "libfake.so")), cancel, seen::add);

		assertTrue(r.cancelled());
		assertTrue(r.problems().isEmpty(), r.problems().toString());
		assertEquals(0, r.libraryResults().size()); // the stopped library is not a failure
		assertFalse(r.isClean());
		assertTrue(r.summary().startsWith("Export cancelled"), r.summary());
		assertTrue(read(temp.resolve(ProjectExporter.MANIFEST_NAME)).contains("CANCELLED"));
		try (Stream<Path> walk = Files.walk(temp)) {
			assertTrue(walk.noneMatch(p -> p.getFileName().toString().endsWith(".c")));
		}
		// the analysis phase carried the bridge's own counts, so it can drive a determinate bar
		assertTrue(seen.stream().anyMatch(p -> "analyzing".equals(p.phase())
				&& p.doneFunctions() == 10 && p.totalFunctions() == 100
				&& p.overallPercent() == 10), seen.toString());
	}

	@Test
	void cleanIsTrueOnlyWhenNothingWentWrongAnywhere() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);

		// a perfect run: the only shape that may auto-close the dialog
		assertTrue(run(src, (soId, watch) -> { }, split(temp, true, false),
				List.of(new Library("so1", "libfake.so"))).isClean());

		// one failed function -- even with every library exported fine -- is not clean
		FakeSource broken = new FakeSource();
		broken.add("so1", "bad", false);
		broken.failPseudo("bad");
		assertFalse(run(broken, (soId, watch) -> { }, split(temp, true, false),
				List.of(new Library("so1", "libfake.so"))).isClean());

		// a failed library is not clean
		assertFalse(run(src, (soId, watch) -> { throw new IOException("boom"); },
				split(temp, true, false), List.of(new Library("so1", "libfake.so"))).isClean());
	}

	@Test
	void aRunLevelFailureIsNotCleanEvenWithAnEmptyLibraryList() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);
		// an output root that cannot be created: the file that is in the way -- exactly the
		// "can't create the output folder" case, whose empty library list used to read as clean
		Path blocked = temp.resolve("blocked");
		Files.writeString(blocked, "in the way");

		Result r = run(src, (soId, watch) -> { },
				new Options(blocked.resolve("out"), true, false),
				List.of(new Library("so1", "libfake.so")));

		assertFalse(r.isClean(), "an unwritable root must never read as a clean run");
		assertTrue(r.libraryResults().isEmpty());
		assertTrue(r.problems().stream().anyMatch(p -> p.contains("could not write")),
				r.problems().toString());
	}

	@Test
	void newRunDirGivesEveryRunItsOwnSubfolder() throws Exception {
		Path first = ProjectExporter.newRunDir(temp);
		assertTrue(first.getFileName().toString().startsWith("Jexray Export "),
				first.getFileName().toString());
		assertEquals(temp, first.getParent());

		// a second export into the same shared folder lands beside the first, never on top of it
		Files.createDirectories(first);
		Path second = ProjectExporter.newRunDir(temp);
		assertTrue(Files.notExists(second));
		assertTrue(second.getFileName().toString().contains("("),
				second.getFileName().toString());
	}

	@Test
	void progressReportsTheTreesPhasePerLibrary() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);
		List<Progress> seen = new ArrayList<>();

		ProjectExporter exporter = exporter(src, (soId, watch) -> { });
		exporter.run(split(temp, true, false), List.of(new Library("so1", "libfake.so")),
				new AtomicBoolean(false), seen::add);

		assertTrue(seen.stream().anyMatch(p -> "analyzing".equals(p.phase())));
		Progress last = seen.get(seen.size() - 1);
		assertEquals("exporting", last.phase());
		assertEquals(1, last.doneFunctions());
		assertEquals(1, last.totalFunctions());
		assertEquals(100, last.overallPercent());
	}

	// -------------------------------------------------------------- single-file layout

	@Test
	void singleFileLayoutWritesOneFilePerLibraryWithBannerPerFunction() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "Java_com_example_Foo_bar", false);
		src.exported("so1", "Java_com_example_Foo_bar");
		src.add("so1", "helper", false);
		src.add("so1", "ext_open", true);

		Result r = run(src, (soId, watch) -> { }, single(temp, true, true), List.of(new Library("so1", "libfake.so")));

		assertFalse(r.cancelled());
		assertEquals(0, r.failedFunctions());
		assertEquals(2, r.filesWritten()); // one .c and one .asm for the whole library
		Path c = temp.resolve("libfake.so.c");
		Path asm = temp.resolve("libfake.so.asm");
		String text = read(c);
		// each function behind a banner carrying its symbol, address, group and library
		assertTrue(text.contains("Java_com_example_Foo_bar @ 0x1000"), text);
		assertTrue(text.contains("Group: JNI methods | Library: libfake.so"), text);
		// imports keep their place: banner plus an explanation instead of a body
		assertTrue(text.contains("ext_open"), text);
		assertTrue(text.contains("no body"), text);
		// the tree's order is preserved inside the file: entry points before internal functions
		assertTrue(text.indexOf("Java_com_example_Foo_bar") < text.indexOf("helper"), text);
		assertTrue(read(asm).contains("; Group: JNI methods | Library: libfake.so"), asm.toString());
		// nothing was split out into folders or per-function files
		assertFalse(Files.exists(temp.resolve("libfake.so")));
		// the streaming temps are gone: only the finished files remain
		try (Stream<Path> walk = Files.walk(temp)) {
			assertTrue(walk.noneMatch(p -> p.getFileName().toString().endsWith(".part")));
		}
		String manifest = read(temp.resolve(ProjectExporter.MANIFEST_NAME));
		assertTrue(manifest.contains("single file per library"), manifest);
	}

	@Test
	void defaultLayoutIsSingleFiles() {
		Options o = new Options(temp, true, false);
		assertEquals(ProjectExporter.Layout.SINGLE_FILES, o.layout());
	}

	@Test
	void cancellingMidLibraryLeavesAnHonestPartialSingleFile() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "aaa_first", false);
		src.add("so1", "zzz_second", false);
		AtomicBoolean cancel = new AtomicBoolean(false);

		ProjectExporter exporter = exporter(src, (soId, watch) -> { });
		// the listener fires after each function, so the second one is dropped mid-library
		Result r = exporter.run(single(temp, true, false), List.of(new Library("so1", "libfake.so")),
				cancel, p -> {
					if (p.doneFunctions() >= 1) {
						cancel.set(true);
					}
				});

		assertTrue(r.cancelled());
		assertEquals(1, r.filesWritten());
		String text = read(temp.resolve("libfake.so.c"));
		assertTrue(text.contains("aaa_first"), text);
		assertFalse(text.contains("zzz_second"), text);
		assertTrue(text.contains("export cancelled"), text);
		assertTrue(text.contains("only 1 of 2 functions"), text);
	}

	@Test
	void aCancelBeforeTheFirstFunctionLeavesNoEmptySingleFiles() throws Exception {
		FakeSource src = new FakeSource();
		src.add("so1", "helper", false);
		AtomicBoolean cancel = new AtomicBoolean(false);

		// cancel right at the exporting phase's first report: the library gets listed but not a
		// single function is fetched -- the streamed layout must leave nothing behind, not even
		// empty files pretending to be an export
		Result r = exporter(src, (soId, watch) -> { }).run(single(temp, true, true),
				List.of(new Library("so1", "libfake.so")), cancel,
				p -> { if ("exporting".equals(p.phase())) cancel.set(true); });

		assertTrue(r.cancelled());
		assertEquals(0, r.filesWritten());
		try (Stream<Path> walk = Files.walk(temp)) {
			assertTrue(walk.noneMatch(q -> {
				String n = q.getFileName().toString();
				return n.endsWith(".part") || n.endsWith(".c") || n.endsWith(".asm");
			}), "nothing was exported, so nothing must be left on disk");
		}
	}

	// -------------------------------------------------------------- harness

	private static Options split(Path root, boolean pseudo, boolean disasm) {
		return new Options(root, pseudo, disasm, ProjectExporter.Layout.SPLIT);
	}

	private static Options single(Path root, boolean pseudo, boolean disasm) {
		return new Options(root, pseudo, disasm, ProjectExporter.Layout.SINGLE_FILES);
	}

	private static Result run(FunctionSource src, ProjectExporter.Analyzer analyzer, Options options,
			List<Library> libs) throws IOException {
		return run(src, analyzer, options, libs, new AtomicBoolean(false));
	}

	private static Result run(FunctionSource src, ProjectExporter.Analyzer analyzer, Options options,
			List<Library> libs, AtomicBoolean cancelled) throws IOException {
		return exporter(src, analyzer).run(options, libs, cancelled, p -> { });
	}

	private static ProjectExporter exporter(FunctionSource src, ProjectExporter.Analyzer analyzer) {
		return new ProjectExporter("0.0-test", "12.0", src, analyzer);
	}

	private static String read(Path p) throws IOException {
		return Files.readString(p, StandardCharsets.UTF_8);
	}

	/** In-memory stand-in for the bridge: one library's listing, grouping facts and bodies. */
	private static final class FakeSource implements FunctionSource {
		private final Map<String, List<FunctionRef>> bySo = new HashMap<>();
		private final Map<String, Set<String>> exported = new HashMap<>();
		private final Map<String, Set<String>> registered = new HashMap<>();
		private final Set<String> failPseudo = new HashSet<>();
		private final Set<String> externalFromBridge = new HashSet<>();

		void add(String soId, String name, boolean external) {
			FunctionRef f = new FunctionRef();
			f.name = name;
			f.address = "0x1000";
			f.external = external;
			bySo.computeIfAbsent(soId, k -> new ArrayList<>()).add(f);
		}

		void exported(String soId, String name) {
			exported.computeIfAbsent(soId, k -> new HashSet<>()).add(name);
		}

		void registered(String soId, String name) {
			registered.computeIfAbsent(soId, k -> new HashSet<>()).add(name);
		}

		void failPseudo(String name) {
			failPseudo.add(name);
		}

		void externalFromBridge(String name) {
			externalFromBridge.add(name);
		}

		@Override
		public List<FunctionRef> listFunctions(String soId) {
			return bySo.getOrDefault(soId, List.of());
		}

		@Override
		public String pseudocode(String soId, String name) throws BridgeException {
			if (failPseudo.contains(name)) {
				throw new BridgeException(BridgeException.Kind.NOT_FOUND, "no body for " + name);
			}
			if (externalFromBridge.contains(name)) {
				throw new BridgeException(BridgeException.Kind.EXTERNAL_SYMBOL, "imported: " + name);
			}
			return "// pseudo of " + name;
		}

		@Override
		public String disassembly(String soId, String name) {
			return "; disasm of " + name;
		}

		@Override
		public Set<String> exportedSymbols(String soId) {
			return exported.getOrDefault(soId, Set.of());
		}

		@Override
		public Set<String> registeredSymbols(String soId) {
			return registered.getOrDefault(soId, Set.of());
		}
	}
}
