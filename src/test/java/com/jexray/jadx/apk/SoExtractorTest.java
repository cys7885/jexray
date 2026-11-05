package com.jexray.jadx.apk;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.jexray.jadx.apk.SoExtractor.ExtractedSo;
import com.jexray.jadx.apk.SoExtractor.SoEntry;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers what the library scan must see through containers: split APK sets ({@code .apks} with
 * per-ABI splits), zip-packaged libraries, and {@code .aab}-style paths -- plus that a library
 * found through a container chain extracts back out byte-for-byte.
 */
class SoExtractorTest {

	@TempDir
	Path temp;

	// ------------------------------------------------------------ split APK sets

	@Test
	void findsLibraryInsideASplitApkSet() throws Exception {
		byte[] so = bytes("fake-ELF arm64 lib");
		Path apks = zip(temp.resolve("example.apks"), Map.of(
				"toc.pb", bytes("toc"),
				"base.apk", zipBytes(Map.of("AndroidManifest.xml", bytes("manifest"))),
				"split_config.arm64_v8a.apk", zipBytes(Map.of(
						"AndroidManifest.xml", bytes("manifest"),
						"lib/arm64-v8a/libfake.so", so)),
				"split_config.en.apk", zipBytes(Map.of("resources.arsc", bytes("res")))));

		SoExtractor extractor = new SoExtractor(temp.resolve("cache"));
		List<SoEntry> entries = extractor.listSoEntries(List.of(apks.toFile()));

		assertEquals(1, entries.size());
		SoEntry e = entries.get(0);
		assertEquals("arm64-v8a", e.abi());
		assertEquals("libfake.so", e.soName());
		assertEquals("lib/arm64-v8a/libfake.so", e.entryPath());
		assertEquals(List.of("split_config.arm64_v8a.apk"), e.containerPath());
		// exact size: whether the inner local header carried it or the scan had to count the bytes
		assertEquals(so.length, e.sizeBytes());

		Path extracted = extractor.extract(apks.toFile(), e);
		assertEquals("arm64-v8a_libfake.so", extracted.getFileName().toString());
		assertArrayEquals(so, Files.readAllBytes(extracted));
	}

	@Test
	void prefersTheBestAbiAcrossSplits() throws Exception {
		byte[] arm64 = bytes("arm64 lib");
		byte[] arm32 = bytes("arm32 lib");
		Path apks = zip(temp.resolve("app.apks"), Map.of(
				"split_config.arm64_v8a.apk", zipBytes(Map.of("lib/arm64-v8a/libfoo.so", arm64)),
				"split_config.armeabi_v7a.apk", zipBytes(Map.of("lib/armeabi-v7a/libfoo.so", arm32))));

		SoExtractor extractor = new SoExtractor(temp.resolve("cache"));
		List<SoEntry> entries = extractor.listSoEntries(List.of(apks.toFile()));
		assertEquals(2, entries.size());

		SoEntry best = extractor.pickPreferredAbi(entries).get("libfoo.so");
		assertEquals("arm64-v8a", best.abi());

		ExtractedSo picked = extractor.extractPreferred(List.of(apks.toFile()));
		assertEquals("arm64-v8a", picked.entry().abi());
		assertArrayEquals(arm64, Files.readAllBytes(picked.path()));
	}

	@Test
	void soManagerListsAndExtractsTheSplitLibrary() throws Exception {
		byte[] so = bytes("fake-ELF for the manager");
		Path apks = zip(temp.resolve("example.apks"), Map.of(
				"base.apk", zipBytes(Map.of()),
				"split_config.arm64_v8a.apk", zipBytes(Map.of("lib/arm64-v8a/libfake.so", so)),
				"split_config.armeabi_v7a.apk", zipBytes(Map.of("lib/armeabi-v7a/libfake.so", bytes("arm32")))));

		SoManager manager = new SoManager(List.of(apks.toFile()),
				SoExtractor.ABI_PREFERENCE, temp.resolve("cache"));

		assertTrue(manager.hasNativeLibraries());
		assertEquals("arm64-v8a", manager.chosenAbi());
		assertEquals(List.of("arm64-v8a_libfake.so"), manager.soIds());
		assertEquals("libfake.so", manager.soIdToName().get("arm64-v8a_libfake.so"));
		assertEquals(so.length, manager.soIdToSize().get("arm64-v8a_libfake.so"));

		ExtractedSo es = manager.extractedForId("arm64-v8a_libfake.so");
		assertNotNull(es);
		assertArrayEquals(so, Files.readAllBytes(es.path()));
	}

	// ------------------------------------------------------------ plain inputs

	@Test
	void readsLibrariesDirectlyInTheInputAndInAabLayout() throws Exception {
		byte[] apkLib = bytes("x86_64 lib");
		byte[] aabLib = bytes("aab arm64 lib");
		Path apk = zip(temp.resolve("plain.apk"), Map.of(
				"AndroidManifest.xml", bytes("manifest"),
				"lib/x86_64/libfoo.so", apkLib,
				"assets/not_a_lib.so", bytes("ignored")));
		Path aab = zip(temp.resolve("bundle.aab"), Map.of(
				"base/dex/classes.dex", bytes("dex"),
				"base/lib/arm64-v8a/libbar.so", aabLib));

		SoExtractor extractor = new SoExtractor(temp.resolve("cache"));
		List<SoEntry> entries = extractor.listSoEntries(List.of(apk.toFile(), aab.toFile()));

		assertEquals(2, entries.size());
		SoEntry direct = entries.get(0);
		assertEquals("x86_64", direct.abi());
		assertTrue(direct.containerPath().isEmpty());
		assertArrayEquals(apkLib, Files.readAllBytes(extractor.extract(apk.toFile(), direct)));

		SoEntry fromAab = entries.get(1);
		assertEquals("arm64-v8a", fromAab.abi());
		assertEquals("libbar.so", fromAab.soName());
		assertArrayEquals(aabLib, Files.readAllBytes(extractor.extract(aab.toFile(), fromAab)));
	}

	@Test
	void nonZipInputsAreSkippedSilently() throws Exception {
		Path notZip = Files.writeString(temp.resolve("notes.txt"), "not a zip");
		assertTrue(new SoExtractor(temp.resolve("cache"))
				.listSoEntries(List.of(notZip.toFile())).isEmpty());
	}

	// ------------------------------------------------------------ nested zips

	@Test
	void descendsThroughNestedZipsAndStreamsTheLibraryBackOut() throws Exception {
		byte[] so = bytes("double-nested lib");
		Path input = zip(temp.resolve("libs.zip"), Map.of(
				"docs/readme.txt", bytes("hi"),
				"bundle.zip", zipBytes(Map.of(
						"inner.zip", zipBytes(Map.of("lib/arm64-v8a/libnested.so", so))))));

		SoExtractor extractor = new SoExtractor(temp.resolve("cache"));
		List<SoEntry> entries = extractor.listSoEntries(List.of(input.toFile()));

		assertEquals(1, entries.size());
		SoEntry e = entries.get(0);
		assertEquals(List.of("bundle.zip", "inner.zip"), e.containerPath());
		assertEquals(so.length, e.sizeBytes());

		Path extracted = extractor.extract(input.toFile(), e);
		assertArrayEquals(so, Files.readAllBytes(extracted));
	}

	@Test
	void aSplitWithNoLibrariesContributesNothing() throws Exception {
		Path apks = zip(temp.resolve("empty.apks"), Map.of(
				"base.apk", zipBytes(Map.of("AndroidManifest.xml", bytes("manifest")))));
		SoExtractor extractor = new SoExtractor(temp.resolve("cache"));
		assertTrue(extractor.listSoEntries(List.of(apks.toFile())).isEmpty());
	}

	// ------------------------------------------------------------ fixtures

	private static byte[] bytes(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	/** A zip file at {@code file} holding the given entries in iteration order. */
	private static Path zip(Path file, Map<String, byte[]> entries) throws IOException {
		Files.createDirectories(file.getParent());
		try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(file))) {
			writeEntries(out, entries);
		}
		return file;
	}

	/** The same zips, in memory -- for embedding one archive inside another. */
	private static byte[] zipBytes(Map<String, byte[]> entries) throws IOException {
		java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
		try (ZipOutputStream out = new ZipOutputStream(buf)) {
			writeEntries(out, entries);
		}
		return buf.toByteArray();
	}

	private static void writeEntries(ZipOutputStream out, Map<String, byte[]> entries)
			throws IOException {
		for (Map.Entry<String, byte[]> e : entries.entrySet()) {
			out.putNextEntry(new ZipEntry(e.getKey()));
			out.write(e.getValue());
			out.closeEntry();
		}
	}
}
