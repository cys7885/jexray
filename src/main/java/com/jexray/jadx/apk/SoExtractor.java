package com.jexray.jadx.apk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Extracts native libraries ({@code lib/<abi>/<name>.so}) from an input APK on demand.
 *
 * <p>Not just plain APKs: split APK sets and zip-packaged libraries are understood too. An
 * {@code .apks}/{@code .xapk}/{@code .apkm} input -- or any zip -- is also searched through its
 * nested archives, so {@code split_config.arm64_v8a.apk} inside {@code example.apks} is found like
 * any other library: the scan opens each nested {@code .apk}/{@code .zip} entry, lists its
 * {@code lib/} folders, and remembers the chain of archives each entry came from -- which is what
 * lets {@link #extract} stream the library back out through the same chain without unpacking
 * anything to disk first. ({@code .aab}'s {@code base/lib/...} layout matches the same rule.)
 *
 * <p>Known simplification (v1): when multiple ABI folders are present a single ABI is
 * chosen deterministically by {@link #ABI_PREFERENCE}. A per-ABI selection UI is future work.
 */
public class SoExtractor {

	/** Preferred ABIs, best first. First match wins; otherwise any available ABI is used. */
	public static final List<String> ABI_PREFERENCE = List.of("arm64-v8a", "armeabi-v7a", "x86_64", "x86");

	/** How many archive levels inside the input file are searched ({@code input -> nested -> nested-nested}). */
	private static final int MAX_NESTED_DEPTH = 2;

	/** Entry suffixes opened and searched as nested archives (containers that may carry libraries). */
	private static final List<String> NESTED_ARCHIVE_SUFFIXES =
			List.of(".apk", ".zip", ".apks", ".xapk", ".apkm");

	private final Path cacheDir;

	public SoExtractor(Path cacheDir) {
		this.cacheDir = cacheDir;
	}

	/**
	 * A native library entry found inside an input: its abi, file name, the zip entry path that
	 * holds it, its uncompressed size, and -- when it lives inside a nested archive -- the chain
	 * of archive entries in the owner file that leads to it, outermost first (empty when the .so
	 * sits directly in the input file).
	 */
	public record SoEntry(String abi, String soName, String entryPath, long sizeBytes,
			List<String> containerPath) {
		public SoEntry {
			containerPath = containerPath == null ? List.of() : List.copyOf(containerPath);
		}

		/** Convenience for entries directly inside the input file ({@code containerPath} empty). */
		public SoEntry(String abi, String soName, String entryPath, long sizeBytes) {
			this(abi, soName, entryPath, sizeBytes, List.of());
		}

		/** Stable id for the bridge: {@code <abi>_<soName>} with unsafe chars replaced. */
		public String soId() {
			return (abi + "_" + soName).replaceAll("[^A-Za-z0-9._-]", "_");
		}
	}

	/**
	 * List all {@code lib/<abi>/*.so} entries across the given input files (APKs and zips),
	 * descending into nested archives (split APK sets, zip-packaged apks). Files that are not
	 * zips are skipped silently; so is a nested archive that cannot be read.
	 */
	public List<SoEntry> listSoEntries(List<File> inputFiles) {
		List<SoEntry> result = new ArrayList<>();
		for (File f : inputFiles) {
			if (f == null || !f.isFile()) {
				continue;
			}
			try (ZipFile zip = new ZipFile(f)) {
				scanOpenZip(zip, List.of(), 0, result);
			} catch (IOException ignored) {
				// not a zip / unreadable -> skip
			}
		}
		return result;
	}

	/** One archive level with random access (an input file): collect its .so entries, open nested archives. */
	private void scanOpenZip(ZipFile zip, List<String> containerPath, int depth, List<SoEntry> out) {
		Enumeration<? extends ZipEntry> entries = zip.entries();
		while (entries.hasMoreElements()) {
			ZipEntry e = entries.nextElement();
			if (e.isDirectory()) {
				continue;
			}
			String name = e.getName();
			String[] parts = soPartsOf(name);
			if (parts != null) {
				// uncompressed size, so callers can judge analysis cost without extracting first
				out.add(new SoEntry(parts[0], parts[1], name, Math.max(0, e.getSize()), containerPath));
				continue;
			}
			if (depth < MAX_NESTED_DEPTH && isNestedArchive(name)) {
				try (ZipInputStream nested = new ZipInputStream(zip.getInputStream(e))) {
					scanStreamedZip(nested, childPath(containerPath, name), depth + 1, out);
				} catch (IOException ignored) {
					// unreadable nested archive -> skip it, keep scanning the rest
				}
			}
		}
	}

	/**
	 * One streamed archive level (an archive found inside another): same listing, same descent.
	 * The stream is not closed here -- it belongs to the caller's chain when nested again -- and
	 * the loop simply resumes with the next entry once a nested scan has consumed one.
	 */
	private void scanStreamedZip(ZipInputStream zis, List<String> containerPath, int depth,
			List<SoEntry> out) throws IOException {
		ZipEntry e;
		while ((e = zis.getNextEntry()) != null) {
			if (e.isDirectory()) {
				continue;
			}
			String name = e.getName();
			String[] parts = soPartsOf(name);
			if (parts != null) {
				out.add(new SoEntry(parts[0], parts[1], name, sizeOfStreamedEntry(zis, e), containerPath));
				continue;
			}
			if (depth < MAX_NESTED_DEPTH && isNestedArchive(name)) {
				try {
					scanStreamedZip(new ZipInputStream(zis), childPath(containerPath, name), depth + 1, out);
				} catch (IOException ignored) {
					// unreadable nested archive -> skip it; the outer stream resumes at the
					// next entry (it skips whatever remained of this one)
				}
			}
		}
	}

	/**
	 * The uncompressed size of a streamed entry. A deflated entry's local header often omits it
	 * (the central directory is where the real value lives), so fall back to reading the entry
	 * out -- the very bytes a naive skip would inflate through anyway, just counted.
	 */
	private static long sizeOfStreamedEntry(ZipInputStream zis, ZipEntry e) throws IOException {
		long known = e.getSize();
		if (known >= 0) {
			return known;
		}
		long total = 0;
		byte[] buf = new byte[8192];
		int n;
		while ((n = zis.read(buf)) != -1) {
			total += n;
		}
		return total;
	}

	/**
	 * The abi and file name an archive entry names, or null when it names anything else. A plain
	 * {@code lib/<abi>/<name>.so} matches, and so does the same path one or more directories down
	 * -- {@code base/lib/arm64-v8a/{@literal x}.so} in an {@code .aab}, or a split's lib folder
	 * read through its container -- as long as the file sits directly under an abi directory.
	 *
	 * @return {@code {abi, soName}}, or null
	 */
	private static String[] soPartsOf(String entryName) {
		String rest;
		int libIdx = entryName.lastIndexOf("/lib/");
		if (libIdx >= 0) {
			rest = entryName.substring(libIdx + "/lib/".length());
		} else if (entryName.startsWith("lib/")) {
			rest = entryName.substring("lib/".length());
		} else {
			return null;
		}
		int slash = rest.indexOf('/');
		if (slash <= 0 || slash == rest.length() - 1) {
			return null;
		}
		String abi = rest.substring(0, slash);
		String soName = rest.substring(slash + 1);
		if (soName.indexOf('/') >= 0 || !soName.toLowerCase(Locale.ROOT).endsWith(".so")) {
			return null;
		}
		return new String[] { abi, soName };
	}

	private static boolean isNestedArchive(String entryName) {
		String lower = entryName.toLowerCase(Locale.ROOT);
		for (String suffix : NESTED_ARCHIVE_SUFFIXES) {
			if (lower.endsWith(suffix)) {
				return true;
			}
		}
		return false;
	}

	private static List<String> childPath(List<String> containerPath, String entryName) {
		List<String> next = new ArrayList<>(containerPath.size() + 1);
		next.addAll(containerPath);
		next.add(entryName);
		return List.copyOf(next);
	}

	/**
	 * Pick the best ABI's copy of each distinct .so name from the given entries.
	 *
	 * @return map of soName -&gt; chosen SoEntry
	 */
	public Map<String, SoEntry> pickPreferredAbi(List<SoEntry> entries) {
		Map<String, SoEntry> best = new LinkedHashMap<>();
		for (SoEntry e : entries) {
			SoEntry current = best.get(e.soName());
			if (current == null || abiRank(e.abi()) < abiRank(current.abi())) {
				best.put(e.soName(), e);
			}
		}
		return best;
	}

	private static int abiRank(String abi) {
		int idx = ABI_PREFERENCE.indexOf(abi);
		return idx < 0 ? Integer.MAX_VALUE : idx;
	}

	/**
	 * Extract a single .so entry from the containing input file to the cache directory, walking
	 * the entry's container chain when it lives inside a nested archive.
	 *
	 * @return the extracted file's path
	 */
	public Path extract(File archive, SoEntry entry) throws IOException {
		Files.createDirectories(cacheDir);
		Path out = cacheDir.resolve(entry.soId());
		try (ZipFile zip = new ZipFile(archive)) {
			try (InputStream in = openEntryStream(zip, entry)) {
				Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
			}
		}
		return out;
	}

	/**
	 * A stream over the .so's bytes: the entry itself when it sits directly in {@code zip}, or a
	 * reader descended through the entry's container chain ({@code .apks} -> inner split .apk ->
	 * {@code lib/...so}) when it does not. Closing the returned stream closes the whole chain.
	 */
	private static InputStream openEntryStream(ZipFile zip, SoEntry entry) throws IOException {
		List<String> containers = entry.containerPath();
		if (containers.isEmpty()) {
			ZipEntry ze = zip.getEntry(entry.entryPath());
			if (ze == null) {
				throw new IOException("Entry not found in input: " + entry.entryPath());
			}
			return zip.getInputStream(ze);
		}
		ZipEntry first = zip.getEntry(containers.get(0));
		if (first == null) {
			throw new IOException("Entry not found in input: " + containers.get(0));
		}
		ZipInputStream zis = new ZipInputStream(zip.getInputStream(first));
		for (int i = 1; i < containers.size(); i++) {
			if (!advanceTo(zis, containers.get(i))) {
				throw new IOException("Entry not found in input: " + containers.get(i));
			}
			zis = new ZipInputStream(zis);
		}
		if (!advanceTo(zis, entry.entryPath())) {
			throw new IOException("Entry not found in input: " + entry.entryPath());
		}
		return zis;
	}

	/** Position a streamed reader on {@code name}'s entry; false once the archive ends without it. */
	private static boolean advanceTo(ZipInputStream zis, String name) throws IOException {
		ZipEntry e;
		while ((e = zis.getNextEntry()) != null) {
			if (name.equals(e.getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Locate and extract the preferred .so from the given input files. Convenience for the
	 * common single-native-lib case; returns null if no .so is present.
	 *
	 * @return the extracted SoEntry paired with its on-disk path, or null
	 */
	public ExtractedSo extractPreferred(List<File> inputFiles) throws IOException {
		List<SoEntry> all = listSoEntries(inputFiles);
		if (all.isEmpty()) {
			return null;
		}
		Map<String, SoEntry> preferred = pickPreferredAbi(all);
		// deterministic: first .so name in insertion order
		SoEntry chosen = preferred.values().iterator().next();
		File owner = findOwner(inputFiles, chosen);
		Path path = extract(owner, chosen);
		return new ExtractedSo(chosen, path);
	}

	private File findOwner(List<File> inputFiles, SoEntry entry) throws IOException {
		String firstAnchor = entry.containerPath().isEmpty()
				? entry.entryPath()
				: entry.containerPath().get(0);
		for (File f : inputFiles) {
			if (f == null || !f.isFile()) {
				continue;
			}
			try (ZipFile zip = new ZipFile(f)) {
				if (zip.getEntry(firstAnchor) != null) {
					return f;
				}
			} catch (IOException ignored) {
				// skip
			}
		}
		throw new IOException("No input file contains entry: " + entry.entryPath());
	}

	public record ExtractedSo(SoEntry entry, Path path) {
	}
}
