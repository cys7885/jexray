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
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Extracts native libraries ({@code lib/<abi>/<name>.so}) from an input APK on demand.
 *
 * <p>Known simplification (v1): when multiple ABI folders are present a single ABI is
 * chosen deterministically by {@link #ABI_PREFERENCE}. A per-ABI selection UI is future work.
 */
public class SoExtractor {

	/** Preferred ABIs, best first. First match wins; otherwise any available ABI is used. */
	public static final List<String> ABI_PREFERENCE = List.of("arm64-v8a", "armeabi-v7a", "x86_64", "x86");

	private final Path cacheDir;

	public SoExtractor(Path cacheDir) {
		this.cacheDir = cacheDir;
	}

	/** A native library entry found inside an APK: its abi, file name and full zip entry path. */
	public record SoEntry(String abi, String soName, String entryPath, long sizeBytes) {
		/** Stable id for the bridge: {@code <abi>_<soName>} with unsafe chars replaced. */
		public String soId() {
			return (abi + "_" + soName).replaceAll("[^A-Za-z0-9._-]", "_");
		}
	}

	/**
	 * List all {@code lib/<abi>/*.so} entries across the given input files (APKs/zips).
	 * Files that are not zips are skipped silently.
	 */
	public List<SoEntry> listSoEntries(List<File> inputFiles) {
		List<SoEntry> result = new ArrayList<>();
		for (File f : inputFiles) {
			if (f == null || !f.isFile()) {
				continue;
			}
			try (ZipFile zip = new ZipFile(f)) {
				Enumeration<? extends ZipEntry> entries = zip.entries();
				while (entries.hasMoreElements()) {
					ZipEntry e = entries.nextElement();
					if (e.isDirectory()) {
						continue;
					}
					String name = e.getName();
					if (name.startsWith("lib/") && name.endsWith(".so")) {
						String[] parts = name.split("/");
						if (parts.length == 3) {
							// uncompressed size, so callers can judge analysis cost without extracting first
							result.add(new SoEntry(parts[1], parts[2], name, Math.max(0, e.getSize())));
						}
					}
				}
			} catch (IOException ignored) {
				// not a zip / unreadable -> skip
			}
		}
		return result;
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
	 * Extract a single .so entry from the containing APK to the cache directory.
	 *
	 * @return the extracted file's path
	 */
	public Path extract(File apk, SoEntry entry) throws IOException {
		Files.createDirectories(cacheDir);
		Path out = cacheDir.resolve(entry.soId());
		try (ZipFile zip = new ZipFile(apk)) {
			ZipEntry ze = zip.getEntry(entry.entryPath());
			if (ze == null) {
				throw new IOException("Entry not found in APK: " + entry.entryPath());
			}
			try (InputStream in = zip.getInputStream(ze)) {
				Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
			}
		}
		return out;
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
		for (File f : inputFiles) {
			if (f == null || !f.isFile()) {
				continue;
			}
			try (ZipFile zip = new ZipFile(f)) {
				if (zip.getEntry(entry.entryPath()) != null) {
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
