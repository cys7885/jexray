package com.jexray.jadx.ghidra;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Reads and reclaims the on-disk Ghidra analysis cache under {@code <home>/projects/}.
 *
 * <p>Two generations of cache key live side by side there:
 * <ul>
 *   <li><b>active</b> -- keyed by the analyzed .so's SHA-256 content hash (64 lowercase hex
 *       chars). This is what {@link EmbeddedGhidraBridge} reads and writes today.</li>
 *   <li><b>legacy</b> -- keyed by the pre-hash {@code <abi>_<soName>} id (see
 *       {@code SoExtractor.SoEntry#soId()}), carrying the same {@code .cache.json} /
 *       {@code .progress.json} / {@code .gpr} / {@code .rep} suffixes.
 *       Left over from before this change. Deliberately never read by the bridge: nothing on
 *       disk proves which binary produced a legacy entry (the .so bytes that made it were never
 *       kept, only Ghidra's dump of them), and one file name can stand for more than one binary,
 *       so adopting an entry on the strength of its name alone could answer with another
 *       library's pseudocode. Keying by content hash is what makes that unrepresentable.</li>
 * </ul>
 *
 * <p>{@code index.json} maps an active entry's hash back to the human-readable id it was last
 * analyzed under (a bare hash means nothing to a user browsing the cache in Preferences/UI), so
 * this class -- not just the bridge's in-memory session state -- can name it.
 */
public final class CacheCatalog {

	private static final Pattern HASH_PATTERN = Pattern.compile("[0-9a-f]{64}");
	private static final String INDEX_FILE = "index.json";

	// Guards every read AND write of index.json -- recordUse, scan's read, and clear*'s read+write
	// all take this before touching the file. Without it, a writer (recordUse/clear*) could replace
	// index.json while a reader (scan) has it open, or two writers could interleave their read
	// -modify-write and lose one's update; on Windows, replacing a file another thread has open for
	// reading throws AccessDeniedException outright rather than silently working as it does on
	// POSIX, which is why this only ever showed up here as a rare macOS @TempDir teardown flake.
	private static final Object INDEX_LOCK = new Object();

	private CacheCatalog() {
	}

	/** One cached library on disk: its key (hash or legacy id), a human name, and its size. */
	public record Entry(String key, String displayName, long sizeBytes) {
	}

	/** Everything found under {@code <home>/projects/}, split by generation. */
	public record Stats(List<Entry> active, long activeBytes, List<Entry> legacy, long legacyBytes) {
		public long totalBytes() {
			return activeBytes + legacyBytes;
		}
	}

	public static File homeDir() {
		return new File(System.getProperty("user.home"), ".jexray");
	}

	public static File projectsDir(File home) {
		return new File(home, "projects");
	}

	private static File indexFile(File home) {
		return new File(projectsDir(home), INDEX_FILE);
	}

	static boolean isContentHash(String key) {
		return key != null && HASH_PATTERN.matcher(key).matches();
	}

	/**
	 * Record (or refresh) the human-readable name and size for a hash-keyed cache entry.
	 * Called by the bridge after every successful load (fresh analysis or cache hit) so the
	 * catalog can later show a name instead of a bare hash. Best-effort: a failure to persist
	 * the index never fails the load it's attached to.
	 */
	public static void recordUse(File home, String hash, String displayName) {
		synchronized (INDEX_LOCK) {
			try {
				Map<String, String> index = readIndex(home);
				index.put(hash, displayName);
				writeIndex(home, index);
			} catch (IOException e) {
				System.err.println("[jexray-bridge] failed to update cache index for " + hash + ": " + e.getMessage());
			}
		}
	}

	private static Map<String, String> readIndex(File home) {
		Map<String, String> out = new LinkedHashMap<>();
		File f = indexFile(home);
		if (!f.isFile()) {
			return out;
		}
		try {
			JsonObject root = JsonParser.parseString(Files.readString(f.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();
			for (Map.Entry<String, com.google.gson.JsonElement> e : root.entrySet()) {
				out.put(e.getKey(), e.getValue().getAsString());
			}
		} catch (Exception e) {
			// corrupt index -> treat as empty; names fall back to the bare hash, nothing fatal
			System.err.println("[jexray-bridge] cache index unreadable, ignoring: " + e.getMessage());
		}
		return out;
	}

	private static void writeIndex(File home, Map<String, String> index) throws IOException {
		File dir = projectsDir(home);
		Files.createDirectories(dir.toPath());
		StringBuilder sb = new StringBuilder("{");
		boolean first = true;
		for (Map.Entry<String, String> e : index.entrySet()) {
			if (!first) {
				sb.append(',');
			}
			first = false;
			sb.append(jsonString(e.getKey())).append(':').append(jsonString(e.getValue()));
		}
		sb.append('}');
		// a unique-per-write temp name so two writers (however they're serialized -- this call
		// itself always runs under INDEX_LOCK, but the name is unique regardless in case that ever
		// changes) can never collide on the same temp file; always cleaned up below, even on failure,
		// so a thrown exception can never orphan it the way a fixed "index.json.tmp" name
		// could.
		File tmp = Files.createTempFile(dir.toPath(), INDEX_FILE, ".tmp").toFile();
		try {
			Files.writeString(tmp.toPath(), sb.toString(), StandardCharsets.UTF_8);
			try {
				Files.move(tmp.toPath(), indexFile(home).toPath(),
						java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
			} catch (java.nio.file.AtomicMoveNotSupportedException e) {
				// some filesystems (notably several Windows configurations) can't do an atomic
				// rename across the source/target in question -- fall back to a plain replace rather
				// than fail the write entirely; index.json isn't read mid-write by anything holding
				// less than INDEX_LOCK, so losing atomicity here (but not the lock) is an acceptable
				// trade rather than a correctness problem.
				Files.move(tmp.toPath(), indexFile(home).toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
			}
		} finally {
			// if writeString or move threw, tmp is still sitting on disk under its own unique name --
			// this is exactly the orphaned index.json.tmp the flaky @TempDir teardown couldn't
			// delete; harmless no-op once the move above already succeeded (the file is gone).
			Files.deleteIfExists(tmp.toPath());
		}
	}

	/** Scan {@code <home>/projects/} and classify every cached library into active vs. legacy. */
	public static Stats scan(File home) {
		File dir = projectsDir(home);
		File[] files = dir.listFiles();
		if (files == null) {
			return new Stats(List.of(), 0, List.of(), 0);
		}
		Map<String, String> names;
		synchronized (INDEX_LOCK) {
			names = readIndex(home);
		}
		Map<String, Boolean> keys = new LinkedHashMap<>(); // key -> isActive, insertion order
		for (File f : files) {
			String name = f.getName();
			String key = stripKnownSuffix(name);
			if (key == null || INDEX_FILE.equals(name)) {
				continue;
			}
			keys.putIfAbsent(key, isContentHash(key));
		}

		List<Entry> active = new ArrayList<>();
		List<Entry> legacy = new ArrayList<>();
		long activeBytes = 0;
		long legacyBytes = 0;
		for (Map.Entry<String, Boolean> e : keys.entrySet()) {
			String key = e.getKey();
			long size = keySize(dir, key);
			String display = e.getValue() ? names.getOrDefault(key, key) : key;
			Entry entry = new Entry(key, display, size);
			if (e.getValue()) {
				active.add(entry);
				activeBytes += size;
			} else {
				legacy.add(entry);
				legacyBytes += size;
			}
		}
		return new Stats(active, activeBytes, legacy, legacyBytes);
	}

	/** Delete every legacy-keyed cache entry. Returns bytes freed. */
	public static long clearLegacy(File home) {
		return clear(home, key -> !isContentHash(key));
	}

	/** Delete every cached entry, active and legacy, plus the name index. Returns bytes freed. */
	public static long clearAll(File home) {
		long freed = clear(home, key -> true);
		synchronized (INDEX_LOCK) {
			indexFile(home).delete();
		}
		return freed;
	}

	private static long clear(File home, java.util.function.Predicate<String> matches) {
		File dir = projectsDir(home);
		File[] files = dir.listFiles();
		if (files == null) {
			return 0;
		}
		java.util.Set<String> keys = new java.util.LinkedHashSet<>();
		for (File f : files) {
			String key = stripKnownSuffix(f.getName());
			if (key != null && !INDEX_FILE.equals(f.getName()) && matches.test(key)) {
				keys.add(key);
			}
		}
		long freed = 0;
		for (String key : keys) {
			freed += keySize(dir, key);
			deleteQuietly(new File(dir, key + ".cache.json"));
			deleteQuietly(new File(dir, key + ".progress.json"));
			deleteQuietly(new File(dir, key + ".gpr"));
			deleteRecursively(new File(dir, key + ".rep"));
		}
		// the index read-modify-write is its own critical section, separate from the file deletions
		// above (which don't touch index.json at all) -- serialized against every other reader/writer
		// the same way recordUse's is, so a concurrent recordUse/scan/clear can never observe or
		// produce a half-written index.
		synchronized (INDEX_LOCK) {
			Map<String, String> index = readIndex(home);
			boolean indexChanged = false;
			for (String key : keys) {
				if (index.remove(key) != null) {
					indexChanged = true;
				}
			}
			if (indexChanged) {
				try {
					writeIndex(home, index);
				} catch (IOException e) {
					System.err.println("[jexray-bridge] failed to update cache index after clear: " + e.getMessage());
				}
			}
		}
		return freed;
	}

	/** Total on-disk bytes for one key's cache.json + progress.json + gpr + rep/ directory. */
	private static long keySize(File dir, String key) {
		long total = 0;
		total += new File(dir, key + ".cache.json").length();
		total += new File(dir, key + ".progress.json").length();
		total += new File(dir, key + ".gpr").length();
		total += sizeRecursively(new File(dir, key + ".rep"));
		return total;
	}

	private static long sizeRecursively(File f) {
		if (f == null || !f.exists()) {
			return 0;
		}
		if (f.isFile()) {
			return f.length();
		}
		File[] children = f.listFiles();
		if (children == null) {
			return 0;
		}
		long total = 0;
		for (File c : children) {
			total += sizeRecursively(c);
		}
		return total;
	}

	private static void deleteRecursively(File f) {
		if (f == null || !f.exists()) {
			return;
		}
		File[] children = f.listFiles();
		if (children != null) {
			for (File c : children) {
				deleteRecursively(c);
			}
		}
		f.delete();
	}

	private static void deleteQuietly(File f) {
		if (f != null && f.exists()) {
			f.delete();
		}
	}

	/**
	 * Strip a known cache-file suffix to recover the key, or null if {@code name} doesn't end in
	 * one. Suffix-stripping (not splitting on the first separator) because a key can itself
	 * contain dots, since a legacy id embeds the library's own file name.
	 */
	private static String stripKnownSuffix(String name) {
		for (String suffix : new String[] {".cache.json", ".progress.json", ".gpr", ".rep"}) {
			if (name.endsWith(suffix) && name.length() > suffix.length()) {
				return name.substring(0, name.length() - suffix.length());
			}
		}
		return null;
	}

	private static String jsonString(String s) {
		StringBuilder sb = new StringBuilder(s.length() + 16);
		sb.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					sb.append("\\\"");
					break;
				case '\\':
					sb.append("\\\\");
					break;
				case '\n':
					sb.append("\\n");
					break;
				case '\r':
					sb.append("\\r");
					break;
				case '\t':
					sb.append("\\t");
					break;
				default:
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					} else {
						sb.append(c);
					}
			}
		}
		sb.append('"');
		return sb.toString();
	}
}
