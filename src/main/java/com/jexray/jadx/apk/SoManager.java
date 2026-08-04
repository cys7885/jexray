package com.jexray.jadx.apk;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.jexray.jadx.apk.SoExtractor.ExtractedSo;
import com.jexray.jadx.apk.SoExtractor.SoEntry;
import com.jexray.jadx.symbols.NativeSymbols;

/**
 * Multi-.so coordinator: enumerates the native libraries of the chosen ABI in the loaded
 * input(s), reads each candidate's exported symbols locally (pure Java, no Ghidra), and
 * resolves which .so actually exports a given JNI symbol so only that one is Ghidra-loaded
 * on demand.
 */
public class SoManager {

	private final List<String> abiPreference;
	private final SoExtractor extractor;
	private final List<Candidate> candidates = new ArrayList<>();
	private String chosenAbi;

	// memoized per soId
	private final Map<String, ExtractedSo> extracted = new ConcurrentHashMap<>();
	private final Map<String, Set<String>> exports = new ConcurrentHashMap<>();
	// memoized symbol -> soId ("" = looked up, not found)
	private final Map<String, String> symbolToSo = new ConcurrentHashMap<>();

	private record Candidate(SoEntry entry, File owner) {
		String soId() {
			return entry.soId();
		}
	}

	public SoManager(List<File> inputs, List<String> abiPreference, Path cacheDir) {
		this.abiPreference = abiPreference;
		this.extractor = new SoExtractor(cacheDir);
		scan(inputs);
	}

	private void scan(List<File> inputs) {
		if (inputs == null) {
			return;
		}
		for (File f : inputs) {
			if (f == null || !f.isFile()) {
				continue;
			}
			for (SoEntry e : extractor.listSoEntries(List.of(f))) {
				candidates.add(new Candidate(e, f));
			}
		}
		this.chosenAbi = pickAbi();
	}

	/** Best available ABI by preference; falls back to the first ABI seen. */
	private String pickAbi() {
		List<String> present = new ArrayList<>();
		for (Candidate c : candidates) {
			if (!present.contains(c.entry().abi())) {
				present.add(c.entry().abi());
			}
		}
		if (present.isEmpty()) {
			return null;
		}
		for (String pref : abiPreference) {
			if (present.contains(pref)) {
				return pref;
			}
		}
		return present.get(0);
	}

	public String chosenAbi() {
		return chosenAbi;
	}

	public boolean hasNativeLibraries() {
		return !candidates.isEmpty();
	}

	private List<Candidate> chosenCandidates() {
		List<Candidate> out = new ArrayList<>();
		for (Candidate c : candidates) {
			if (c.entry().abi().equals(chosenAbi)) {
				out.add(c);
			}
		}
		return out;
	}

	/** soIds of every .so in the chosen ABI (for the .so selector), in listing order. */
	public List<String> soIds() {
		List<String> ids = new ArrayList<>();
		for (Candidate c : chosenCandidates()) {
			if (!ids.contains(c.soId())) {
				ids.add(c.soId());
			}
		}
		return ids;
	}

	/** soId -> display .so file name, chosen ABI only. */
	public Map<String, String> soIdToName() {
		Map<String, String> m = new LinkedHashMap<>();
		for (Candidate c : chosenCandidates()) {
			m.putIfAbsent(c.soId(), c.entry().soName());
		}
		return m;
	}

	/**
	 * soId -&gt; uncompressed size in bytes, chosen ABI only. Read from the APK entry, so it is known
	 * before anything is extracted or analyzed -- which is what lets callers decide whether a
	 * library is too large to analyze without asking first.
	 */
	public Map<String, Long> soIdToSize() {
		Map<String, Long> m = new LinkedHashMap<>();
		for (Candidate c : chosenCandidates()) {
			m.putIfAbsent(c.soId(), c.entry().sizeBytes());
		}
		return m;
	}

	/** Extract (once) the .so for a soId, or null if unknown. */
	public synchronized ExtractedSo extractedForId(String soId) throws IOException {
		ExtractedSo cached = extracted.get(soId);
		if (cached != null) {
			return cached;
		}
		for (Candidate c : chosenCandidates()) {
			if (c.soId().equals(soId)) {
				Path p = extractor.extract(c.owner(), c.entry());
				ExtractedSo es = new ExtractedSo(c.entry(), p);
				extracted.put(soId, es);
				return es;
			}
		}
		return null;
	}

	private Set<String> exportsOf(Candidate c) {
		return exports.computeIfAbsent(c.soId(), id -> {
			try {
				ExtractedSo es = extractedForId(id);
				return es == null ? Set.of() : NativeSymbols.exportedSymbols(es.path().toFile());
			} catch (IOException e) {
				return Set.of();
			}
		});
	}

	/** soIds (chosen ABI) whose exported symbols include {@code exportName}. */
	public synchronized List<String> soIdsWithExport(String exportName) {
		List<String> out = new ArrayList<>();
		for (Candidate c : chosenCandidates()) {
			if (NativeSymbols.defines(exportsOf(c), exportName)) {
				out.add(c.soId());
			}
		}
		return out;
	}

	/**
	 * The soId of the .so that exports {@code jniSymbol}, found by scanning candidates' symbol
	 * tables locally, or null if no .so in the chosen ABI defines it (the caller then shows the
	 * RegisterNatives hint). A negative result is cached as {@code ""} internally so a repeated
	 * miss does not re-scan every candidate.
	 */
	public synchronized String findSoForSymbol(String jniSymbol) {
		String cached = symbolToSo.get(jniSymbol);
		if (cached != null) {
			return cached.isEmpty() ? null : cached;
		}
		for (Candidate c : chosenCandidates()) {
			if (NativeSymbols.defines(exportsOf(c), jniSymbol)) {
				symbolToSo.put(jniSymbol, c.soId());
				return c.soId();
			}
		}
		symbolToSo.put(jniSymbol, "");
		return null;
	}
}
