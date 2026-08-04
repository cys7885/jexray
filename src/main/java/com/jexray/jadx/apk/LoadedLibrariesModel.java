package com.jexray.jadx.apk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jadx.api.metadata.ICodeNodeRef;

import com.jexray.jadx.LoadLibraryDetector.Kind;
import com.jexray.jadx.LoadLibraryDetector.LoadLibraryCall;

/**
 * Correlates detected {@code System.loadLibrary}/{@code load} call sites with the native
 * libraries actually present in the loaded input(s), for the "Loaded Libraries" window.
 *
 * <p>Produces the three-part honest picture that window exists to show -- never just the part
 * that could be fully resolved:
 * <ul>
 *   <li>{@link Result#resolved()} -- a requested name/path jadx could read, whether or not the
 *       library it names is actually in the APK ({@link ResolvedLibrary#inApk()} says which).</li>
 *   <li>{@link Result#unresolved()} -- a real call site whose argument could NOT be read (
 *       obfuscated, concatenated, a computed value). Dropping these would imply the app loads
 *       only what could be read, which is false.</li>
 *   <li>{@link Result#unloaded()} -- a .so shipped in the input that no detected call site loads
 *       (dead weight, or loaded reflectively/by JNI_OnLoad rather than a plain loadLibrary call).</li>
 * </ul>
 */
public final class LoadedLibrariesModel {

	private LoadedLibrariesModel() {
	}

	/** Where a load call was made from, so the UI can offer "loaded by ..." navigation. */
	public record LoadSite(String classBinaryName, String methodName, ICodeNodeRef ref) {
	}

	/** One requested library name/path, resolved to an APK .so when one matches. */
	public record ResolvedLibrary(String requestedName, Kind kind, String soId, String soFileName,
			long sizeBytes, boolean inApk, List<LoadSite> loadSites) {
	}

	/** A load call whose argument jadx could not resolve to a literal string. */
	public record UnresolvedCall(Kind kind, LoadSite site) {
	}

	/** A .so present in the input that no detected call site resolves to. */
	public record UnloadedLibrary(String soId, String soFileName, long sizeBytes) {
	}

	public record Result(List<ResolvedLibrary> resolved, List<UnresolvedCall> unresolved,
			List<UnloadedLibrary> unloaded) {
	}

	/**
	 * Build the three-part result from every detected call site and the .so's known to be in the
	 * chosen-ABI input. Multiple calls that resolve to the same requested name are merged into one
	 * {@link ResolvedLibrary} with every load site attached, so a library loaded from several
	 * places (common for a shared "load all natives" helper) shows up once, not once per call.
	 */
	public static Result build(List<LoadLibraryCall> calls, SoManager soManager) {
		Map<String, String> soIdToName = soManager.soIdToName();
		Map<String, Long> soIdToSize = soManager.soIdToSize();
		Map<String, String> nameToSoId = new LinkedHashMap<>();
		for (Map.Entry<String, String> e : soIdToName.entrySet()) {
			nameToSoId.put(e.getValue(), e.getKey());
		}

		// accumulated per requested name, then frozen into immutable ResolvedLibrary records below
		Map<String, Kind> kindByName = new LinkedHashMap<>();
		Map<String, List<LoadSite>> sitesByName = new LinkedHashMap<>();
		Map<String, String> soIdByName = new LinkedHashMap<>();
		List<UnresolvedCall> unresolved = new ArrayList<>();
		Set<String> matchedSoIds = new LinkedHashSet<>();

		for (LoadLibraryCall call : calls) {
			LoadSite site = new LoadSite(call.classBinaryName(), call.methodName(), call.ref());
			if (call.rawArg() == null) {
				unresolved.add(new UnresolvedCall(call.kind(), site));
				continue;
			}
			String name = call.rawArg();
			kindByName.putIfAbsent(name, call.kind());
			sitesByName.computeIfAbsent(name, k -> new ArrayList<>()).add(site);
			String soId = soIdByName.computeIfAbsent(name,
					n -> nameToSoId.get(expectedSoName(call.kind(), n))); // null if not in the APK
			if (soId != null) {
				matchedSoIds.add(soId);
			}
		}

		List<ResolvedLibrary> resolved = new ArrayList<>();
		for (Map.Entry<String, List<LoadSite>> e : sitesByName.entrySet()) {
			String name = e.getKey();
			String soId = soIdByName.get(name);
			resolved.add(new ResolvedLibrary(name, kindByName.get(name), soId,
					soId == null ? null : soIdToName.get(soId),
					soId == null ? 0L : soIdToSize.getOrDefault(soId, 0L),
					soId != null, List.copyOf(e.getValue())));
		}

		List<UnloadedLibrary> unloaded = new ArrayList<>();
		for (String soId : soManager.soIds()) {
			if (!matchedSoIds.contains(soId)) {
				unloaded.add(new UnloadedLibrary(soId, soIdToName.get(soId), soIdToSize.getOrDefault(soId, 0L)));
			}
		}

		return new Result(resolved, unresolved, unloaded);
	}

	/**
	 * The .so file name a requested library/path is expected to correspond to. {@code
	 * loadLibrary(name)} follows Android's "the VM prepends 'lib' and appends '.so'" convention;
	 * {@code load(path)} already names the file directly, so only its basename is taken.
	 */
	private static String expectedSoName(Kind kind, String rawArg) {
		if (kind == Kind.LOAD) {
			int slash = Math.max(rawArg.lastIndexOf('/'), rawArg.lastIndexOf('\\'));
			return slash >= 0 ? rawArg.substring(slash + 1) : rawArg;
		}
		return "lib" + rawArg + ".so";
	}
}
