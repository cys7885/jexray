package com.jexray.jadx;

import jadx.api.plugins.options.impl.BasePluginOptionsBuilder;

import com.jexray.jadx.bridge.GhidraBridgeClient;

/**
 * Plugin options, surfaced in JADX GUI Preferences &gt; Plugins.
 *
 * <p>Deliberately has no cache-size/clear option: {@link BasePluginOptionsBuilder} (this whole
 * API) only offers value settings -- {@code boolOption}/{@code strOption}/{@code intOption}/
 * {@code enumOption}, each just a getter/setter pair a preferences panel renders as a plain field
 * -- with no button or action control to trigger a clear, and no way for a value to refresh itself
 * as the cache grows or shrinks after the options panel is built. A str/int field showing a size
 * here would either need live refreshing this API can't do, or would go stale the moment the
 * cache changes -- worse than not showing it. The actual size display and clear action live in
 * the Native View toolbar's "Cache…" button instead, where they can be computed on
 * demand: see {@code com.jexray.jadx.ui.CacheDialog} and {@code JexrayPlugin#showCacheDialog}.
 */
public class JexrayOptions extends BasePluginOptionsBuilder {

	public static final String OPT_BASE_URL = JexrayPlugin.PLUGIN_ID + ".bridge.url";
	public static final String OPT_EMBEDDED = JexrayPlugin.PLUGIN_ID + ".bridge.embedded";
	public static final String OPT_GHIDRA_DIR = JexrayPlugin.PLUGIN_ID + ".ghidra.installDir";
	public static final String OPT_ABI_PREF = JexrayPlugin.PLUGIN_ID + ".abi.preference";
	public static final String OPT_ANALYZE_ALL_ON_OPEN = JexrayPlugin.PLUGIN_ID + ".analyze.allOnOpen";
	public static final String OPT_ANALYZE_ALL_ON_BROWSE = JexrayPlugin.PLUGIN_ID + ".analyze.allOnBrowse";

	public static final String DEFAULT_ABI_PREF = "arm64-v8a,armeabi-v7a,x86_64,x86";

	private String bridgeUrl = GhidraBridgeClient.DEFAULT_BASE_URL;
	private boolean embeddedBridge = true;
	private String ghidraInstallDir = "";
	private String abiPreference = DEFAULT_ABI_PREF;
	private boolean analyzeAllOnOpen;
	private boolean analyzeAllOnBrowse = true;

	@Override
	public void registerOptions() {
		boolOption(OPT_EMBEDDED)
				.description("Run the Ghidra bridge in-process (single jar). Disable to use an external bridge.")
				.defaultValue(true)
				.setter(v -> embeddedBridge = v);

		strOption(OPT_GHIDRA_DIR)
				.description("Ghidra install directory (the folder containing support/analyzeHeadless[.bat]). "
						+ "Blank = use $GHIDRA_INSTALL_DIR or auto-detect common locations.")
				.defaultValue("")
				.setter(v -> ghidraInstallDir = v == null ? "" : v);

		strOption(OPT_BASE_URL)
				.description("Base URL of an external Ghidra bridge (used only when embedded bridge is disabled)")
				.defaultValue(GhidraBridgeClient.DEFAULT_BASE_URL)
				.setter(v -> bridgeUrl = v);

		// Analysis is per-library and on-demand by default because it is expensive -- a large
		// library can take an hour, and an APK shipping several would otherwise spend all of it
		// before showing the first function. These two let a user who would rather wait once say so.
		boolOption(OPT_ANALYZE_ALL_ON_OPEN)
				.description("Analyze every native library as soon as an APK is opened. Off by default: "
						+ "analysis time scales with library size, so a large APK can take a long while "
						+ "before anything is browsable.")
				.defaultValue(false)
				.setter(v -> analyzeAllOnOpen = v);

		boolOption(OPT_ANALYZE_ALL_ON_BROWSE)
				.description("When a Jexray window is opened, analyze every native library rather than "
						+ "only the one being looked at.")
				.defaultValue(true)
				.setter(v -> analyzeAllOnBrowse = v);

		strOption(OPT_ABI_PREF)
				.description("Preferred ABIs (comma-separated, best first) for choosing which lib/<abi>/ to analyze")
				.defaultValue(DEFAULT_ABI_PREF)
				.setter(v -> abiPreference = (v == null || v.isBlank()) ? DEFAULT_ABI_PREF : v);
	}

	/** Parsed ABI preference list, best first. */
	public java.util.List<String> getAbiPreference() {
		java.util.List<String> out = new java.util.ArrayList<>();
		for (String s : abiPreference.split(",")) {
			String t = s.trim();
			if (!t.isEmpty()) {
				out.add(t);
			}
		}
		return out.isEmpty() ? java.util.List.of("arm64-v8a", "armeabi-v7a", "x86_64", "x86") : out;
	}

	public String getBridgeUrl() {
		return bridgeUrl;
	}

	public boolean isEmbeddedBridge() {
		return embeddedBridge;
	}

	public String getGhidraInstallDir() {
		return ghidraInstallDir;
	}

	/** Analyze every library up front, as soon as an APK is opened. */
	public boolean isAnalyzeAllOnOpen() {
		return analyzeAllOnOpen;
	}

	/** Analyze every library when a Jexray window is opened, not just the one in view. */
	public boolean isAnalyzeAllOnBrowse() {
		return analyzeAllOnBrowse;
	}
}
