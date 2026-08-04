package com.jexray.jadx;

import java.io.InputStream;
import java.util.Properties;

/**
 * Reads the plugin's own version, injected at build time from the pom {@code <version>} into
 * {@code /jexray/build.properties} (Maven resource filtering) — so the version lives in one
 * place, not hard-coded in source.
 */
public final class PluginVersion {

	private static final String VERSION = load();

	private PluginVersion() {
	}

	public static String get() {
		return VERSION;
	}

	private static String load() {
		try (InputStream in = PluginVersion.class.getResourceAsStream("/jexray/build.properties")) {
			if (in != null) {
				Properties p = new Properties();
				p.load(in);
				String v = p.getProperty("plugin.version");
				if (v != null && !v.isBlank() && !v.contains("${")) {
					return v.trim();
				}
			}
		} catch (Exception ignored) {
			// fall through
		}
		return "dev";
	}
}
