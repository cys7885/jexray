package com.jexray.jadx.ghidra;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Reads and range-checks the installed Ghidra version from
 * {@code <installDir>/Ghidra/application.properties}. Pure/IO-only, no Ghidra runtime.
 *
 * <p>Supported majors are those actually integration-tested by this project: 11.x and 12.x
 * (verified with Ghidra 11.3.2 and 12.0). Other versions still run — the plugin only warns.
 */
public final class GhidraVersion {

	public static final int MIN_SUPPORTED_MAJOR = 11;
	public static final int MAX_SUPPORTED_MAJOR = 12;

	private GhidraVersion() {
	}

	/** {@code application.version} from the install's application.properties, or null if unreadable. */
	public static String readVersion(File ghidraInstallDir) {
		if (ghidraInstallDir == null) {
			return null;
		}
		File props = new File(new File(ghidraInstallDir, "Ghidra"), "application.properties");
		if (!props.isFile()) {
			return null;
		}
		try {
			for (String line : Files.readAllLines(props.toPath(), StandardCharsets.UTF_8)) {
				String t = line.trim();
				if (t.startsWith("application.version=")) {
					String v = t.substring("application.version=".length()).trim();
					return v.isEmpty() ? null : v;
				}
			}
		} catch (IOException ignored) {
			// unreadable -> unknown
		}
		return null;
	}

	/** Major version number (e.g. 12 for "12.0", 11 for "11.3.2"), or -1 if unparseable. */
	public static int majorOf(String version) {
		if (version == null) {
			return -1;
		}
		int dot = version.indexOf('.');
		String major = dot < 0 ? version : version.substring(0, dot);
		try {
			return Integer.parseInt(major.trim());
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/** True if the version's major is within the tested support range. Unknown versions are not "supported". */
	public static boolean isSupported(String version) {
		int major = majorOf(version);
		return major >= MIN_SUPPORTED_MAJOR && major <= MAX_SUPPORTED_MAJOR;
	}

	/**
	 * A user-facing warning if the version is known but outside the tested range, else null.
	 * A null/unparseable version returns null (nothing to warn about — the missing-install
	 * check handles absent Ghidra separately).
	 */
	public static String supportWarning(String version) {
		if (version == null || majorOf(version) < 0) {
			return null;
		}
		if (isSupported(version)) {
			return null;
		}
		return "Ghidra " + version + " is untested with this plugin (tested range: "
				+ MIN_SUPPORTED_MAJOR + ".x-" + MAX_SUPPORTED_MAJOR + ".x). "
				+ "Decompilation may not work correctly.";
	}
}
