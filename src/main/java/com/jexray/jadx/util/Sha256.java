package com.jexray.jadx.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 content hashing for native libraries, used as the Ghidra bridge's cache key (see
 * {@code com.jexray.jadx.ghidra.EmbeddedGhidraBridge}) so two .so files that merely share a name
 * -- e.g. the same-named library shipped with different bytes in two different APKs -- can never
 * collide on a cached analysis result the way the old {@code <abi>_<soName>} key did.
 *
 * <p>Streamed rather than read into a byte array: a native library can run to hundreds of megabytes,
 * and a full heap copy per hash would be wasteful for something computed once per {@code /so/load}.
 */
public final class Sha256 {

	private static final int BUFFER_SIZE = 1 << 16; // 64KB

	private Sha256() {
	}

	/** Lowercase hex SHA-256 digest of a file's contents. */
	public static String hex(File file) throws IOException {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// every JDK ships SHA-256; this is defensive only, never expected to trigger
			throw new IOException("SHA-256 not available in this JVM", e);
		}
		try (InputStream in = Files.newInputStream(file.toPath())) {
			byte[] buf = new byte[BUFFER_SIZE];
			int n;
			while ((n = in.read(buf)) != -1) {
				md.update(buf, 0, n);
			}
		}
		return toHex(md.digest());
	}

	private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(Character.forDigit((b >> 4) & 0xF, 16));
			sb.append(Character.forDigit(b & 0xF, 16));
		}
		return sb.toString();
	}
}
