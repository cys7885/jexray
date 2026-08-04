package com.jexray.jadx.jni;

/**
 * Computes JNI short-form exported symbol names for {@code native} Java methods.
 *
 * <p>Short form only: overload disambiguation (the long form with a {@code __} +
 * mangled argument signature suffix) is NOT implemented. If two native methods in the
 * same class share a name, both map to the same short symbol here; the native library
 * would actually export the long form for the overloaded ones.
 *
 * <p>No dependency on any JADX API so it can be unit tested in isolation.
 */
public final class JniMangler {

	private JniMangler() {
	}

	/**
	 * Build the JNI short-form symbol for a native method.
	 *
	 * @param classBinaryName the owning class' fully qualified binary name in dotted form,
	 *                        including any {@code $} separator for a nested class
	 * @param methodName      the (unaliased/raw) Java method name
	 * @return the exported symbol: the {@code Java_} prefix, then the mangled class name and
	 *         method name joined by an underscore
	 */
	public static String shortSymbol(String classBinaryName, String methodName) {
		StringBuilder sb = new StringBuilder("Java_");
		mangle(sb, classBinaryName);
		sb.append('_');
		mangle(sb, methodName);
		return sb.toString();
	}

	/**
	 * Convenience: derive the JNI class prefix, i.e. the dotted class name in JNI-mangled form.
	 */
	public static String mangleClass(String classBinaryName) {
		StringBuilder sb = new StringBuilder();
		mangle(sb, classBinaryName);
		return sb.toString();
	}

	/**
	 * Apply the JNI Unicode mangling to a name.
	 *
	 * <p>Per the JNI spec "Resolving Native Method Names":
	 * <ul>
	 *   <li>package separator ('.' here, '/' in internal form) &rarr; '_'</li>
	 *   <li>'_' &rarr; "_1"</li>
	 *   <li>';' &rarr; "_2"</li>
	 *   <li>'[' &rarr; "_3"</li>
	 *   <li>ASCII letters and digits &rarr; unchanged</li>
	 *   <li>any other character (incl. '$' for inner classes) &rarr; "_0" + 4-digit lowercase hex</li>
	 * </ul>
	 */
	private static void mangle(StringBuilder sb, String name) {
		int len = name.length();
		for (int i = 0; i < len; i++) {
			char c = name.charAt(i);
			if (c == '.' || c == '/') {
				sb.append('_');
			} else if (c == '_') {
				sb.append("_1");
			} else if (c == ';') {
				sb.append("_2");
			} else if (c == '[') {
				sb.append("_3");
			} else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				sb.append(c);
			} else {
				sb.append("_0");
				String hex = Integer.toHexString(c);
				for (int p = hex.length(); p < 4; p++) {
					sb.append('0');
				}
				sb.append(hex);
			}
		}
	}
}
