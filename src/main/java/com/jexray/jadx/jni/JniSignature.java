package com.jexray.jadx.jni;

import java.util.List;

import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.instructions.args.PrimitiveType;

/**
 * Builds the JNI type signature of a method: the parameter descriptors in order, parenthesised,
 * followed by the return descriptor.
 *
 * <p>This is the descriptor passed in a {@code JNINativeMethod} entry (2nd field) when a
 * method is registered dynamically via {@code RegisterNatives}. It is a separate concern from
 * {@link JniMangler} (which builds the exported symbol name); this maps parameter and return
 * types to JVM type descriptors per the JNI spec:
 * <ul>
 *   <li>Z boolean, B byte, C char, S short, I int, J long, F float, D double, V void</li>
 *   <li>{@code L<binary/class/name>;} for objects (dots become slashes)</li>
 *   <li>{@code [} prefix for each array dimension</li>
 * </ul>
 */
public final class JniSignature {

	private JniSignature() {
	}

	/** Full signature: {@code (<arg descriptors>)<return descriptor>}. */
	public static String of(List<ArgType> argTypes, ArgType returnType) {
		StringBuilder sb = new StringBuilder("(");
		if (argTypes != null) {
			for (ArgType a : argTypes) {
				sb.append(descriptorOf(a));
			}
		}
		sb.append(')').append(descriptorOf(returnType));
		return sb.toString();
	}

	/** JVM type descriptor for a single type. */
	public static String descriptorOf(ArgType type) {
		if (type == null || type.isVoid()) {
			return "V";
		}
		if (type.isArray()) {
			return "[" + descriptorOf(type.getArrayElement());
		}
		if (type.isPrimitive()) {
			return primitive(type.getPrimitiveType());
		}
		if (type.isObject()) {
			return "L" + type.getObject().replace('.', '/') + ";";
		}
		return "V";
	}

	private static String primitive(PrimitiveType p) {
		switch (p) {
			case BOOLEAN: return "Z";
			case BYTE:    return "B";
			case CHAR:    return "C";
			case SHORT:   return "S";
			case INT:     return "I";
			case LONG:    return "J";
			case FLOAT:   return "F";
			case DOUBLE:  return "D";
			case VOID:    return "V";
			default:      return "V";
		}
	}
}
