package com.jexray.jadx;

import jadx.api.metadata.ICodeAnnotation;
import jadx.api.metadata.ICodeNodeRef;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.nodes.MethodNode;

import com.jexray.jadx.jni.JniMangler;
import com.jexray.jadx.jni.JniSignature;

/**
 * Bridges JADX method nodes to the JNI symbol computation.
 */
public final class NativeMethodResolver {

	private NativeMethodResolver() {
	}

	/**
	 * A detected native method with its computed JNI export symbol, JNI type signature
	 * (for matching a {@code RegisterNatives} entry), and a reference back to the original
	 * Java method node (for GUI navigation via {@code JadxGuiContext.open}).
	 */
	public record NativeMethod(String classBinaryName, String methodName, String jniSymbol,
			String signature, ICodeNodeRef ref) {
	}

	public static boolean isNative(MethodNode mth) {
		return mth != null && mth.getAccessFlags().isNative();
	}

	/**
	 * Build a {@link NativeMethod} from a native {@link MethodNode}. Uses the raw
	 * (un-aliased) class binary name and method name so the JNI symbol matches the
	 * shipped native library even for renamed/deobfuscated views.
	 */
	public static NativeMethod resolve(MethodNode mth) {
		MethodInfo mi = mth.getMethodInfo();
		String classBinaryName = mi.getDeclClass().makeRawFullName();
		String methodName = mi.getName();
		String symbol = JniMangler.shortSymbol(classBinaryName, methodName);
		String signature = JniSignature.of(mi.getArgumentsTypes(), mi.getReturnType());
		return new NativeMethod(classBinaryName, methodName, symbol, signature, mth);
	}

	/**
	 * Resolve a native method from a GUI code node reference (from a popup action).
	 *
	 * @return the resolved native method, or null if the ref is not a native method node
	 */
	public static NativeMethod resolveFromRef(ICodeNodeRef ref) {
		if (ref == null || ref.getAnnType() != ICodeAnnotation.AnnType.METHOD) {
			return null;
		}
		if (!(ref instanceof MethodNode mth)) {
			return null;
		}
		if (!isNative(mth)) {
			return null;
		}
		return resolve(mth);
	}
}
