package com.jexray.jadx;

import java.util.ArrayList;
import java.util.List;

import jadx.api.metadata.ICodeNodeRef;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.BaseInvokeNode;
import jadx.core.dex.instructions.args.InsnArg;
import jadx.core.dex.nodes.BlockNode;
import jadx.core.dex.nodes.InsnNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.dex.nodes.RootNode;
import jadx.core.utils.InsnUtils;

/**
 * Detects {@code System.loadLibrary(String)} / {@code System.load(String)} call sites in
 * decompiled Java, for the "Loaded Libraries" window -- the only place in this plugin that needs
 * to know which native libraries an app actually asks the VM to load, as opposed to which native
 * <em>methods</em> it declares (that's {@link NativeMethodResolver}'s job).
 *
 * <p>Walks basic-block instructions the same way jadx's own {@code MethodInvokeVisitor} does
 * (both run as ordinary decompile passes, before codegen discards the block/instruction view), so
 * this sees exactly the invokes that end up in the generated source.
 */
public final class LoadLibraryDetector {

	private LoadLibraryDetector() {
	}

	public enum Kind {
		/** {@code System.loadLibrary(name)} -- resolved by Android's "lib" + name + ".so" convention. */
		LOAD_LIBRARY,
		/** {@code System.load(path)} -- resolved by the basename of the literal path. */
		LOAD
	}

	/**
	 * One detected call site.
	 *
	 * @param rawArg the literal string argument when jadx's constant folding could resolve it (a
	 *               plain string literal, an inlined {@code static final} constant, ...); {@code
	 *               null} when the argument is computed (concatenation, obfuscation, a
	 *               non-constant field/parameter) -- the call is real either way, but only a
	 *               non-null {@code rawArg} names a library. Callers must surface a null one as
	 *               "unresolved" rather than dropping it: an app that computes its library name
	 *               still loads *something*, and hiding the call site would understate that.
	 */
	public record LoadLibraryCall(Kind kind, String rawArg, String classBinaryName, String methodName,
			ICodeNodeRef ref) {
	}

	/** Scan one method's instructions for loadLibrary/load call sites. Empty for methods with no code. */
	public static List<LoadLibraryCall> detect(MethodNode mth, RootNode root) {
		List<LoadLibraryCall> out = new ArrayList<>();
		if (mth.isNoCode()) {
			return out;
		}
		MethodInfo mi = mth.getMethodInfo();
		String classBinaryName = mi.getDeclClass().makeRawFullName();
		String methodName = mi.getName();
		for (BlockNode block : mth.getBasicBlocks()) {
			for (InsnNode insn : block.getInstructions()) {
				insn.visitInsns(in -> {
					if (in instanceof BaseInvokeNode invoke) {
						Kind kind = kindOf(invoke.getCallMth());
						if (kind != null) {
							String raw = literalArg(root, invoke);
							out.add(new LoadLibraryCall(kind, raw, classBinaryName, methodName, mth));
						}
					}
				});
			}
		}
		return out;
	}

	/** {@code System.loadLibrary(String)} / {@code System.load(String)}, and nothing else -- an
	 * app-defined method that happens to be named "load" must never be mistaken for this. */
	private static Kind kindOf(MethodInfo callMth) {
		if (!"java.lang.System".equals(callMth.getDeclClass().getFullName())) {
			return null;
		}
		if (callMth.getArgsCount() != 1) {
			return null;
		}
		if ("loadLibrary".equals(callMth.getName())) {
			return Kind.LOAD_LIBRARY;
		}
		if ("load".equals(callMth.getName())) {
			return Kind.LOAD;
		}
		return null;
	}

	/** The literal string passed, or null if it can't be resolved to a constant. Both methods are
	 * static, so {@link BaseInvokeNode#getFirstArgOffset()} is the sole (name/path) argument. */
	private static String literalArg(RootNode root, BaseInvokeNode invoke) {
		int offset = invoke.getFirstArgOffset();
		if (invoke.getArgsCount() <= offset) {
			return null;
		}
		InsnArg arg = invoke.getArg(offset);
		Object value = InsnUtils.getConstValueByArg(root, arg);
		return value instanceof String s ? s : null;
	}
}
