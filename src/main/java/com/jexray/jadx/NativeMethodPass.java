package com.jexray.jadx;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.plugins.pass.JadxPassInfo;
import jadx.api.plugins.pass.impl.SimpleJadxPassInfo;
import jadx.api.plugins.pass.types.JadxDecompilePass;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.dex.nodes.RootNode;

import com.jexray.jadx.LoadLibraryDetector.LoadLibraryCall;
import com.jexray.jadx.NativeMethodResolver.NativeMethod;

/**
 * Scans decompiled methods and records every {@code native} method together with its
 * computed JNI export symbol, plus every {@code System.loadLibrary}/{@code load} call site (see
 * {@link LoadLibraryDetector}) -- both are per-method facts this pass's method-visiting traversal
 * already does the work to reach, so both are collected in the same pass rather than walking every
 * method's instructions twice.
 *
 * <p>Native methods are exposed as a map keyed by the full JNI export symbol, so a caller holding a
 * symbol can resolve it back to its Java method node. Both collections only cover methods this pass
 * actually visited -- in jadx-gui, the classes the user has opened -- so neither is a whole-input
 * view; the raw-bytecode scanner is used where that is required.
 */
public class NativeMethodPass implements JadxDecompilePass {

	private static final Logger LOG = LoggerFactory.getLogger(NativeMethodPass.class);

	/** jniSymbol -> NativeMethod for all detected native methods. */
	private final Map<String, NativeMethod> nativeMethods = new ConcurrentHashMap<>();
	/** Every detected loadLibrary/load call site, in no particular order (methods may be
	 * decompiled concurrently). */
	private final List<LoadLibraryCall> loadLibraryCalls = new CopyOnWriteArrayList<>();
	private volatile RootNode root;

	@Override
	public JadxPassInfo getInfo() {
		return new SimpleJadxPassInfo("JexrayNativeMethodPass",
				"Detect native (JNI) methods and compute their export symbols");
	}

	@Override
	public void init(RootNode root) {
		this.root = root;
		nativeMethods.clear();
		loadLibraryCalls.clear();
	}

	@Override
	public boolean visit(ClassNode cls) {
		return true;
	}

	@Override
	public void visit(MethodNode mth) {
		if (NativeMethodResolver.isNative(mth)) {
			NativeMethod nm = NativeMethodResolver.resolve(mth);
			nativeMethods.put(nm.jniSymbol(), nm);
			if (LOG.isDebugEnabled()) {
				LOG.debug("native method detected: {} -> {}", nm.classBinaryName() + "." + nm.methodName(), nm.jniSymbol());
			}
		}
		List<LoadLibraryCall> calls = LoadLibraryDetector.detect(mth, root);
		if (!calls.isEmpty()) {
			loadLibraryCalls.addAll(calls);
		}
	}

	public Map<String, NativeMethod> getNativeMethods() {
		return Collections.unmodifiableMap(nativeMethods);
	}

	public List<NativeMethod> asList() {
		return List.copyOf(nativeMethods.values());
	}

	/** Every detected {@code System.loadLibrary}/{@code load} call site across the whole input. */
	public List<LoadLibraryCall> getLoadLibraryCalls() {
		return List.copyOf(loadLibraryCalls);
	}
}
