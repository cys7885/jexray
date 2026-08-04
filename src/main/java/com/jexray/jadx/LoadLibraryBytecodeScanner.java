package com.jexray.jadx;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jadx.api.plugins.input.data.ICodeReader;
import jadx.api.plugins.input.data.IFieldRef;
import jadx.api.plugins.input.data.IMethodRef;
import jadx.api.plugins.input.insns.InsnData;
import jadx.api.plugins.input.insns.InsnIndexType;
import jadx.api.plugins.input.insns.Opcode;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.dex.nodes.RootNode;

import com.jexray.jadx.LoadLibraryDetector.Kind;
import com.jexray.jadx.LoadLibraryDetector.LoadLibraryCall;

/**
 * Scans every class's RAW dex instructions for {@code System.loadLibrary}/{@code load} call sites,
 * without decompiling anything -- this is the fix for the gap {@link LoadLibraryDetector} has on
 * its own: that class only sees what {@link NativeMethodPass} (a {@code JadxDecompilePass})
 * happened to already decompile, which in jadx-gui is only whatever class the user has opened. A
 * {@code loadLibrary} call sitting in a {@code <clinit>} the user never opened was invisible to the
 * "Loaded Libraries" window even though the app unconditionally runs it.
 *
 * <p>Reads {@link MethodNode#getCodeReader()} -- the pre-decompile view straight over dex
 * bytecode ({@code jadx.plugins.input.dex.sections.DexCodeReader} under the hood) -- which every
 * {@link MethodNode} already owns from when jadx parsed the input's classes, well before its
 * decompile pipeline (block building / SSA / codegen) ever runs for any of them. So this scan
 * touches every method in the input with none of the cost of decompiling it: confirmed against
 * jadx 1.5.5 by driving this scanner off a {@code JadxDecompiler} that only called {@code load()}
 * (parses class/method structure) and never processed a single class.
 *
 * <p>Constant tracking is deliberately narrow: a {@code const-string} is only trusted as an
 * invoke's argument when it lands in the SAME register the VERY NEXT instruction visited reads --
 * exactly the shape javac/d8 emit for {@code System.loadLibrary("literal")}, including a literal
 * pulled from an inlined {@code static final} (javac itself inlines those at compile time, so they
 * already arrive here as a plain {@code const-string}, no field read involved). Raw dex has no
 * general-purpose "what wrote this register" answer the way jadx's own IR/SSA does once decompiled,
 * so anything looser -- a const-string set further back, a register reused for something else in
 * between -- is left {@code null} (unresolved) rather than risked: per
 * {@link LoadLibraryCall#rawArg}, a wrong guess here would be worse than reporting no guess at all.
 *
 * <p>One narrow exception is worth the extra risk: a non-final static field assigned a single
 * string literal and read back right before the load call -- common when the literal is set well
 * ahead of the load with logging or StringBuilder work in between, which defeats the
 * one-instruction lookahead above and used to report the call as
 * unresolved even though the name is, in fact, statically known. This is handled with a class-wide
 * two-pass scan: {@link #collectFieldLiterals} first walks every method of a class recording, per
 * static field, the literal from any {@code const-string; sput} pair that targets it; {@link
 * #scanClass} then re-walks every method treating an {@code sget} of a field found in that map as
 * if it were a fresh {@code const-string} for the SAME one-instruction-lookahead rule above. The
 * safety condition is single assignment: a field written more than once anywhere in the class --
 * even to the same literal twice -- or ever written from something that isn't a plain
 * {@code const-string} (a concatenation, a method result, another field) is POISONED and permanently
 * dropped from the map, because at that point the value actually observed at any one read site can
 * no longer be determined just by looking at the field's declaration; it depends on control flow
 * this scanner deliberately does not model. Instance fields ({@code iget}/{@code iput}), array
 * elements, and anything else computed are never tracked -- only single-assignment static fields
 * are provably constant from local, non-dataflow inspection alone.
 */
public final class LoadLibraryBytecodeScanner {

	private LoadLibraryBytecodeScanner() {
	}

	/** Every {@code System.loadLibrary}/{@code load} call site in the whole input, found by
	 * reading raw dex instructions -- no class needs to have been opened/decompiled first. */
	public static List<LoadLibraryCall> scanAll(RootNode root) {
		List<LoadLibraryCall> out = new ArrayList<>();
		for (ClassNode cls : root.getClasses()) {
			scanClass(cls, out);
		}
		return out;
	}

	/** Identifies a static field the way {@link IFieldRef} does -- declaring class, name, and
	 * type together -- so a field literal collected for one class can never be looked up as if it
	 * belonged to another, and two identically-named fields of different types don't collide. */
	private record FieldKey(String declClass, String name, String type) {
		static FieldKey of(IFieldRef ref) {
			return new FieldKey(ref.getParentClassType(), ref.getName(), ref.getType());
		}
	}

	private static void scanClass(ClassNode cls, List<LoadLibraryCall> out) {
		// Pass 1: collect every static field that has exactly one const-string assignment anywhere
		// in the class. This must finish before pass 2 starts -- the assignment can textually come
		// either before or after the load-call site that reads the field back (it is usually first,
		// in the same <clinit>, but nothing guarantees that in general).
		Map<FieldKey, String> fieldLiterals = new HashMap<>();
		Set<FieldKey> poisonedFields = new HashSet<>();
		for (MethodNode mth : cls.getMethods()) {
			collectFieldLiterals(mth, fieldLiterals, poisonedFields);
		}
		// Pass 2: resolve call sites, now treating a known-single-assignment field read as if it
		// were a fresh const-string for the existing one-instruction lookahead.
		for (MethodNode mth : cls.getMethods()) {
			scanMethod(mth, fieldLiterals, out);
		}
	}

	/** Walks one method looking only for {@code const-string vX; sput vX, F} pairs, recording F's
	 * literal in {@code fieldLiterals} -- or, if F is ever assigned more than once anywhere in the
	 * class (even to the same literal twice) or ever assigned from anything other than a plain
	 * const-string, moving F into {@code poisonedFields} and keeping it out of the literal map for
	 * good. Both sets are shared across every method of the class, since the two assignments that
	 * poison a field can live in different methods. */
	private static void collectFieldLiterals(MethodNode mth, Map<FieldKey, String> fieldLiterals,
			Set<FieldKey> poisonedFields) {
		if (mth.isNoCode()) {
			return;
		}
		ICodeReader codeReader = mth.getCodeReader();
		if (codeReader == null) {
			return;
		}
		ICodeReader reader = codeReader.copy(); // see scanMethod's javadoc note on why: never read
													// the MethodNode's own stored reader concurrently
													// with jadx's lazy decompile.
		PendingConst pending = new PendingConst();
		reader.visitInstructions(insn -> visitForFieldLiterals(insn, pending, fieldLiterals, poisonedFields));
	}

	private static void visitForFieldLiterals(InsnData insn, PendingConst pending,
			Map<FieldKey, String> fieldLiterals, Set<FieldKey> poisonedFields) {
		Opcode op = insn.getOpcode();
		if (op == Opcode.CONST_STRING) {
			insn.decode();
			pending.reg = insn.getReg(0);
			pending.literal = insn.getIndexAsString();
			return; // pending stays live for exactly the next instruction visited below
		}
		if (op == Opcode.SPUT && insn.getIndexType() == InsnIndexType.FIELD_REF) {
			insn.decode();
			FieldKey key = FieldKey.of(insn.getIndexAsField());
			boolean isLiteralAssignment = insn.getRegsCount() == 1 && insn.getReg(0) == pending.reg;
			recordFieldAssignment(key, isLiteralAssignment ? pending.literal : null, fieldLiterals, poisonedFields);
			pending.reg = -1;
			pending.literal = null;
			return;
		}
		pending.reg = -1;
		pending.literal = null;
	}

	/** One sighting of a static field being written. {@code literalOrNull} is the const-string
	 * value when this specific assignment was a direct {@code const-string; sput} pair, or {@code
	 * null} when it was assigned from anything else (computed, concatenated, another field/method
	 * result). Either a null literal here, or a second sighting of a field already in {@code
	 * fieldLiterals}, proves the field's value at some read site can't be pinned to one literal
	 * just by looking at its declaration -- so it's poisoned rather than guessed. */
	private static void recordFieldAssignment(FieldKey key, String literalOrNull,
			Map<FieldKey, String> fieldLiterals, Set<FieldKey> poisonedFields) {
		if (poisonedFields.contains(key)) {
			return; // already known unsafe; no further sighting changes that
		}
		if (literalOrNull == null || fieldLiterals.containsKey(key)) {
			poisonedFields.add(key);
			fieldLiterals.remove(key);
			return;
		}
		fieldLiterals.put(key, literalOrNull);
	}

	private static void scanMethod(MethodNode mth, Map<FieldKey, String> fieldLiterals, List<LoadLibraryCall> out) {
		if (mth.isNoCode()) {
			return;
		}
		ICodeReader codeReader = mth.getCodeReader();
		if (codeReader == null) {
			return;
		}
		MethodInfo mi = mth.getMethodInfo();
		String classBinaryName = mi.getDeclClass().makeRawFullName();
		String methodName = mi.getName();

		// Operate on a fresh copy, never the MethodNode's own stored reader: DexCodeReader tracks
		// a mutable read position, and jadx's own lazy decompile (mth.load(), triggered the moment
		// the user opens this method's class in the GUI) can start reading that SAME stored
		// instance concurrently with this scan. MethodNode itself takes this exact precaution --
		// its constructor stores codeReader.copy() rather than the IMethodData's original -- so
		// mirroring that here is what keeps this scan safe to run while the user is browsing.
		ICodeReader reader = codeReader.copy();
		PendingConst pending = new PendingConst();
		reader.visitInstructions(insn -> visit(insn, pending, fieldLiterals, classBinaryName, methodName, mth, out));
	}

	/** The most recent {@code const-string} (or, per the field-resolution pass, its stand-in from a
	 * single-assignment static field read), valid for exactly one more instruction -- see the class
	 * javadoc on why tracking doesn't reach any further than that. */
	private static final class PendingConst {
		int reg = -1;
		String literal;
	}

	private static void visit(InsnData insn, PendingConst pending, Map<FieldKey, String> fieldLiterals,
			String classBinaryName, String methodName, MethodNode mth, List<LoadLibraryCall> out) {
		Opcode op = insn.getOpcode();
		if (op == Opcode.CONST_STRING) {
			insn.decode();
			pending.reg = insn.getReg(0);
			pending.literal = insn.getIndexAsString();
			return; // pending stays live for exactly the next instruction visited below
		}
		if (op == Opcode.SGET && insn.getIndexType() == InsnIndexType.FIELD_REF) {
			insn.decode();
			String literal = insn.getRegsCount() == 1
					? fieldLiterals.get(FieldKey.of(insn.getIndexAsField()))
					: null;
			if (literal != null) {
				pending.reg = insn.getReg(0);
				pending.literal = literal;
			} else {
				pending.reg = -1;
				pending.literal = null;
			}
			return; // same one-instruction-lookahead contract as the const-string case above
		}
		if (op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE) {
			insn.decode();
			if (insn.getIndexType() == InsnIndexType.METHOD_REF) {
				Kind kind = kindOf(insn.getIndexAsMethod());
				if (kind != null) {
					String rawArg = insn.getRegsCount() == 1 && insn.getReg(0) == pending.reg
							? pending.literal
							: null;
					out.add(new LoadLibraryCall(kind, rawArg, classBinaryName, methodName, mth));
				}
			}
		}
		pending.reg = -1;
		pending.literal = null;
	}

	/** {@code System.loadLibrary(String)} / {@code System.load(String)} by raw type descriptor --
	 * mirrors {@link LoadLibraryDetector}'s IR-level check exactly, so an app-defined method named
	 * "load" is never mistaken for this at either detection layer. */
	private static Kind kindOf(IMethodRef ref) {
		if (ref == null) {
			return null;
		}
		ref.load(); // IMethodRef is a lazy handle into the method-ref pool -- name/class/args are
					// null until this runs; idempotent, so re-loading an already-loaded ref is a no-op
		if (!"Ljava/lang/System;".equals(ref.getParentClassType())) {
			return null;
		}
		List<String> args = ref.getArgTypes();
		if (args == null || args.size() != 1 || !"Ljava/lang/String;".equals(args.get(0))) {
			return null;
		}
		String name = ref.getName();
		if ("loadLibrary".equals(name)) {
			return Kind.LOAD_LIBRARY;
		}
		if ("load".equals(name)) {
			return Kind.LOAD;
		}
		return null;
	}
}
