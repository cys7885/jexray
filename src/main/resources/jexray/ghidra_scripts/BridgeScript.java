// Ghidra headless worker script for the jexray bridge.
// Invoked as: -postScript BridgeScript.java <op> <arg> <outFile>
//   op = decompile | disassemble | search
//   arg = function name (decompile/disassemble) or query substring (search)
//   outFile = absolute path the server reads back
//   OR
// Invoked as: -postScript BridgeScript.java dumpall <cacheFile> <progressFile>
//   Decompiles + disassembles EVERY function once, collects its callers (cross references), and
//   writes a single JSON cache to <cacheFile> (tagged with "formatVersion" -- see
//   CACHE_FORMAT_VERSION -- so a reader can tell a cache that predates caller collection from one
//   that genuinely found none) while streaming {"completed":N,"total":T} into <progressFile>.
//
// For decompile/disassemble/search the output file format is: first line is the
// intended HTTP status code, the remaining bytes are the JSON response body.

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class BridgeScript extends GhidraScript {

    // Bumped whenever dumpAll's JSON shape changes in a way a reader must know about before
    // trusting a field's absence as meaningful. Introduced at 2 (not 1) because every cache
    // written before this field existed at all is, by definition, version < 2 -- there was never
    // an explicit "1". EmbeddedGhidraBridge.CURRENT_CACHE_FORMAT_VERSION on the server side must
    // be kept equal to this: the two live in separate compilation units (this file is compiled by
    // Ghidra at runtime from a bundled resource, not by Maven) with no shared constant possible.
    /**
     * Upper bound on dump passes. Each pass picks up functions the previous one caused Ghidra to
     * define; the count converges quickly, and the bound only stops a pathological program from
     * looping forever.
     */
    private static final int MAX_DUMP_ROUNDS = 10;

    private static final int CACHE_FORMAT_VERSION = 2;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("BridgeScript: expected 3 args, got " + args.length);
            return;
        }
        String op = args[0];
        String arg = args[1];
        String outFile = args[2];

        // dumpall has its own file protocol (writes cache + progress directly),
        // so handle it before the status/body output convention below.
        if ("dumpall".equals(op)) {
            dumpAll(arg, outFile);
            return;
        }

        int status;
        String body;
        try {
            switch (op) {
                case "decompile":
                    Object[] d = decompile(arg);
                    status = (Integer) d[0];
                    body = (String) d[1];
                    break;
                case "disassemble":
                    Object[] a = disassemble(arg);
                    status = (Integer) a[0];
                    body = (String) a[1];
                    break;
                case "search":
                    status = 200;
                    body = search(arg);
                    break;
                default:
                    status = 400;
                    body = errorJson("unknown op: " + op);
            }
        } catch (Exception e) {
            status = 500;
            body = errorJson("script error: " + e.getMessage());
        }

        try (PrintWriter pw = new PrintWriter(outFile, "UTF-8")) {
            pw.println(status);
            pw.print(body);
        }
    }

    /**
     * A PLT stub or GOT-level thunk: real code, but only a jump into the function that carries
     * the same name. Listing these alongside their targets makes every exported symbol appear
     * twice (and every import twice over, since it gets both kinds), so they are filtered out of
     * the function list and never used as a lookup result. Calls that land on them are still
     * attributed to the function they forward to -- see {@link #callersJson}.
     */
    private boolean isForwardingStub(Function f) {
        return f.isThunk() || f.isExternal();
    }

    private Function findFunction(String name) {
        FunctionManager fm = currentProgram.getFunctionManager();
        // exact match first
        for (Function f : fm.getFunctions(true)) {
            if (!isForwardingStub(f) && f.getName().equals(name)) {
                return f;
            }
        }
        // tolerate a single leading underscore difference (Mach-O vs ELF symbol
        // naming): a request for "Java_..." should still find "_Java_..." and
        // vice-versa. Harmless for ELF Android .so where names match exactly.
        for (Function f : fm.getFunctions(true)) {
            if (isForwardingStub(f)) {
                continue;
            }
            String fn = f.getName();
            if (fn.equals("_" + name) || name.equals("_" + fn)) {
                return f;
            }
        }
        return null;
    }

    /**
     * Response for a name {@link #findFunction} could not resolve. If the only thing carrying that
     * name is a forwarding stub, the symbol is imported from another library (libc, liblog, ...)
     * rather than missing, and the UI should say so -- 410, not 404.
     */
    private Object[] unresolved(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (isForwardingStub(f) && f.getName().equals(name)) {
                return new Object[]{410, errorJson("external symbol: " + name)};
            }
        }
        return new Object[]{404, errorJson("function not found: " + name)};
    }

    private Object[] decompile(String name) {
        Function func = findFunction(name);
        if (func == null) {
            return unresolved(name);
        }
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(currentProgram);
            DecompileResults res = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
            String c;
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c = res.getDecompiledFunction().getC();
            } else {
                String em = (res != null) ? res.getErrorMessage() : "no result";
                return new Object[]{500, errorJson("decompilation failed: " + em)};
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"pseudocode\":").append(jsonString(c)).append(',');
            sb.append("\"address\":").append(jsonString(addr(func.getEntryPoint())));
            sb.append('}');
            return new Object[]{200, sb.toString()};
        } finally {
            decomp.dispose();
        }
    }

    private Object[] disassemble(String name) {
        Function func = findFunction(name);
        if (func == null) {
            return unresolved(name);
        }
        String text = disassembleBody(func);
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"disassembly\":").append(jsonString(text)).append(',');
        sb.append("\"address\":").append(jsonString(addr(func.getEntryPoint())));
        sb.append('}');
        return new Object[]{200, sb.toString()};
    }

    private String disassembleBody(Function func) {
        Listing listing = currentProgram.getListing();
        Address start = func.getEntryPoint();
        Address end = func.getBody().getMaxAddress();
        StringBuilder text = new StringBuilder();
        InstructionIterator it = listing.getInstructions(start, true);
        while (it.hasNext()) {
            Instruction instr = it.next();
            if (instr.getAddress().compareTo(end) > 0) {
                break;
            }
            text.append(addr(instr.getAddress()))
                .append(": ")
                .append(instr.toString())
                .append('\n');
        }
        return text.toString();
    }

    // One-shot: decompile + disassemble every function, write a single JSON cache
    // the server serves all later queries from. Streams progress as it goes.
    /**
     * Functions not yet dumped, by entry point. Forwarding stubs are excluded here as everywhere
     * else -- they are listed separately, and are not code the user opens.
     */
    private List<Function> pendingFunctions(FunctionManager fm, Set<String> done) {
        List<Function> out = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (!isForwardingStub(f) && !done.contains(addr(f.getEntryPoint()))) {
                out.add(f);
            }
        }
        return out;
    }

    private void dumpAll(String cacheFile, String progressFile) throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<String> done = new HashSet<>();
        List<Function> pending = pendingFunctions(fm, done);
        int total = pending.size();
        writeProgress(progressFile, 0, total);

        DecompInterface decomp = new DecompInterface();
        StringBuilder json = new StringBuilder();
        json.append("{\"functions\":[");
        int i = 0;
        boolean first = true;
        List<String[]> dumped = new ArrayList<>();
        String regNativesJson = "[]";
        String earlyRegNatives = "[]";
        try {
            decomp.openProgram(currentProgram);
            // Read the registration table first: it can define functions Ghidra never found, and
            // they must exist before the walk below decides what there is to dump.
            earlyRegNatives = parseRegisterNatives(decomp);
            pending = pendingFunctions(fm, done);
            total = pending.size();
            writeProgress(progressFile, 0, total);
            // Decompiling can define new functions -- Ghidra creates one at a call target it had
            // not recognised as code yet. Those appear after the pass that caused them, so a single
            // walk of the function list misses them, and the pseudocode still names them: the user
            // clicks a call and the cache has no such function.
            //
            // So walk repeatedly, each round taking only what has not been dumped, until a round
            // turns up nothing new. Rounds are bounded in case a program keeps producing functions.
            int round = 0;
            for (; round < MAX_DUMP_ROUNDS && !pending.isEmpty(); round++) {
                for (Function stale : pending) {
                    // Re-fetch by address: analysis during an earlier decompile can delete or
                    // replace a function, leaving the snapshot holding something no longer in the
                    // program. Asking again is cheap and keeps a vanished entry from throwing.
                    Address entry = stale.getEntryPoint();
                    done.add(addr(entry));
                    Function func = fm.getFunctionAt(entry);
                    if (func == null || isForwardingStub(func)) {
                        continue;
                    }
                    String pseudocode = "";
                    try {
                        DecompileResults res = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                            pseudocode = res.getDecompiledFunction().getC();
                        }
                    } catch (Exception e) {
                        pseudocode = "// decompilation error: " + e.getMessage();
                    }
                    dumped.add(new String[] {
                        func.getName(), addr(entry), pseudocode, disassembleBody(func) });
                    i++;
                    if (i % 5 == 0) {
                        writeProgress(progressFile, i, total);
                    }
                }
                pending = pendingFunctions(fm, done);
                total = i + pending.size();
                writeProgress(progressFile, i, total);
            }
            if (!pending.isEmpty()) {
                // Saying nothing here would repeat the very fault this loop exists to fix: a
                // function the cache cannot answer for, with no record of why.
                println("BridgeScript: stopped after " + MAX_DUMP_ROUNDS + " passes with "
                    + pending.size() + " function(s) still undumped");
            }

            // Callers are collected only now, once the set of functions has settled. Doing it as
            // each function was dumped would have recorded the callers known at that moment, and a
            // later pass can add code that calls something dumped earlier -- leaving the earlier
            // entry short of callers that exist by the time anyone reads it.
            for (String[] e : dumped) {
                Function func = fm.getFunctionAt(currentProgram.getAddressFactory()
                    .getAddress(e[1]));
                if (!first) {
                    json.append(',');
                }
                first = false;
                json.append('{')
                    .append("\"name\":").append(jsonString(e[0])).append(',')
                    .append("\"address\":").append(jsonString(e[1])).append(',')
                    .append("\"pseudocode\":").append(jsonString(e[2])).append(',')
                    .append("\"disassembly\":").append(jsonString(e[3])).append(',')
                    .append("\"callers\":").append(func == null ? "[]" : callersJson(func))
                    .append('}');
            }
            writeProgress(progressFile, i, total);
            regNativesJson = earlyRegNatives;
        } finally {
            decomp.dispose();
        }
        // Names that exist here ONLY as a forwarding stub: imports from libc, liblog and friends.
        //
        // An exported local function also has a PLT stub, so a name is only external when nothing
        // emitted above carries it -- otherwise a function defined right here would be reported as
        // an import of itself. Keyed by name so an import contributes one entry, not the two it
        // actually has (a PLT stub plus a GOT-level thunk).
        Set<String> listed = new HashSet<>();
        for (Function f : fm.getFunctions(true)) {
            if (!isForwardingStub(f)) {
                listed.add(f.getName());
            }
        }
        Map<String, Function> externalByName = new LinkedHashMap<>();
        for (Function f : fm.getFunctions(true)) {
            if (isForwardingStub(f) && !listed.contains(f.getName())) {
                externalByName.putIfAbsent(f.getName(), f);
            }
        }

        // Imports are listed so the browser answers "what does this library depend on", but they
        // carry no body -- the server serves them straight from "externals" and never reads these
        // empty fields. Emitted into the same array so the client needs no second code path.
        for (Map.Entry<String, Function> e : externalByName.entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('{')
                .append("\"name\":").append(jsonString(e.getKey())).append(',')
                .append("\"address\":").append(jsonString(addr(e.getValue().getEntryPoint()))).append(',')
                .append("\"pseudocode\":").append(jsonString("")).append(',')
                .append("\"disassembly\":").append(jsonString("")).append(',')
                .append("\"callers\":[]")
                .append('}');
        }

        StringBuilder externals = new StringBuilder("[");
        boolean firstExt = true;
        for (String n : externalByName.keySet()) {
            if (!firstExt) {
                externals.append(',');
            }
            firstExt = false;
            externals.append(jsonString(n));
        }
        externals.append(']');

        json.append("],\"registerNatives\":").append(regNativesJson)
            .append(",\"externals\":").append(externals)
            .append(",\"formatVersion\":").append(CACHE_FORMAT_VERSION)
            .append('}');

        // Write atomically so the server only ever sees a complete cache: the
        // server treats cacheFile's existence as "load finished".
        File tmp = new File(cacheFile + ".tmp");
        try (PrintWriter pw = new PrintWriter(tmp, "UTF-8")) {
            pw.print(json.toString());
        }
        java.nio.file.Files.move(tmp.toPath(), new File(cacheFile).toPath(),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        writeProgress(progressFile, total, total);
        println("BridgeScript dumpall: wrote " + total + " functions to " + cacheFile);
    }

    // ---- Cross references (who calls this function) ----
    //
    // One entry per distinct CALLING FUNCTION, not per call instruction: a caller that invokes
    // the target from three call sites is one logical "caller" to a human reading a xref list, and
    // deduping this way keeps the cache bounded by the call graph's edge count rather than its raw
    // instruction count -- material at the scale the largest libraries reach. The
    // address kept is the first call site found for that caller; a user who wants every site can
    // still open the caller's own disassembly.
    private String callersJson(Function target) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Map<Function, Address> byCaller = new LinkedHashMap<>();
        // A call to an exported function normally lands on its PLT stub, not on its body, so
        // references to the entry point alone would only ever find that stub. Ghidra models the
        // stub as a thunk, so ask for every thunk forwarding here -- recursively, because an
        // imported symbol gets a PLT stub *and* a GOT-level thunk -- and treat calls to any of
        // them as calls to this function.
        List<Address> entryPoints = new ArrayList<>();
        entryPoints.add(target.getEntryPoint());
        Address[] thunkAddrs = target.getFunctionThunkAddresses(true);
        if (thunkAddrs != null) {
            for (Address t : thunkAddrs) {
                entryPoints.add(t);
            }
        }
        for (Address entryPoint : entryPoints) {
            ReferenceIterator refs = refMgr.getReferencesTo(entryPoint);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (!ref.getReferenceType().isCall()) {
                    continue; // data references (e.g. a function-pointer table) are not "calls"
                }
                Address from = ref.getFromAddress();
                Function caller = getFunctionContaining(from);
                if (caller == null) {
                    continue; // call site not inside any defined function -- nothing to navigate to
                }
                if (caller.isThunk()) {
                    continue; // a stub forwarding to us is not a caller the user can navigate to
                }
                byCaller.putIfAbsent(caller, from);
            }
        }
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (Map.Entry<Function, Address> e : byCaller.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append('{')
               .append("\"name\":").append(jsonString(e.getKey().getName())).append(',')
               .append("\"address\":").append(jsonString(addr(e.getValue())))
               .append('}');
        }
        out.append(']');
        return out.toString();
    }

    // ---- RegisterNatives (dynamic JNI registration) ----
    //
    // If JNI_OnLoad exists, find its call to JNIEnv->RegisterNatives (slot 215 of the JNI
    // function table = offset 215*pointerSize), read the JNINativeMethod[] array it passes
    // ({name, signature, fnPtr} triples), and emit [{name, signature, symbol, address}] so a
    // native method registered under an obscure/local function can still be resolved.
    private String parseRegisterNatives(DecompInterface decomp) {
        int ptrSize = currentProgram.getDefaultPointerSize();
        // Collect entries keyed by name+symbol so the two detection paths below can't emit a
        // duplicate for the same registration (insertion-ordered for stable output).
        Map<String, String> entries = new LinkedHashMap<>();

        // Path 1 (confirmed call): decompile JNI_OnLoad and the functions it transitively calls,
        // and read the array handed to the RegisterNatives slot call. Apps often delegate the call
        // to a helper (registerAll(), init(), ...), so we must walk callees, not just JNI_OnLoad.
        parseRegisterNativesViaCallGraph(decomp, ptrSize, entries);

        // Path 2 (data-driven): scan initialized data for JNINativeMethod-shaped triples
        // {name*, signature*, fnPtr}. Path 1 assumes the registration call can be recovered and
        // reached from JNI_OnLoad; nothing in the JNI contract requires either, so this path covers
        // the inputs where that assumption does not hold, without depending on the call at all.
        scanJniMethodTables(ptrSize, entries);

        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (String entry : entries.values()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append(entry);
        }
        out.append(']');
        return out.toString();
    }

    private void parseRegisterNativesViaCallGraph(DecompInterface decomp, int ptrSize, Map<String, String> entries) {
        Function onLoad = findFunction("JNI_OnLoad");
        if (onLoad == null) {
            return;
        }
        long expectedOffset = 215L * ptrSize; // 0x6b8 (64-bit) / 0x35c (32-bit)
        java.util.Set<Function> visited = new java.util.HashSet<>();
        java.util.ArrayDeque<Function> queue = new java.util.ArrayDeque<>();
        queue.add(onLoad);
        visited.add(onLoad);
        int scanned = 0;
        final int MAX_FUNCS = 64; // bound total decompilation work so a huge OnLoad closure can't stall load
        while (!queue.isEmpty() && scanned < MAX_FUNCS) {
            Function fn = queue.poll();
            scanned++;
            try {
                DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                if (res == null || !res.decompileCompleted() || res.getHighFunction() == null) {
                    continue;
                }
                HighFunction hf = res.getHighFunction();
                Iterator<PcodeOpAST> ops = hf.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    if (op.getOpcode() != PcodeOp.CALLIND || op.getNumInputs() < 5) {
                        continue;
                    }
                    if (callTargetOffset(op.getInput(0)) != expectedOffset) {
                        continue;
                    }
                    // args: input0=target, 1=env, 2=clazz, 3=methods array, 4=count
                    Varnode methodsVn = op.getInput(3);
                    Varnode countVn = op.getInput(4);
                    if (methodsVn == null || countVn == null || !countVn.isConstant()) {
                        continue;
                    }
                    long methodsAddr = resolveConstAddr(methodsVn);
                    long count = countVn.getOffset();
                    if (methodsAddr == 0 || count <= 0 || count > 4096) {
                        continue;
                    }
                    readMethodsArray(methodsAddr, (int) count, ptrSize, entries);
                }
                // enqueue this function's direct callees for the next BFS level
                for (Function callee : fn.getCalledFunctions(new ConsoleTaskMonitor())) {
                    if (callee != null && !callee.isExternal() && !callee.isThunk() && visited.add(callee)) {
                        queue.add(callee);
                    }
                }
            } catch (Exception e) {
                println("BridgeScript: RegisterNatives parse error in " + fn.getName() + ": " + e.getMessage());
            }
        }
    }

    private void readMethodsArray(long arrayAddr, int count, int ptrSize, Map<String, String> entries) {
        Memory mem = currentProgram.getMemory();
        ghidra.program.model.address.AddressSpace space =
            currentProgram.getAddressFactory().getDefaultAddressSpace();
        int stride = 3 * ptrSize;
        for (int idx = 0; idx < count; idx++) {
            try {
                long base = arrayAddr + (long) idx * stride;
                long namePtr = readPointer(mem, space.getAddress(base), ptrSize);
                long sigPtr = readPointer(mem, space.getAddress(base + ptrSize), ptrSize);
                long fnPtr = readPointer(mem, space.getAddress(base + 2L * ptrSize), ptrSize);
                String name = readCString(mem, space.getAddress(namePtr));
                if (name == null || name.isEmpty()) {
                    continue;
                }
                String sig = readCString(mem, space.getAddress(sigPtr));
                Address fnAddr = space.getAddress(fnPtr);
                emitRegNative(entries, name, sig, symbolAt(fnAddr), fnAddr);
            } catch (Exception e) {
                // skip a bad entry, keep parsing the rest
            }
        }
    }

    /**
     * Find JNINativeMethod arrays by their shape in initialized data instead of by recovering the
     * RegisterNatives call. Each entry is three pointers {@code {const char* name, const char*
     * signature, void* fnPtr}}; the signature string (starts with '(', JNI grammar) is a strong
     * enough discriminator that three consecutive pointers passing it are almost never a
     * coincidence. Bounded by a slot budget so a pathological binary can't stall the load.
     */
    private void scanJniMethodTables(int ptrSize, Map<String, String> entries) {
        Memory mem = currentProgram.getMemory();
        ghidra.program.model.address.AddressSpace space =
            currentProgram.getAddressFactory().getDefaultAddressSpace();
        long budget = 4_000_000L; // cap total slots inspected across all data blocks
        for (ghidra.program.model.mem.MemoryBlock block : mem.getBlocks()) {
            // the table lives in initialized data (.data / .data.rel.ro), never code or .bss
            if (block == null || !block.isInitialized() || block.isExecute()) {
                continue;
            }
            Address start = block.getStart();
            long size = block.getSize();
            for (long off = 0; off + 3L * ptrSize <= size; off += ptrSize) {
                if (--budget <= 0) {
                    return;
                }
                try {
                    Address base = start.add(off);
                    long sigPtr = readPointer(mem, base.add(ptrSize), ptrSize);
                    if (sigPtr == 0) {
                        continue;
                    }
                    // cheap pre-filter: a JNI signature string starts with '('
                    Address sigAddr = space.getAddress(sigPtr);
                    if ((mem.getByte(sigAddr) & 0xFF) != '(') {
                        continue;
                    }
                    String sig = readCString(mem, sigAddr);
                    if (!isJniSignature(sig)) {
                        continue;
                    }
                    long namePtr = readPointer(mem, base, ptrSize);
                    if (namePtr == 0) {
                        continue;
                    }
                    String name = readCString(mem, space.getAddress(namePtr));
                    if (!isPlausibleMethodName(name)) {
                        continue;
                    }
                    long fnPtr = readPointer(mem, base.add(2L * ptrSize), ptrSize);
                    if (fnPtr == 0) {
                        continue;
                    }
                    Address fnAddr = space.getAddress(fnPtr);
                    if (!pointsToCode(mem, fnAddr)) {
                        continue;
                    }
                    emitRegNative(entries, name, sig, symbolAt(fnAddr), fnAddr);
                } catch (Exception e) {
                    // not a valid triple at this offset; keep scanning
                }
            }
        }
    }

    private void emitRegNative(Map<String, String> entries, String name, String sig, String symbol, Address fnAddr) {
        String key = name + '\u0001' + symbol;
        if (entries.containsKey(key)) {
            return;
        }
        entries.put(key, "{"
            + "\"name\":" + jsonString(name) + ","
            + "\"signature\":" + jsonString(sig == null ? "" : sig) + ","
            + "\"symbol\":" + jsonString(symbol) + ","
            + "\"address\":" + jsonString(addr(fnAddr))
            + "}");
    }

    private boolean pointsToCode(Memory mem, Address a) {
        ghidra.program.model.mem.MemoryBlock b = mem.getBlock(a);
        if (b != null && b.isExecute()) {
            return true;
        }
        return currentProgram.getFunctionManager().getFunctionContaining(a) != null;
    }

    // A JNI type signature uses only these characters and always opens with '(' ... ')'.
    private boolean isJniSignature(String s) {
        if (s == null || s.length() < 3 || s.charAt(0) != '(' || s.indexOf(')') < 0) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = c == '(' || c == ')' || c == '[' || c == ';' || c == '/' || c == '$' || c == '_'
                || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    // A Java method name (the RegisterNatives "name" field) is a plain identifier.
    private boolean isPlausibleMethodName(String s) {
        if (s == null || s.isEmpty() || s.length() > 200) {
            return false;
        }
        char c0 = s.charAt(0);
        if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_' || c0 == '$')) {
            return false;
        }
        for (int i = 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '$')) {
                return false;
            }
        }
        return true;
    }

    // Trace a CALLIND target back through LOAD/INT_ADD to the constant table offset, i.e.
    // the "0x6b8" in (**(code**)(*env + 0x6b8))(...). Returns -1 if the pattern isn't matched.
    private long callTargetOffset(Varnode target) {
        Varnode t = target;
        PcodeOp def = (t == null) ? null : t.getDef();
        int guard = 0;
        while (def != null && (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST) && guard++ < 8) {
            t = def.getInput(0);
            def = (t == null) ? null : t.getDef();
        }
        if (def == null || def.getOpcode() != PcodeOp.LOAD) {
            return -1;
        }
        Varnode ptr = def.getInput(1);
        PcodeOp pdef = (ptr == null) ? null : ptr.getDef();
        guard = 0;
        while (pdef != null && (pdef.getOpcode() == PcodeOp.COPY || pdef.getOpcode() == PcodeOp.CAST) && guard++ < 8) {
            ptr = pdef.getInput(0);
            pdef = (ptr == null) ? null : ptr.getDef();
        }
        if (pdef != null && pdef.getOpcode() == PcodeOp.INT_ADD) {
            Varnode a = pdef.getInput(0);
            Varnode b = pdef.getInput(1);
            if (b != null && b.isConstant()) {
                return b.getOffset();
            }
            if (a != null && a.isConstant()) {
                return a.getOffset();
            }
        }
        return -1;
    }

    // Resolve a Varnode that ultimately holds a constant address (e.g. &methods_array),
    // tracing back through COPY/CAST/PTRSUB/INT_ADD. Returns 0 if not a static address.
    private long resolveConstAddr(Varnode v) {
        int guard = 0;
        while (v != null && guard++ < 16) {
            if (v.isConstant() || v.isAddress()) {
                return v.getOffset();
            }
            PcodeOp def = v.getDef();
            if (def == null) {
                return 0;
            }
            int op = def.getOpcode();
            if (op == PcodeOp.COPY || op == PcodeOp.CAST) {
                v = def.getInput(0);
            } else if (op == PcodeOp.PTRSUB || op == PcodeOp.INT_ADD || op == PcodeOp.PTRADD) {
                Varnode a = def.getInput(0);
                Varnode b = def.getInput(1);
                boolean aConst = a != null && (a.isConstant() || a.isAddress());
                boolean bConst = b != null && (b.isConstant() || b.isAddress());
                if (aConst && bConst) {
                    return a.getOffset() + b.getOffset();
                }
                if (a != null && !aConst) {
                    v = a;
                } else if (b != null && !bConst) {
                    v = b;
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        }
        return 0;
    }

    private long readPointer(Memory mem, Address a, int ptrSize) throws Exception {
        if (ptrSize == 8) {
            return mem.getLong(a);
        }
        return mem.getInt(a) & 0xFFFFFFFFL;
    }

    private String readCString(Memory mem, Address a) {
        if (a == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        try {
            for (int k = 0; k < 512; k++) {
                byte b = mem.getByte(a.add(k));
                if (b == 0) {
                    break;
                }
                sb.append((char) (b & 0xFF));
            }
        } catch (Exception e) {
            return sb.length() > 0 ? sb.toString() : null;
        }
        return sb.toString();
    }

    /**
     * The function a registration entry points at, defining one if Ghidra has not.
     *
     * <p>An entry in the table proves its address is an entry point, but Ghidra may never have made
     * a function there: the only thing referencing the address is a pointer inside a data table, so
     * flow analysis never reaches it. Naming it {@code FUN_<address>} without defining it produced
     * something that looked exactly like a name Ghidra had assigned while belonging to no function
     * at all -- offered by the browser, and unresolvable by every lookup.
     */
    private String symbolAt(Address fnAddr) {
        Function f = getFunctionAt(fnAddr);
        if (f == null) {
            f = currentProgram.getFunctionManager().getFunctionContaining(fnAddr);
        }
        if (f == null) {
            try {
                f = createFunction(fnAddr, null);
            } catch (Exception e) {
                println("BridgeScript: could not define a function at a registration target: "
                    + e.getMessage());
            }
        }
        if (f != null) {
            return f.getName();
        }
        // Nothing could be made of the address. Still report the entry -- the table said something
        // is registered here -- and let the lookup fail loudly rather than hide the registration.
        return "FUN_" + fnAddr.toString();
    }

    private void writeProgress(String progressFile, int completed, int total) {
        try (PrintWriter pw = new PrintWriter(progressFile, "UTF-8")) {
            pw.print("{\"completed\":" + completed + ",\"total\":" + total + "}");
        } catch (Exception e) {
            // progress is best-effort; ignore failures
        }
    }

    private String search(String query) {
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"functions\":[");
        boolean first = true;
        for (Function f : fm.getFunctions(true)) {
            if (isForwardingStub(f)) {
                continue;
            }
            if (query == null || query.isEmpty() || f.getName().contains(query)) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"name\":").append(jsonString(f.getName()))
                  .append(",\"address\":").append(jsonString(addr(f.getEntryPoint())))
                  .append('}');
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String addr(Address a) {
        return "0x" + a.toString();
    }

    private static String errorJson(String msg) {
        return "{\"status\":\"error\",\"message\":" + jsonString(msg) + "}";
    }

    private static String jsonString(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
