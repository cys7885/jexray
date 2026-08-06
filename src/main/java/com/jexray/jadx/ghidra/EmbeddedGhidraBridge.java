package com.jexray.jadx.ghidra;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.jexray.jadx.util.Sha256;

/**
 * In-process headless Ghidra bridge, embedded in the JADX plugin so a single
 * jexray-jadx-plugin.jar provides the whole feature.
 *
 * <p>On {@code /so/load} it runs {@code analyzeHeadless} once to import + auto-analyze a
 * .so and decompile/disassemble every function into a JSON cache; subsequent
 * decompile/disassemble/search requests are served from that cache with no further Ghidra
 * invocation. Loading is asynchronous; progress is exposed via {@code GET /so/{soId}/status}.
 *
 * <p>Ported from the standalone {@code com.jexray.bridge.GhidraBridgeServer}. Differences:
 * home dir and Ghidra install dir are injected (not system properties), the HTTP port is
 * auto-selected (preferred port, else ephemeral), the worker script is extracted from a
 * bundled classpath resource, JSON parsing uses the plugin's shaded gson, and {@link #stop()}
 * cleanly shuts everything down on plugin unload.
 */
public class EmbeddedGhidraBridge {

    /**
     * Give up on a load only after this long with no sign of life -- no output from Ghidra and no
     * change to the progress file. There is deliberately no overall time limit: analysis time scales
     * with the binary, and a library with hundreds of thousands of functions can take hours, so any
     * fixed ceiling we picked would kill healthy work (which is the bug this replaces).
     *
     * <p><b>This value is a guess.</b> We have no measurement of how long Ghidra can legitimately go
     * quiet during auto-analysis, so it is set high enough to be safe rather than tight. Each load
     * logs the largest silence it actually observed; once that data accumulates this can be
     * tightened to something evidence-based.
     */
    private static final long STALL_TIMEOUT_MS = 10 * 60 * 1000L;

    /** How often to check liveness while waiting. */
    private static final long LIVENESS_POLL_MS = 2000;
    /** How much of the analyzeHeadless output to keep for explaining a failure. */
    private static final int LOG_TAIL_LINES = 40;
    private static final String SCRIPT_RESOURCE = "/jexray/ghidra_scripts/BridgeScript.java";

    /**
     * Must equal {@code BridgeScript.CACHE_FORMAT_VERSION}. A cache written before this field
     * existed at all (every cache produced before xref collection was added) has no
     * {@code "formatVersion"} key and parses as 0, which is always less than this constant --
     * that is precisely the signal used to tell "this cache's xrefs are unknown" apart from "this
     * cache checked and found none" (see {@link CacheData#xrefsKnown}). Bump this only in lockstep
     * with a bump to the script's constant; the two can't share a literal because the script is
     * compiled by Ghidra at runtime from a bundled resource, not by this build.
     */
    private static final int CURRENT_CACHE_FORMAT_VERSION = 2;

    private static final java.util.regex.Pattern SOID_PATTERN =
        java.util.regex.Pattern.compile("^[A-Za-z0-9._-]{1,128}$");

    private final File homeDir;
    private final File ghidraInstallDir;
    private final File analyzeHeadless;
    private final boolean windows;
    private final File scriptDir;
    private final File projectsDir;
    private final File ghidraProjectDir;
    private final String scriptName = "BridgeScript.java";
    private final int preferredPort;

    /**
     * Analyzing several libraries at once scales close to linearly, because each run is a separate
     * JVM doing its own CPU-bound analysis, so loads run concurrently rather than one at a time.
     * It stays bounded: each run is a full
     * Ghidra JVM, and while a small library costs well under a GB, a large one costs far more, so an
     * unbounded pool on an app with many libraries would exhaust memory.
     */
    private static final int MAX_CONCURRENT_LOADS = 3;

    /** The cap on how many analyzeHeadless runs may be in flight at once. */
    static int loadPoolSize() {
        int byCpu = Math.max(1, Runtime.getRuntime().availableProcessors() / 2);
        return Math.min(MAX_CONCURRENT_LOADS, byCpu);
    }

    /**
     * Guards only the very first load. Ghidra compiles our GhidraScript into an OSGi bundle under
     * its shared user directory the first time it runs; letting several cold runs race on that
     * shared compilation is the one place concurrency is genuinely unsafe.
     *
     * <p>The flag is set once the first load has been <i>attempted</i>, successfully or not, so a
     * cold start that fails does not re-serialize the next one. That trades a repeat of the race
     * (only in the case where the first run failed before compiling anything) against a failing
     * install serializing every subsequent load behind a lock that can never help it.
     */
    private final ReentrantLock coldStartLock = new ReentrantLock();
    private volatile boolean scriptBundleWarmed = false;

    /**
     * One lock per content hash, so concurrent loads that happen to resolve to the same hash
     * (two soIds naming identical bytes) serialize on that hash instead of racing on the same
     * Ghidra project name and cache/progress files. Loads of different hashes never contend --
     * unbounded growth here is bounded by how many distinct binaries this process has ever seen,
     * the same lifetime as {@link #caches} and {@link #soIdToHash}.
     */
    private final Map<String, ReentrantLock> hashLocks = new ConcurrentHashMap<>();

    /** Live analyzeHeadless processes, so {@link #stop()} can kill them instead of orphaning them. */
    private final java.util.Set<Process> liveProcesses = ConcurrentHashMap.newKeySet();

    /**
     * Backstop for host exits that never call {@link #stop()} (a killed or crashing jadx-gui).
     * It only destroys child processes -- no server teardown, no locking -- so it stays safe to run
     * during JVM shutdown, and it is deregistered by {@link #stop()} so a normal unload doesn't
     * leave the hook (and this bridge) reachable for the rest of the host's life.
     */
    private Thread shutdownHook;

    private final ExecutorService loadExecutor = Executors.newFixedThreadPool(loadPoolSize(), r -> {
        Thread t = new Thread(r, "jexray-bridge-load");
        t.setDaemon(true);
        return t;
    });
    private ExecutorService httpExecutor;
    private volatile ServerSocket serverSocket;
    private volatile boolean serving;
    private final SoDispatchHandler soDispatch = new SoDispatchHandler();
    private final CacheHandler cacheDispatch = new CacheHandler();
    private volatile int actualPort = -1;
    private volatile String detectedGhidraVersion;
    private volatile String versionWarning;

    // keyed by the client-supplied soId, so /so/{soId}/... requests and status polling keep
    // working unchanged
    private final Map<String, LoadState> states = new ConcurrentHashMap<>();
    // soId -> content hash of the .so it was last loaded from, computed once per /so/load (see
    // doLoad). The hash, not soId, is the real cache identity from here on.
    private final Map<String, String> soIdToHash = new ConcurrentHashMap<>();
    // keyed by content hash: two soIds (even across different loaded APKs) that happen to name
    // the same bytes share one entry here, on disk, and in the analysis work needed to produce it.
    private final Map<String, CacheData> caches = new ConcurrentHashMap<>();

    /**
     * @param homeDir          working dir holding {@code ghidra_scripts/} and {@code projects/}
     * @param ghidraInstallDir Ghidra install dir; null/blank falls back to {@code GHIDRA_INSTALL_DIR}
     *                         env then a homebrew default
     * @param preferredPort    port to try first; if taken, an ephemeral port is used
     */
    public EmbeddedGhidraBridge(File homeDir, String ghidraInstallDir, int preferredPort) {
        this.windows = isWindows(System.getProperty("os.name"));
        // Priority: explicit plugin option -> GHIDRA_INSTALL_DIR env -> best-effort auto-detect.
        // Never a hardcoded per-machine path: on another OS that path is just noise in the error.
        String dir = (ghidraInstallDir != null && !ghidraInstallDir.isBlank()) ? ghidraInstallDir.trim() : null;
        if (dir == null) {
            String env = System.getenv("GHIDRA_INSTALL_DIR");
            dir = (env != null && !env.isBlank()) ? env.trim() : autoDetectGhidraDir(windows);
        }
        this.homeDir = homeDir;
        this.ghidraInstallDir = new File(dir != null ? dir : "");
        this.analyzeHeadless = headlessLauncher(this.ghidraInstallDir, windows);
        this.scriptDir = new File(homeDir, "ghidra_scripts");
        this.projectsDir = new File(homeDir, "projects");
        // Ghidra's project LOCATION must not contain a path element starting with '.' (Ghidra
        // 12.1+ aborts headless with "Path element starting with '.' is not permitted"). Our home
        // is ~/.jexray, so the Ghidra project can't live under it -- put it under the OS temp dir
        // (never dot-prefixed). It's disposable: after the one dumpall run per load, every
        // decompile/disassemble/search is served from the on-disk cache, not the project. The cache
        // and progress files themselves stay under ~/.jexray (plain file paths Ghidra never checks).
        this.ghidraProjectDir = ghidraProjectRoot();
        this.scriptDir.mkdirs();
        this.projectsDir.mkdirs();
        this.ghidraProjectDir.mkdirs();
        this.preferredPort = preferredPort;
    }

    /** A Ghidra-project-safe scratch dir (no dot-prefixed path element), under the OS temp dir. */
    private static File ghidraProjectRoot() {
        String tmp = System.getProperty("java.io.tmpdir");
        File base = (tmp != null && !tmp.isBlank()) ? new File(tmp) : new File(".");
        return new File(base, "jexray-ghidra-projects");
    }

    static boolean isWindows(String osName) {
        return osName != null && osName.toLowerCase(Locale.ROOT).contains("win");
    }

    /**
     * The analyzeHeadless launcher inside a Ghidra install dir. Ghidra ships {@code
     * support/analyzeHeadless} (shell) on macOS/Linux and {@code support\analyzeHeadless.bat} on
     * Windows -- resolving the right one is what makes a user-supplied path work on either OS.
     */
    static File headlessLauncher(File ghidraInstallDir, boolean windows) {
        return new File(ghidraInstallDir, windows ? "support/analyzeHeadless.bat" : "support/analyzeHeadless");
    }

    /**
     * Best-effort scan of the usual install locations for a Ghidra whose launcher exists, so the
     * plugin works out of the box for common setups on any OS. Returns {@code null} if none found,
     * in which case the user simply sets the path in plugin options. Never throws.
     */
    static String autoDetectGhidraDir(boolean windows) {
        List<File> candidates = new ArrayList<>();
        String home = System.getProperty("user.home");
        if (windows) {
            collectGhidraDirs(candidates, "C:\\");
            collectGhidraDirs(candidates, System.getenv("ProgramFiles"));
            collectGhidraDirs(candidates, System.getenv("ProgramFiles(x86)"));
            collectGhidraDirs(candidates, System.getenv("LOCALAPPDATA"));
            collectGhidraDirs(candidates, home);
        } else {
            // Homebrew keeps versioned installs under Cellar/ghidra/<version>/libexec
            collectCellarLibexec(candidates, "/opt/homebrew/Cellar/ghidra");
            collectCellarLibexec(candidates, "/usr/local/Cellar/ghidra");
            collectGhidraDirs(candidates, "/opt");
            collectGhidraDirs(candidates, "/usr/local");
            collectGhidraDirs(candidates, "/usr/share");
            collectGhidraDirs(candidates, "/Applications");
            collectGhidraDirs(candidates, home);
            candidates.add(new File("/usr/share/ghidra"));
        }
        File picked = pickGhidraDir(candidates, windows);
        return picked == null ? null : picked.getAbsolutePath();
    }

    /**
     * First candidate whose analyzeHeadless launcher exists, preferring later-sorted (typically
     * higher-version) names. Pure and side-effect free so it can be unit-tested against a fake tree.
     */
    static File pickGhidraDir(List<File> candidates, boolean windows) {
        List<File> ordered = new ArrayList<>(candidates);
        // descending by path so "ghidra_12.0" is tried before "ghidra_11.3.2"
        ordered.sort((a, b) -> b.getPath().compareToIgnoreCase(a.getPath()));
        for (File dir : ordered) {
            if (dir != null && headlessLauncher(dir, windows).isFile()) {
                return dir;
            }
        }
        return null;
    }

    /** Add every child of {@code root} whose name starts with "ghidra" (and root itself). */
    private static void collectGhidraDirs(List<File> out, String root) {
        if (root == null || root.isBlank()) {
            return;
        }
        File base = new File(root);
        File[] children = base.listFiles();
        if (children != null) {
            for (File c : children) {
                if (c.isDirectory() && c.getName().toLowerCase(Locale.ROOT).startsWith("ghidra")) {
                    out.add(c);
                }
            }
        }
    }

    /** Add {@code <cellarGhidra>/<version>/libexec} for each installed Homebrew version. */
    private static void collectCellarLibexec(List<File> out, String cellarGhidra) {
        File base = new File(cellarGhidra);
        File[] versions = base.listFiles();
        if (versions != null) {
            for (File v : versions) {
                if (v.isDirectory()) {
                    out.add(new File(v, "libexec"));
                }
            }
        }
    }

    /** Start the HTTP server (fast; Ghidra only runs later on /so/load). Idempotent-ish. */
    public synchronized void start() throws IOException {
        if (serverSocket != null) {
            return;
        }
        extractBridgeScript();

        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        try {
            socket.bind(new InetSocketAddress(loopback, preferredPort));
        } catch (IOException bindFail) {
            // preferred port busy (e.g. an external bridge already running) -> ephemeral
            socket.bind(new InetSocketAddress(loopback, 0));
        }
        this.serverSocket = socket;
        this.actualPort = socket.getLocalPort();
        this.serving = true;
        this.httpExecutor = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "jexray-bridge-http");
            t.setDaemon(true);
            return t;
        });
        Thread acceptThread = new Thread(this::acceptLoop, "jexray-bridge-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();

        shutdownHook = new Thread(this::killLiveProcesses, "jexray-bridge-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        if (!analyzeHeadless.exists()) {
            System.err.println("[jexray-bridge] WARNING: "
                + (ghidraInstallDir.getPath().isEmpty()
                    ? "no Ghidra install directory configured/auto-detected"
                    : "analyzeHeadless not found at " + analyzeHeadless)
                + " (set 'Ghidra install directory' in plugin options or GHIDRA_INSTALL_DIR)");
        } else {
            this.detectedGhidraVersion = GhidraVersion.readVersion(ghidraInstallDir);
            this.versionWarning = GhidraVersion.supportWarning(detectedGhidraVersion);
            if (versionWarning != null) {
                System.err.println("[jexray-bridge] WARNING: " + versionWarning);
            } else {
                System.out.println("[jexray-bridge] Ghidra version: "
                    + (detectedGhidraVersion == null ? "unknown" : detectedGhidraVersion));
            }
        }
        System.out.println("[jexray-bridge] listening on " + getBaseUrl()
            + " (ghidra=" + ghidraInstallDir + ", home=" + projectsDir.getParentFile() + ")");
    }

    /** Detected Ghidra version string (e.g. "12.0"), or null if unknown/unreadable. */
    public String getGhidraVersion() {
        return detectedGhidraVersion;
    }

    /** A warning if the detected Ghidra version is outside the tested range, else null. */
    public String getVersionWarning() {
        return versionWarning;
    }

    /** Stop the server and release the port/threads (called from plugin unload). */
    public synchronized void stop() {
        serving = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // closed to interrupt accept(); nothing to recover
            }
            serverSocket = null;
        }
        loadExecutor.shutdownNow();
        killLiveProcesses();
        if (shutdownHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // already shutting down; the hook is running or has run
            }
            shutdownHook = null;
        }
        if (httpExecutor != null) {
            httpExecutor.shutdownNow();
            httpExecutor = null;
        }
        actualPort = -1;
    }

    /**
     * Kill every analyzeHeadless we started. Interrupting our own threads is not enough: each run is
     * a separate OS process that would otherwise keep analyzing after the host is gone, holding a
     * Ghidra JVM's worth of memory (0.5GB+ for a small library, several GB for a large one) for
     * minutes -- multiplied by the load pool size.
     */
    private void killLiveProcesses() {
        for (Process p : liveProcesses) {
            destroyTree(p);
        }
        liveProcesses.clear();
    }

    /**
     * Kill a launched analyzeHeadless and everything it spawned.
     *
     * <p>Ghidra's launcher is three processes deep and neither level uses {@code exec}:
     * {@code analyzeHeadless} (what {@link ProcessBuilder} gives us) runs {@code launch.sh}, which
     * in turn runs the java JVM that does all the work. Destroying only our own handle therefore
     * kills a shell and leaves the JVM running -- reparented to init, still holding the Ghidra
     * project lock, and still consuming GBs. Descendants are collected first, because once the
     * parent dies they are reparented and can no longer be reached through this handle.
     */
    private static void destroyTree(Process p) {
        if (p == null) {
            return;
        }
        try {
            for (ProcessHandle h : p.descendants().collect(java.util.stream.Collectors.toList())) {
                h.destroyForcibly();
            }
            p.destroyForcibly();
            // descendants() is a snapshot: anything the tree spawned between collecting and killing
            // (Ghidra starts helper processes of its own) would survive. Sweep once more for
            // stragglers -- still cheap, and the parent is already dead so the list is short.
            Thread.sleep(150);
            for (ProcessHandle h : p.descendants().collect(java.util.stream.Collectors.toList())) {
                h.destroyForcibly();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // best effort: shutting down regardless
        }
    }

    public boolean isRunning() {
        return serverSocket != null && actualPort > 0;
    }

    public int getPort() {
        return actualPort;
    }

    public String getBaseUrl() {
        return "http://127.0.0.1:" + actualPort;
    }

    // ---- Minimal HTTP/1.1 server over java.base sockets ----
    //
    // The plugin runs in-process but keeps a loopback HTTP contract so an external bridge can be
    // swapped in behind the same client. com.sun.net.httpserver would be simpler, but it lives in
    // the jdk.httpserver module, which the trimmed JRE some jadx-gui builds bundle does not ship --
    // so the server is hand-rolled on ServerSocket, which is always present in java.base.

    @FunctionalInterface
    private interface Handler {
        void handle(Exchange exchange) throws IOException;
    }

    /** One request/response over a single socket; the response is written by {@link #sendJson}. */
    private static final class Exchange {
        private final String method;
        private final URI uri;
        private final byte[] body;
        private final OutputStream out;
        private boolean responded;

        Exchange(String method, URI uri, byte[] body, OutputStream out) {
            this.method = method;
            this.uri = uri;
            this.body = body;
            this.out = out;
        }

        String getRequestMethod() {
            return method;
        }

        URI getRequestURI() {
            return uri;
        }

        InputStream getRequestBody() {
            return new ByteArrayInputStream(body);
        }
    }

    private void acceptLoop() {
        while (serving) {
            Socket client;
            try {
                client = serverSocket.accept();
            } catch (IOException e) {
                // serverSocket closed by stop(), or a transient accept error while shutting down
                if (serving) {
                    continue;
                }
                return;
            }
            httpExecutor.submit(() -> serveConnection(client));
        }
    }

    private void serveConnection(Socket client) {
        try (Socket s = client) {
            s.setSoTimeout(60_000);
            BufferedInputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                return;
            }
            String method = parts[0];
            String target = parts[1];

            int contentLength = 0;
            String header;
            while ((header = readLine(in)) != null && !header.isEmpty()) {
                int colon = header.indexOf(':');
                if (colon > 0 && header.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
                    try {
                        contentLength = Integer.parseInt(header.substring(colon + 1).trim());
                    } catch (NumberFormatException ignored) {
                        contentLength = 0;
                    }
                }
            }
            byte[] body = readBytes(in, contentLength);

            URI uri;
            try {
                uri = new URI(target);
            } catch (Exception badTarget) {
                writeResponse(out, 400, errorJson("bad request target"));
                return;
            }

            Exchange exchange = new Exchange(method, uri, body, out);
            try {
                route(exchange);
            } catch (IOException handlerErr) {
                if (!exchange.responded) {
                    sendJson(exchange, 500, errorJson("internal error: " + handlerErr.getMessage()));
                }
            }
            if (!exchange.responded) {
                sendJson(exchange, 404, errorJson("not found"));
            }
        } catch (IOException ignored) {
            // client went away mid-request; nothing to send
        }
    }

    private void route(Exchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if ("/health".equals(path)) {
            sendJson(exchange, 200, "{\"status\":\"ok\"}");
        } else if (path.startsWith("/so/")) {
            soDispatch.handle(exchange);
        } else if (path.startsWith("/cache/")) {
            cacheDispatch.handle(exchange);
        }
        // else: leave unresponded -> serveConnection sends 404
    }

    /** Read one CRLF- or LF-terminated line as ASCII; null at end of stream with nothing buffered. */
    private static String readLine(BufferedInputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                buf.write(c);
            }
        }
        if (c == -1 && buf.size() == 0) {
            return null;
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }

    private static byte[] readBytes(InputStream in, int len) throws IOException {
        if (len <= 0) {
            return new byte[0];
        }
        byte[] data = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(data, off, len - off);
            if (n < 0) {
                break;
            }
            off += n;
        }
        return (off == len) ? data : java.util.Arrays.copyOf(data, off);
    }

    private static void writeResponse(OutputStream out, int status, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + ' ' + reasonPhrase(status) + "\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "Content-Length: " + bytes.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.US_ASCII));
        out.write(bytes);
        out.flush();
    }

    private static String reasonPhrase(int status) {
        switch (status) {
            case 200: return "OK";
            case 202: return "Accepted";
            case 400: return "Bad Request";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            case 500: return "Internal Server Error";
            default:  return "Status";
        }
    }

    private void extractBridgeScript() throws IOException {
        scriptDir.mkdirs();
        File dest = new File(scriptDir, scriptName);
        try (InputStream in = EmbeddedGhidraBridge.class.getResourceAsStream(SCRIPT_RESOURCE)) {
            if (in == null) {
                throw new IOException("bundled worker script resource missing: " + SCRIPT_RESOURCE);
            }
            Files.copy(in, dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    // Routes /so/load (exact) to the loader and everything else to the query handler.
    private class SoDispatchHandler implements Handler {
        private final LoadHandler loadHandler = new LoadHandler();
        private final SoHandler soHandler = new SoHandler();

        @Override
        public void handle(Exchange exchange) throws IOException {
            if ("/so/load".equals(exchange.getRequestURI().getPath())) {
                loadHandler.handle(exchange);
            } else {
                soHandler.handle(exchange);
            }
        }
    }

    // ---- POST /so/load ----
    private class LoadHandler implements Handler {
        @Override
        public void handle(Exchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendJson(exchange, 405, errorJson("method not allowed"));
                    return;
                }
                String reqBody = readBody(exchange);
                JsonObject json;
                try {
                    json = JsonParser.parseString(reqBody).getAsJsonObject();
                } catch (Exception parseErr) {
                    sendJson(exchange, 400, errorJson("invalid JSON body"));
                    return;
                }
                String soPath = optString(json, "soPath", null);
                String soId = optString(json, "soId", null);
                boolean force = json.has("force") && !json.get("force").isJsonNull() && json.get("force").getAsBoolean();
                if (soPath == null || soId == null || soPath.isEmpty() || soId.isEmpty()) {
                    sendJson(exchange, 400, errorJson("soPath and soId are required"));
                    return;
                }
                if (!SOID_PATTERN.matcher(soId).matches()) {
                    sendJson(exchange, 400, errorJson("invalid soId: must match [A-Za-z0-9._-]{1,128}"));
                    return;
                }

                File so;
                try {
                    so = new File(soPath).getCanonicalFile();
                } catch (IOException ioe) {
                    System.err.println("[jexray-bridge] soPath canonicalization failed: " + soPath);
                    sendJson(exchange, 400, errorJson("soPath is not a readable native library"));
                    return;
                }
                if (!so.isFile() || !isNativeLibrary(so)) {
                    System.err.println("[jexray-bridge] rejected soPath (missing or not ELF/Mach-O): " + so.getAbsolutePath());
                    sendJson(exchange, 400, errorJson("soPath is not a readable native library"));
                    return;
                }

                LoadState existing = states.get(soId);
                if (existing != null && existing.isInProgress()) {
                    sendJson(exchange, 202,
                        "{\"status\":\"accepted\",\"soId\":" + jsonString(soId) + ",\"note\":\"already loading\"}");
                    return;
                }

                LoadState st = new LoadState();
                states.put(soId, st);
                // caches is keyed by content hash, not soId, and the hash isn't known until
                // doLoad hashes soFinal -- nothing to evict here; doLoad's own cache-hit check
                // (or force) decides whether the existing hash-keyed entry is kept or replaced.
                final File soFinal = so;
                final boolean forceFinal = force;
                loadExecutor.submit(() -> runLoad(soFinal, soId, st, forceFinal));

                sendJson(exchange, 202, "{\"status\":\"accepted\",\"soId\":" + jsonString(soId) + "}");
            } catch (Exception e) {
                sendJson(exchange, 500, errorJson("load error: " + e.getMessage()));
            }
        }
    }

    // ---- GET /so/{soId}/{decompile|disassemble|search|status} ----
    private class SoHandler implements Handler {
        @Override
        public void handle(Exchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendJson(exchange, 405, errorJson("method not allowed"));
                    return;
                }
                String path = exchange.getRequestURI().getPath();
                String rest = path.substring("/so/".length());
                int slash = rest.indexOf('/');
                if (slash < 0) {
                    sendJson(exchange, 404, errorJson("not found: " + path));
                    return;
                }
                String soId = urlDecode(rest.substring(0, slash));
                String op = rest.substring(slash + 1);

                if (!SOID_PATTERN.matcher(soId).matches()) {
                    sendJson(exchange, 400, errorJson("invalid soId: must match [A-Za-z0-9._-]{1,128}"));
                    return;
                }

                if ("status".equals(op)) {
                    Result sr = statusResult(soId);
                    sendJson(exchange, sr.status, sr.body);
                    return;
                }

                // RegisterNatives mapping (dynamically-registered native methods). No query arg.
                if ("registernatives".equals(op)) {
                    CacheData cache = getCache(soId);
                    if (cache == null) {
                        sendNotReady(exchange, soId);
                        return;
                    }
                    Result rn = cache.registerNatives();
                    sendJson(exchange, rn.status, rn.body);
                    return;
                }

                Map<String, String> q = parseQuery(exchange.getRequestURI());
                String arg;
                switch (op) {
                    case "decompile":
                    case "disassemble":
                    case "xrefs":
                        arg = q.get("name");
                        break;
                    case "search":
                        arg = q.getOrDefault("query", "");
                        break;
                    default:
                        sendJson(exchange, 404, errorJson("unknown endpoint: " + op));
                        return;
                }
                if (arg == null) {
                    sendJson(exchange, 400, errorJson("missing query parameter"));
                    return;
                }

                CacheData cache = getCache(soId);
                if (cache == null) {
                    sendNotReady(exchange, soId);
                    return;
                }

                Result r;
                switch (op) {
                    case "decompile":
                        r = cache.decompile(arg);
                        break;
                    case "disassemble":
                        r = cache.disassemble(arg);
                        break;
                    case "xrefs":
                        r = cache.xrefs(arg);
                        break;
                    default:
                        r = cache.search(arg);
                }
                sendJson(exchange, r.status, r.body);
            } catch (Exception e) {
                sendJson(exchange, 500, errorJson("request error: " + e.getMessage()));
            }
        }
    }

    // ---- GET /cache/stats, POST /cache/clear ----
    //
    // the on-disk cache is what accumulates silently, so
    // sizing and clearing it go through the bridge that owns it -- not direct filesystem access
    // from the plugin/UI side, which would leave this process's in-memory caches (a still-warm
    // soId) out of sync with whatever got deleted on disk.
    private class CacheHandler implements Handler {
        @Override
        public void handle(Exchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                String method = exchange.getRequestMethod();
                if ("/cache/stats".equals(path) && "GET".equalsIgnoreCase(method)) {
                    CacheCatalog.Stats stats = CacheCatalog.scan(homeDir);
                    sendJson(exchange, 200, "{\"activeCount\":" + stats.active().size()
                        + ",\"activeBytes\":" + stats.activeBytes()
                        + ",\"legacyCount\":" + stats.legacy().size()
                        + ",\"legacyBytes\":" + stats.legacyBytes() + "}");
                    return;
                }
                if ("/cache/clear".equals(path) && "POST".equalsIgnoreCase(method)) {
                    boolean legacyOnly = true;
                    try {
                        JsonObject j = JsonParser.parseString(readBody(exchange)).getAsJsonObject();
                        if (j.has("legacyOnly") && !j.get("legacyOnly").isJsonNull()) {
                            legacyOnly = j.get("legacyOnly").getAsBoolean();
                        }
                    } catch (Exception parseErr) {
                        // no/invalid body -> default to the safe choice (legacy-only)
                    }
                    long freed;
                    if (legacyOnly) {
                        freed = CacheCatalog.clearLegacy(homeDir);
                    } else {
                        freed = CacheCatalog.clearAll(homeDir);
                        // Files for every active entry are gone; this process must forget them
                        // too; otherwise a soId already resolved to a hash this session would
                        // keep serving the deleted result straight out of memory, and the very
                        // "clear" the user asked for would silently do nothing until restart.
                        caches.clear();
                        soIdToHash.clear();
                        states.clear();
                    }
                    System.out.println("[jexray-bridge] cache clear (" + (legacyOnly ? "legacy" : "all")
                        + "): freed " + freed + " bytes");
                    sendJson(exchange, 200, "{\"freedBytes\":" + freed + "}");
                    return;
                }
                sendJson(exchange, 404, errorJson("unknown endpoint: " + path));
            } catch (Exception e) {
                sendJson(exchange, 500, errorJson("cache error: " + e.getMessage()));
            }
        }
    }

    /** Send the appropriate 409/500/404 when a soId's cache isn't available yet. */
    private void sendNotReady(Exchange exchange, String soId) throws IOException {
        LoadState st = states.get(soId);
        if (st != null && st.isInProgress()) {
            sendJson(exchange, 409, errorJson("still loading, poll /so/" + soId + "/status"));
        } else if (st != null && "error".equals(st.status)) {
            sendJson(exchange, 500, errorJson("load failed: " + st.message));
        } else {
            sendJson(exchange, 404, errorJson("soId not loaded: " + soId));
        }
    }

    // ---- Async load: one analyzeHeadless run imports, analyzes, and dumps all ----

    private void runLoad(File so, String soId, LoadState st, boolean force) {
        // Serialize only a cold start, so the shared GhidraScript OSGi bundle is compiled once
        // before concurrent runs rely on it; everything after that runs in parallel.
        if (!scriptBundleWarmed) {
            coldStartLock.lock();
            try {
                if (!scriptBundleWarmed) {
                    try {
                        doLoad(so, soId, st, force);
                    } finally {
                        scriptBundleWarmed = true;
                    }
                    return;
                }
            } finally {
                coldStartLock.unlock();
            }
        }
        doLoad(so, soId, st, force);
    }

    private void doLoad(File so, String soId, LoadState st, boolean force) {
        // identify this exact binary by content, not by name, and reuse whatever
        // was already analyzed for it -- across soIds, across APKs, across a restart of this
        // process -- instead of re-running Ghidra. Hashed once here per load request; every
        // decompile/disassemble/search query afterwards is served from the in-memory CacheData.
        st.status = "hashing";
        st.message = "Checking cache...";
        String hash;
        long hashStartNs = System.nanoTime();
        try {
            hash = Sha256.hex(so);
        } catch (IOException e) {
            st.fail("failed to hash native library: " + e.getMessage());
            return;
        }
        long hashMs = (System.nanoTime() - hashStartNs) / 1_000_000;
        System.out.println("[jexray-bridge] hashed " + so.getName() + " (" + so.length() + " bytes) in "
            + hashMs + "ms -> " + hash);
        soIdToHash.put(soId, hash);

        // Two soIds can hash to the same content (that's the whole point), and their loads can
        // race in from different pool threads at once. Without serializing per hash, two
        // concurrent analyses of the same bytes would both target the same Ghidra project name
        // and the same cache/progress files -- one's "-overwrite" import colliding with the
        // other's, or one deleting the file the other just wrote. This lock makes concurrent
        // loads of the *same* hash queue up behind each other (by the time the second one gets
        // in, the first's result is already cached, so it's a cache hit rather than a second
        // Ghidra run) while loads of *different* hashes remain fully concurrent.
        ReentrantLock hashLock = hashLocks.computeIfAbsent(hash, h -> new ReentrantLock());
        hashLock.lock();
        try {
            doLoadLocked(so, soId, st, force, hash);
        } finally {
            hashLock.unlock();
        }
    }

    private void doLoadLocked(File so, String soId, LoadState st, boolean force, String hash) {
        File cacheFile = cacheFile(hash);
        File progressFile = progressFile(hash);

        if (!force) {
            CacheData existing = getCacheByHash(hash);
            if (existing != null) {
                st.total = existing.functions.size();
                st.completed = existing.functions.size();
                st.status = "ready";
                CacheCatalog.recordUse(homeDir, hash, soId);
                System.out.println("[jexray-bridge] cache hit: soId=" + soId + " hash=" + hash
                    + " (" + st.total + " functions, Ghidra not invoked)");
                return;
            }
        } else {
            System.out.println("[jexray-bridge] force re-analyze: soId=" + soId + " hash=" + hash
                + " (discarding any existing cache)");
        }

        try {
            if (!analyzeHeadless.isFile()) {
                boolean unset = ghidraInstallDir.getPath().isEmpty();
                st.fail((unset
                        ? "No Ghidra install directory is configured (and none was auto-detected)."
                        : "Ghidra not found at " + ghidraInstallDir + ".")
                    + " Set 'Ghidra install directory' in JADX Preferences > Plugins > Jexray"
                    + " (the folder that contains support" + File.separator + "analyzeHeadless"
                    + (windows ? ".bat" : "") + "), or set the GHIDRA_INSTALL_DIR environment variable.");
                return;
            }
            caches.remove(hash);
            cacheFile.delete();
            progressFile.delete();
            st.progressFile = progressFile;
            // only now is this library genuinely being worked on (it may have queued for a while)
            st.status = "analyzing";
            st.message = "Starting Ghidra...";

            // hash, not soId, is the Ghidra project name too: the on-disk project and the cache
            // it feeds share one identity, so a second soId for the same bytes reuses both.
            ProcOutcome outcome = importAnalyzeAndDump(so, hash, cacheFile, progressFile, st);
            if (outcome.exitCode != 0) {
                st.fail("analyzeHeadless exited " + outcome.exitCode + outcome.tailSuffix());
                return;
            }
            if (!cacheFile.exists()) {
                // analyzeHeadless can exit 0 even when the post-script never ran, so the captured
                // output is the only place the real cause appears.
                st.fail("analysis finished but no cache was produced" + outcome.tailSuffix());
                return;
            }
            CacheData cd = loadCacheFromDisk(cacheFile);
            caches.put(hash, cd);
            st.total = cd.functions.size();
            st.completed = cd.functions.size();
            st.status = "ready";
            CacheCatalog.recordUse(homeDir, hash, soId);
            System.out.println("[jexray-bridge] load ready: soId=" + soId + " hash=" + hash
                + " functions=" + st.total);
        } catch (TimeoutException te) {
            st.fail(te.getMessage());
        } catch (InterruptedException ie) {
            // shutting down: the child process was already killed on the way out; preserve the
            // interrupt so the pool thread actually stops instead of picking up more work
            Thread.currentThread().interrupt();
            st.fail("load interrupted (shutting down)");
        } catch (Exception e) {
            st.fail("load error: " + e.getMessage());
        } finally {
            // The Ghidra project is scratch: only the dump we just read matters, and every later
            // query is served from the cache. Drop it so temp doesn't accumulate a project per .so.
            deleteGhidraProject(hash);
        }
    }

    /** Best-effort removal of the disposable Ghidra project ({@code <hash>.gpr} + {@code .rep}). */
    private void deleteGhidraProject(String hash) {
        try {
            File[] artifacts = ghidraProjectDir.listFiles(
                (d, name) -> name.equals(hash + ".gpr") || name.equals(hash + ".rep")
                    || name.startsWith(hash + ".gpr.") || name.startsWith(hash + ".rep."));
            if (artifacts != null) {
                for (File f : artifacts) {
                    deleteRecursively(f);
                }
            }
        } catch (Exception ignore) {
            // scratch cleanup is best-effort; a leftover project is harmless
        }
    }

    private static void deleteRecursively(File f) {
        if (f == null) {
            return;
        }
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) {
                deleteRecursively(c);
            }
        }
        f.delete();
    }

    /** Exit code plus the tail of the subprocess output, so failures can be explained. */
    private static final class ProcOutcome {
        final int exitCode;
        final List<String> tail;

        ProcOutcome(int exitCode, List<String> tail) {
            this.exitCode = exitCode;
            this.tail = tail;
        }

        /**
         * Formatted for appending to an error message; empty when nothing was captured. When a
         * recognisable script failure is present it is quoted first, because that is the actual
         * cause and it would otherwise be buried in the tail.
         */
        String tailSuffix() {
            if (tail.isEmpty()) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            String cause = scriptFailureCause();
            if (cause != null) {
                sb.append(". Cause: ").append(cause);
            }
            sb.append(". Ghidra output (last ").append(tail.size()).append(" lines):\n")
                .append(String.join("\n", tail));
            return sb.toString();
        }

        /**
         * analyzeHeadless exits 0 for every post-script failure that isn't "script not found"
         * (compile errors, OSGi bundle resolution failures and script exceptions all still exit 0),
         * so the exit code can't be trusted and these output markers are the real signal.
         */
        String scriptFailureCause() {
            for (String line : tail) {
                if (line.contains("SCRIPT ERROR:") || line.contains("Failed to find script")
                        || line.contains("Failed to find source bundle")) {
                    return line.trim();
                }
            }
            return null;
        }
    }

    private static List<String> snapshot(Deque<String> buf) {
        synchronized (buf) {
            return new ArrayList<>(buf);
        }
    }

    /**
     * Map a Ghidra output line onto a coarse phase shown while there is no numeric progress.
     * analyzeHeadless emits nothing our progress file can see until the post-script runs, so these
     * lines are the only signal during import + auto-analysis.
     */
    private static void notePhase(LoadState st, String line) {
        String l = line.toUpperCase(java.util.Locale.ROOT);
        if (l.contains("ANALYZING") || l.contains("ANALYSIS")) {
            st.message = "Auto-analyzing (Ghidra)...";
        } else if (l.contains("IMPORTING") || l.contains("USING LOADER")) {
            st.message = "Importing library...";
        } else if (l.contains("PACKED DATABASE") || l.contains("SAVING")) {
            st.message = "Saving program database...";
        }
    }

    private ProcOutcome importAnalyzeAndDump(File so, String projectName, File cacheFile, File progressFile,
            LoadState st) throws IOException, InterruptedException, TimeoutException {
        List<String> command = new ArrayList<>();
        // On Windows analyzeHeadless is a .bat; CreateProcess (what ProcessBuilder uses) can't run a
        // batch file directly, so it must be launched through cmd.exe. On macOS/Linux the shell
        // script is exec'd directly.
        if (windows) {
            command.add("cmd.exe");
            command.add("/c");
        }
        command.add(analyzeHeadless.getAbsolutePath());
        command.add(ghidraProjectDir.getAbsolutePath());
        command.add(projectName);
        command.add("-import");
        command.add(so.getAbsolutePath());
        command.add("-overwrite");
        command.add("-scriptPath");
        command.add(scriptDir.getAbsolutePath());
        command.add("-postScript");
        command.add(scriptName);
        command.add("dumpall");
        command.add(cacheFile.getAbsolutePath());
        command.add(progressFile.getAbsolutePath());
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().put("GHIDRA_INSTALL_DIR", ghidraInstallDir.getAbsolutePath());
        // Do NOT propagate an inherited JAVA_HOME: the host (jadx-gui / Maven) may run on a
        // JDK the target Ghidra can't use for its OSGi script compiler (e.g. Ghidra 11.x's
        // Felix doesn't recognise JDK 25's execution environment -> osgi.ee=UNKNOWN -> the
        // GhidraScript fails to load). Clearing it lets Ghidra's own launcher pick a JDK it
        // supports. Harmless for Ghidra 12.x, which accepts a wider JDK range.
        pb.environment().remove("JAVA_HOME");
        pb.redirectErrorStream(true);
        // Capture rather than INHERIT: analyzeHeadless can exit 0 with the post-script never having
        // run, and then its output is the only record of why. A dedicated thread drains the pipe --
        // if we only read after waitFor, a chatty run fills the pipe buffer and deadlocks.
        Process p = pb.start();
        liveProcesses.add(p); // so stop() can kill it rather than orphan a multi-GB Ghidra JVM
        Deque<String> tail = new ArrayDeque<>();
        // Liveness: every line of Ghidra output counts as a sign of life. maxGap records the longest
        // silence actually observed, which is the evidence needed to tighten STALL_TIMEOUT_MS later.
        java.util.concurrent.atomic.AtomicLong lastSignal =
            new java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis());
        java.util.concurrent.atomic.AtomicLong maxGap = new java.util.concurrent.atomic.AtomicLong(0);
        Thread drain = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    long now = System.currentTimeMillis();
                    maxGap.accumulateAndGet(now - lastSignal.getAndSet(now), Math::max);
                    System.out.println("[ghidra] " + line); // keep the console view we had before
                    synchronized (tail) {
                        tail.addLast(line);
                        while (tail.size() > LOG_TAIL_LINES) {
                            tail.removeFirst();
                        }
                    }
                    notePhase(st, line);
                }
            } catch (IOException ignored) {
                // process died or stream closed; the tail we already have is what we report
            }
        }, "jexray-bridge-ghidra-out");
        drain.setDaemon(true);
        drain.start();

        try {
            // Wait for as long as the analysis keeps showing signs of life. Time alone is not a
            // failure: a large library legitimately runs for an hour. Only silence is.
            while (!p.waitFor(LIVENESS_POLL_MS, TimeUnit.MILLISECONDS)) {
                long progressAt = progressFile.lastModified(); // the post-script's own heartbeat
                if (progressAt > lastSignal.get()) {
                    lastSignal.set(progressAt);
                }
                long idle = System.currentTimeMillis() - lastSignal.get();
                if (idle > STALL_TIMEOUT_MS) {
                    destroyTree(p); // the JVM is a grandchild; killing our handle alone leaves it running
                    p.waitFor(5, TimeUnit.SECONDS);
                    drain.join(2000);
                    throw new TimeoutException("no output from Ghidra for " + (idle / 1000)
                        + "s, giving up (analysis appears stuck)"
                        + new ProcOutcome(-1, snapshot(tail)).tailSuffix());
                }
            }
            drain.join(2000); // let the drain finish so the captured tail is complete
            System.out.println("[jexray-bridge] " + projectName + ": longest silence during analysis was "
                + maxGap.get() + "ms (stall limit " + STALL_TIMEOUT_MS + "ms)");
            return new ProcOutcome(p.exitValue(), snapshot(tail));
        } catch (InterruptedException ie) {
            // plugin unload / shutdownNow: don't leave the Ghidra JVM running behind us
            destroyTree(p);
            throw ie;
        } finally {
            liveProcesses.remove(p);
        }
    }

    // ---- status ----

    private Result statusResult(String soId) {
        LoadState st = states.get(soId);
        if (st == null) {
            // Every soId this bridge knows about was seen through /so/load, which always creates
            // a LoadState -- so "no state" genuinely means "never submitted", not "restart lost
            // it": recovering a warm cache across a restart happens in doLoad's cache-hit path
            // (keyed by content hash) the next time the client calls /so/load, not here. There is
            // no soId-keyed cache left to fall back to reading directly any more.
            return new Result(404, statusJson("not_found", 0, 0, "soId not loaded"));
        }
        if (st.isInProgress()) {
            int[] pr = readProgress(st.progressFile);
            if (pr != null) {
                st.completed = pr[0];
                st.total = pr[1];
                if (pr[1] > 0) {
                    st.status = "caching";
                }
            }
        }
        return new Result(200, statusJson(st.status, st.completed, st.total, st.message));
    }

    private static String statusJson(String status, int completed, int total, String message) {
        return "{\"status\":" + jsonString(status)
            + ",\"completed\":" + completed
            + ",\"total\":" + total
            + ",\"message\":" + jsonString(message == null ? "" : message) + "}";
    }

    private int[] readProgress(File progressFile) {
        if (progressFile == null || !progressFile.exists()) {
            return null;
        }
        try {
            JsonObject o = JsonParser.parseString(
                Files.readString(progressFile.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();
            return new int[]{optInt(o, "completed", 0), optInt(o, "total", 0)};
        } catch (Exception e) {
            return null;
        }
    }

    // ---- cache ----

    /** Resolve a client-facing soId to its cached result, via the hash it was last loaded under. */
    private CacheData getCache(String soId) {
        String hash = soIdToHash.get(soId);
        if (hash == null) {
            return null; // this soId was never submitted via /so/load in this process
        }
        return getCacheByHash(hash);
    }

    /**
     * The real cache lookup, by content hash: in-memory first, else read (and memoize) from disk
     * -- which is what makes a cache produced by an earlier run of this bridge, or by a different
     * soId that happens to name the same bytes, reusable without invoking Ghidra again. A corrupt
     * cache file is treated as absent (logged, not thrown) so the caller's normal "not cached"
     * path re-analyzes rather than failing outright.
     */
    private CacheData getCacheByHash(String hash) {
        CacheData cd = caches.get(hash);
        if (cd != null) {
            return cd;
        }
        File cf = cacheFile(hash);
        if (!cf.exists()) {
            return null;
        }
        try {
            cd = loadCacheFromDisk(cf);
            caches.put(hash, cd);
            return cd;
        } catch (Exception e) {
            System.err.println("[jexray-bridge] cache for hash " + hash + " unreadable, will re-analyze: "
                + e.getMessage());
            return null;
        }
    }

    private CacheData loadCacheFromDisk(File cacheFile) throws IOException {
        JsonObject root = JsonParser.parseString(
            Files.readString(cacheFile.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();
        // A cache from before xref collection existed has no "formatVersion" key at all, which
        // parses as 0 here -- always less than CURRENT_CACHE_FORMAT_VERSION, which is exactly the
        // "xrefs unknown" signal CacheData needs. See the field's javadoc.
        int formatVersion = optInt(root, "formatVersion", 0);
        boolean xrefsKnown = formatVersion >= CURRENT_CACHE_FORMAT_VERSION;
        JsonArray arr = root.getAsJsonArray("functions");
        List<FuncEntry> list = new ArrayList<>(arr.size());
        Map<String, FuncEntry> byName = new HashMap<>();
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            List<CallerEntry> callers = null;
            if (xrefsKnown && o.has("callers") && o.get("callers").isJsonArray()) {
                JsonArray callersArr = o.getAsJsonArray("callers");
                callers = new ArrayList<>(callersArr.size());
                for (JsonElement ce : callersArr) {
                    JsonObject co = ce.getAsJsonObject();
                    callers.add(new CallerEntry(co.get("name").getAsString(), co.get("address").getAsString()));
                }
            }
            FuncEntry fe = new FuncEntry(
                o.get("name").getAsString(),
                o.get("address").getAsString(),
                optString(o, "pseudocode", ""),
                optString(o, "disassembly", ""),
                callers);
            list.add(fe);
            byName.putIfAbsent(fe.name, fe);
        }
        String regNatives = root.has("registerNatives") && root.get("registerNatives").isJsonArray()
            ? root.getAsJsonArray("registerNatives").toString() : "[]";
        // Not gated on formatVersion: a version bump would not regenerate an existing cache, it
        // would only strip its xrefs (see CURRENT_CACHE_FORMAT_VERSION). An older cache simply has
        // no "externals" key and keeps answering "not found", exactly as it did before.
        Set<String> externals = new HashSet<>();
        if (root.has("externals") && root.get("externals").isJsonArray()) {
            for (JsonElement el : root.getAsJsonArray("externals")) {
                externals.add(el.getAsString());
            }
        }
        return new CacheData(list, byName, regNatives, xrefsKnown, externals);
    }

    /** {@code key} is a content hash for every load reaching this point (see {@link #doLoad}). */
    private File cacheFile(String key) {
        return new File(projectsDir, key + ".cache.json");
    }

    private File progressFile(String key) {
        return new File(projectsDir, key + ".progress.json");
    }

    // ---- state / cache model ----

    private static class LoadState {
        // starts queued: the load pool is bounded, so a submitted library may sit in the queue for
        // a long time. Reporting "analyzing" here would make it indistinguishable from one a worker
        // has actually picked up. Reporting "analyzing" here would make a queued library
        // indistinguishable from one actually being analyzed, and clients would burn their
        // analysis timeout while merely waiting in line.
        volatile String status = "queued";
        volatile int completed = 0;
        volatile int total = 0;
        volatile String message = "";
        volatile File progressFile;

        boolean isInProgress() {
            return "queued".equals(status) || "hashing".equals(status)
                || "analyzing".equals(status) || "caching".equals(status);
        }

        void fail(String msg) {
            this.status = "error";
            this.message = msg;
            System.err.println("[jexray-bridge] load failed: " + msg);
        }
    }

    /** One caller of a {@link FuncEntry}: the calling function's name and its (first) call-site address. */
    private static class CallerEntry {
        final String name;
        final String address;

        CallerEntry(String name, String address) {
            this.name = name;
            this.address = address;
        }
    }

    private static class FuncEntry {
        final String name;
        final String address;
        final String pseudocode;
        final String disassembly;
        // null when the owning cache predates xref collection (see CacheData.xrefsKnown); an
        // empty (non-null) list means the collection ran and genuinely found no callers.
        final List<CallerEntry> callers;

        FuncEntry(String name, String address, String pseudocode, String disassembly, List<CallerEntry> callers) {
            this.name = name;
            this.address = address;
            this.pseudocode = pseudocode;
            this.disassembly = disassembly;
            this.callers = callers;
        }
    }

    private static class CacheData {
        final List<FuncEntry> functions;
        final Map<String, FuncEntry> byName;
        final String registerNativesJson; // pre-built JSON array of {name,signature,symbol,address}
        // A function with genuinely no callers must be distinguishable from one whose
        // xrefs were never collected. False when this cache was written before caller collection
        // existed (see CURRENT_CACHE_FORMAT_VERSION) -- every FuncEntry.callers in that case is
        // null and must be reported as "unknown", never rendered as an empty (i.e. "verified
        // none") list.
        final boolean xrefsKnown;
        /**
         * Names present in the library only as a forwarding stub -- imported from libc, liblog and
         * friends. They are intentionally absent from {@link #functions}, so without this set a
         * click on one would be indistinguishable from a typo. Empty for caches written before the
         * key existed, which simply fall back to the old "not found" answer.
         */
        final Set<String> externals;

        CacheData(List<FuncEntry> functions, Map<String, FuncEntry> byName, String registerNativesJson,
                boolean xrefsKnown, Set<String> externals) {
            this.functions = functions;
            this.byName = byName;
            this.registerNativesJson = registerNativesJson;
            this.xrefsKnown = xrefsKnown;
            this.externals = externals;
        }

        Result registerNatives() {
            return new Result(200, "{\"methods\":" + registerNativesJson + "}");
        }

        FuncEntry find(String name) {
            FuncEntry fe = byName.get(name);
            if (fe != null) {
                return fe;
            }
            fe = byName.get("_" + name);
            if (fe != null) {
                return fe;
            }
            if (name.startsWith("_")) {
                fe = byName.get(name.substring(1));
            }
            return fe;
        }

        /**
         * 410 for an import, else null. Checked before {@link #find}, because imports are listed
         * in the function browser (so the user can see what the library depends on) yet carry no
         * body -- a hit in {@code byName} would otherwise serve their empty pseudocode as if it
         * were real output.
         */
        private Result externalOr(String name) {
            return externals.contains(name)
                ? new Result(410, errorJson("external symbol: " + name))
                : null;
        }

        /** 404 for a name this cache simply does not carry. */
        private Result missing(String name) {
            return new Result(404, errorJson("function not found: " + name));
        }

        Result decompile(String name) {
            Result ext = externalOr(name);
            if (ext != null) {
                return ext;
            }
            FuncEntry fe = find(name);
            if (fe == null) {
                return missing(name);
            }
            return new Result(200, "{\"pseudocode\":" + jsonString(fe.pseudocode)
                + ",\"address\":" + jsonString(fe.address) + "}");
        }

        Result disassemble(String name) {
            Result ext = externalOr(name);
            if (ext != null) {
                return ext;
            }
            FuncEntry fe = find(name);
            if (fe == null) {
                return missing(name);
            }
            return new Result(200, "{\"disassembly\":" + jsonString(fe.disassembly)
                + ",\"address\":" + jsonString(fe.address) + "}");
        }

        /**
         * Callers of {@code name}. {@code xrefsKnown=false} in the response means this cache
         * predates caller collection -- the caller list is empty because it was never computed,
         * not because the function has no callers. A genuinely-childless function instead comes
         * back {@code xrefsKnown=true} with an empty {@code callers} array, which is the positive
         * "checked and found none" result callers need.
         */
        Result xrefs(String name) {
            Result ext = externalOr(name);
            if (ext != null) {
                return ext;
            }
            FuncEntry fe = find(name);
            if (fe == null) {
                return missing(name);
            }
            if (!xrefsKnown) {
                return new Result(200, "{\"xrefsKnown\":false,\"callers\":[]}");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("{\"xrefsKnown\":true,\"callers\":[");
            boolean first = true;
            // fe.callers is only null here if a formatVersion>=CURRENT cache somehow omitted the
            // field for one function -- shouldn't happen from a writer that always emits it, but
            // treated as "found none" rather than risking an NPE on a malformed cache file.
            for (CallerEntry c : fe.callers == null ? List.<CallerEntry>of() : fe.callers) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append("{\"name\":").append(jsonString(c.name))
                  .append(",\"address\":").append(jsonString(c.address)).append('}');
            }
            sb.append("]}");
            return new Result(200, sb.toString());
        }

        Result search(String query) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"functions\":[");
            boolean first = true;
            // case-insensitive, matching the client's FunctionFilter -- the "All Functions" total
            // asks this endpoint for a not-yet-loaded library's match count and combines it with
            // counts computed locally (case-insensitively) for already-loaded libraries; if this
            // endpoint compared case-sensitively the combined total would silently shift the moment
            // a library got expanded and its count switched from this endpoint to the local one.
            String needle = query.toLowerCase(Locale.ROOT);
            for (FuncEntry fe : functions) {
                if (needle.isEmpty() || fe.name.toLowerCase(Locale.ROOT).contains(needle)) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    // "external" lets the browser mark an entry the caller can list but not open,
                    // instead of leaving the user to discover that by clicking it.
                    sb.append("{\"name\":").append(jsonString(fe.name))
                      .append(",\"address\":").append(jsonString(fe.address))
                      .append(",\"external\":").append(externals.contains(fe.name))
                      .append('}');
                }
            }
            sb.append("]}");
            return new Result(200, sb.toString());
        }
    }

    private static boolean isNativeLibrary(File f) {
        byte[] magic = new byte[4];
        try (InputStream is = Files.newInputStream(f.toPath())) {
            if (is.read(magic) != 4) {
                return false;
            }
        } catch (IOException e) {
            return false;
        }
        int b0 = magic[0] & 0xFF, b1 = magic[1] & 0xFF, b2 = magic[2] & 0xFF, b3 = magic[3] & 0xFF;
        if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) return true;                 // ELF
        if (b0 == 0xCF && b1 == 0xFA && b2 == 0xED && b3 == 0xFE) return true;                 // Mach-O 64 LE
        if (b0 == 0xCE && b1 == 0xFA && b2 == 0xED && b3 == 0xFE) return true;                 // Mach-O 32 LE
        if (b0 == 0xFE && b1 == 0xED && b2 == 0xFA && (b3 == 0xCF || b3 == 0xCE)) return true; // Mach-O BE
        if (b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBE) return true;                 // fat
        if (b0 == 0xBE && b1 == 0xBA && b2 == 0xFE && b3 == 0xCA) return true;                 // fat swapped
        return false;
    }

    // ---- helpers ----

    private static class Result {
        final int status;
        final String body;
        Result(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    private static String optString(JsonObject o, String key, String def) {
        JsonElement e = o.get(key);
        return (e == null || e.isJsonNull()) ? def : e.getAsString();
    }

    private static int optInt(JsonObject o, String key, int def) {
        JsonElement e = o.get(key);
        try {
            return (e == null || e.isJsonNull()) ? def : e.getAsInt();
        } catch (Exception ex) {
            return def;
        }
    }

    private static String readBody(Exchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> map = new HashMap<>();
        String q = uri.getRawQuery();
        if (q == null || q.isEmpty()) {
            return map;
        }
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                map.put(urlDecode(pair), "");
            } else {
                map.put(urlDecode(pair.substring(0, eq)), urlDecode(pair.substring(eq + 1)));
            }
        }
        return map;
    }

    private static String urlDecode(String s) {
        return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static void sendJson(Exchange exchange, int status, String body) throws IOException {
        writeResponse(exchange.out, status, body);
        exchange.responded = true;
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
