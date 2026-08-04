package com.jexray.jadx.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;

import com.jexray.jadx.bridge.BridgeModels.CacheStatsResult;
import com.jexray.jadx.bridge.BridgeModels.ClearCacheRequest;
import com.jexray.jadx.bridge.BridgeModels.ClearCacheResult;
import com.jexray.jadx.bridge.BridgeModels.DecompileResult;
import com.jexray.jadx.bridge.BridgeModels.DisassembleResult;
import com.jexray.jadx.bridge.BridgeModels.LoadRequest;
import com.jexray.jadx.bridge.BridgeModels.RegisterNativesResult;
import com.jexray.jadx.bridge.BridgeModels.SearchResult;
import com.jexray.jadx.bridge.BridgeModels.StatusResult;
import com.jexray.jadx.bridge.BridgeModels.XrefsResult;

/**
 * HTTP client for the Ghidra bridge service.
 *
 * <p>Uses only {@link HttpURLConnection} from {@code java.base}, so the plugin runs on any Java
 * runtime -- including the minimal, jlink-trimmed JRE some jadx-gui distributions bundle, which
 * omits the {@code java.net.http} and {@code jdk.httpserver} modules.
 *
 * <p>Contract (base URL configurable, default {@code http://localhost:8791}):
 * <ul>
 *   <li>{@code POST /so/load} body {@code {"soPath":"...","soId":"..."}}</li>
 *   <li>{@code GET /so/{soId}/decompile?name=<symbol>} -&gt; {@code {"pseudocode":"...","address":"0x..."}}</li>
 *   <li>{@code GET /so/{soId}/disassemble?name=<symbol>} -&gt; {@code {"disassembly":"...","address":"0x..."}}</li>
 *   <li>{@code GET /so/{soId}/search?query=<substr>} -&gt; {@code {"functions":[{"name":"...","address":"..."}]}}</li>
 *   <li>{@code GET /so/{soId}/xrefs?name=<symbol>} -&gt; {@code {"xrefsKnown":bool,"callers":[{"name":"...","address":"..."}]}}</li>
 * </ul>
 */
public class GhidraBridgeClient {

	public static final String DEFAULT_BASE_URL = "http://localhost:8791";

	private static final int CONNECT_TIMEOUT_MS = 5_000;
	private static final int READ_TIMEOUT_MS = 60_000;

	private final Gson gson = new Gson();
	private volatile String baseUrl;

	public GhidraBridgeClient(String baseUrl) {
		setBaseUrl(baseUrl);
	}

	public void setBaseUrl(String baseUrl) {
		String url = (baseUrl == null || baseUrl.isBlank()) ? DEFAULT_BASE_URL : baseUrl.trim();
		while (url.endsWith("/")) {
			url = url.substring(0, url.length() - 1);
		}
		this.baseUrl = url;
	}

	public String getBaseUrl() {
		return baseUrl;
	}

	/** Ask the bridge to load a .so from a filesystem path under the given id. */
	public void load(String soPath, String soId) throws BridgeException, InterruptedException {
		load(soPath, soId, false);
	}

	/**
	 * As {@link #load(String, String)}, but with {@code force=true} the bridge discards any
	 * existing cache for this binary's content hash and re-analyzes from scratch (the "Re-analyze"
	 * library action), instead of serving the cached result.
	 */
	public void load(String soPath, String soId, boolean force) throws BridgeException, InterruptedException {
		post("/so/load", gson.toJson(new LoadRequest(soPath, soId, force)));
	}

	/** Size of the on-disk analysis cache, split into content-hash-keyed (active) and legacy. */
	public CacheStatsResult cacheStats() throws BridgeException, InterruptedException {
		return parse(get("/cache/stats"), CacheStatsResult.class);
	}

	/** Delete cached analyses. {@code legacyOnly=true} removes only pre-content-hash entries. */
	public ClearCacheResult clearCache(boolean legacyOnly) throws BridgeException, InterruptedException {
		return parse(post("/cache/clear", gson.toJson(new ClearCacheRequest(legacyOnly))), ClearCacheResult.class);
	}

	public DecompileResult decompile(String soId, String symbolName) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/decompile?name=" + enc(symbolName)), DecompileResult.class);
	}

	public DisassembleResult disassemble(String soId, String symbolName) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/disassemble?name=" + enc(symbolName)), DisassembleResult.class);
	}

	public SearchResult search(String soId, String query) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/search?query=" + enc(query)), SearchResult.class);
	}

	/** Callers of {@code symbolName} within {@code soId} -- see {@link XrefsResult} for the unknown-vs-none contract. */
	public XrefsResult xrefs(String soId, String symbolName) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/xrefs?name=" + enc(symbolName)), XrefsResult.class);
	}

	/** Poll the load/analysis status of a previously-submitted .so. */
	public StatusResult status(String soId) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/status"), StatusResult.class);
	}

	/** Dynamically-registered (RegisterNatives) native methods found in the .so. */
	public RegisterNativesResult registerNatives(String soId) throws BridgeException, InterruptedException {
		return parse(get("/so/" + enc(soId) + "/registernatives"), RegisterNativesResult.class);
	}

	private String get(String pathAndQuery) throws BridgeException, InterruptedException {
		return send("GET", pathAndQuery, null);
	}

	private String post(String pathAndQuery, String jsonBody) throws BridgeException, InterruptedException {
		return send("POST", pathAndQuery, jsonBody);
	}

	private <T> T parse(String body, Class<T> type) throws BridgeException {
		try {
			T value = gson.fromJson(body, type);
			if (value == null) {
				throw new BridgeException(BridgeException.Kind.BAD_RESPONSE, "empty response body");
			}
			return value;
		} catch (com.google.gson.JsonSyntaxException e) {
			throw new BridgeException(BridgeException.Kind.BAD_RESPONSE, e.getMessage(), e);
		}
	}

	/**
	 * Perform one request and return the response body. Declares {@code InterruptedException} so
	 * callers can keep handling interruption uniformly, though the blocking here is socket I/O
	 * bounded by the connect/read timeouts rather than a wait that throws it.
	 */
	private String send(String method, String pathAndQuery, String jsonBody)
			throws BridgeException, InterruptedException {
		String url = baseUrl + pathAndQuery;
		HttpURLConnection conn = null;
		try {
			conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
			conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
			conn.setReadTimeout(READ_TIMEOUT_MS);
			conn.setRequestMethod(method);
			conn.setUseCaches(false);
			if (jsonBody != null) {
				byte[] payload = jsonBody.getBytes(StandardCharsets.UTF_8);
				conn.setDoOutput(true);
				conn.setFixedLengthStreamingMode(payload.length);
				conn.setRequestProperty("Content-Type", "application/json");
				try (OutputStream os = conn.getOutputStream()) {
					os.write(payload);
				}
			}

			int code = conn.getResponseCode();
			String body = readAll(code >= 400 ? conn.getErrorStream() : conn.getInputStream());

			if (code == 404) {
				throw new BridgeException(BridgeException.Kind.NOT_FOUND, "HTTP 404 for " + url);
			}
			if (code == 409) {
				throw new BridgeException(BridgeException.Kind.STILL_LOADING, "HTTP 409 for " + url);
			}
			if (code < 200 || code >= 300) {
				throw new BridgeException(BridgeException.Kind.HTTP_ERROR,
						"HTTP " + code + " for " + url + (body.isEmpty() ? "" : ": " + truncate(body)));
			}
			return body;
		} catch (IOException e) {
			// connection refused / timeout / unknown host / reset
			throw new BridgeException(BridgeException.Kind.CONNECTION_FAILED,
					"cannot reach bridge: " + e.getMessage(), e);
		} finally {
			if (conn != null) {
				conn.disconnect();
			}
		}
	}

	private static String readAll(InputStream in) throws IOException {
		if (in == null) {
			return "";
		}
		try (InputStream is = in) {
			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	private static String truncate(String s) {
		return s.length() > 500 ? s.substring(0, 500) + "..." : s;
	}

	private static String enc(String s) {
		return URLEncoder.encode(s, StandardCharsets.UTF_8);
	}
}
