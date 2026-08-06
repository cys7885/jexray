package com.jexray.jadx.bridge;

import java.util.List;

/**
 * DTOs mirroring the Ghidra bridge REST contract. Field names match the JSON keys
 * exactly so Gson maps them directly.
 */
public final class BridgeModels {

	private BridgeModels() {
	}

	/** Request body for {@code POST /so/load}. */
	public static final class LoadRequest {
		public String soPath;
		public String soId;
		/** Force a fresh analysis even if a cache for this binary's content hash already exists. */
		public boolean force;

		public LoadRequest(String soPath, String soId) {
			this(soPath, soId, false);
		}

		public LoadRequest(String soPath, String soId, boolean force) {
			this.soPath = soPath;
			this.soId = soId;
			this.force = force;
		}
	}

	/** Response for {@code GET /cache/stats}. */
	public static final class CacheStatsResult {
		public int activeCount;
		public long activeBytes;
		public int legacyCount;
		public long legacyBytes;
	}

	/** Request body for {@code POST /cache/clear}. */
	public static final class ClearCacheRequest {
		public boolean legacyOnly;

		public ClearCacheRequest(boolean legacyOnly) {
			this.legacyOnly = legacyOnly;
		}
	}

	/** Response for {@code POST /cache/clear}. */
	public static final class ClearCacheResult {
		public long freedBytes;
	}

	/** Response for {@code GET /so/{soId}/status}. */
	public static final class StatusResult {
		public String status; // queued | hashing | analyzing | caching | ready | error
		public int completed;
		public int total;
		public String message;
	}

	/** Response for {@code GET /so/{soId}/decompile}. */
	public static final class DecompileResult {
		public String pseudocode;
		public String address;
	}

	/** Response for {@code GET /so/{soId}/disassemble}. */
	public static final class DisassembleResult {
		public String disassembly;
		public String address;
	}

	/**
	 * Response for {@code GET /so/{soId}/xrefs}. {@code xrefsKnown=false} means the cache this
	 * came from predates cross-reference collection -- it must be shown as "unknown", not
	 * conflated with a function that was checked and genuinely has no callers ({@code
	 * xrefsKnown=true} with an empty {@code callers} list).
	 */
	public static final class XrefsResult {
		public boolean xrefsKnown;
		public List<CallerRef> callers;
	}

	/** One caller: the calling function's name and its (first) call-site address. */
	public static final class CallerRef {
		public String name;
		public String address;
	}

	/** Response for {@code GET /so/{soId}/search}. */
	public static final class SearchResult {
		public List<FunctionRef> functions;
	}

	public static final class FunctionRef {
		public String name;
		public String address;
		/**
		 * The library lists this name but holds no body for it -- it is linked in from elsewhere.
		 * Absent from caches written before the field existed, which parse as {@code false} and so
		 * behave exactly as they did before.
		 */
		public boolean external;
	}

	/** Response for {@code GET /so/{soId}/registernatives}. */
	public static final class RegisterNativesResult {
		public List<RegNative> methods;
	}

	/** A dynamically-registered (RegisterNatives) native method. */
	public static final class RegNative {
		public String name;       // Java method name
		public String signature;  // JNI signature, e.g. "(II)I"
		public String symbol;     // Ghidra function name at fnPtr -- synthetic or recovered
		public String address;    // fnPtr address, "0x..."
	}
}
