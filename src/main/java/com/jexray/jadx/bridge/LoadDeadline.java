package com.jexray.jadx.bridge;

/**
 * How long the client waits on a bridge that has stopped answering.
 *
 * <p>Deliberately not an analysis timeout. Analysis time scales with the binary -- the largest
 * libraries an APK can carry reach hundreds of thousands of functions and can take hours -- so a
 * client-side clock racing the bridge's own only ever cuts healthy work short and reports a timeout
 * that isn't the real problem. The bridge decides when an analysis has genuinely stalled; this only
 * covers the bridge itself going away.
 *
 * <p>Clock values are passed in rather than read here, so the behaviour is testable without waiting
 * in real time.
 */
public final class LoadDeadline {

	/** Bridge status meaning "submitted but not started". */
	public static final String QUEUED = "queued";

	private final long timeoutMs;
	private long deadline;

	public LoadDeadline(long timeoutMs, long now) {
		this.timeoutMs = timeoutMs;
		this.deadline = now + timeoutMs;
	}

	/**
	 * Feed the latest bridge status. Any answer at all pushes the deadline forward: the bridge is
	 * alive and tracking this load, and it is the authority on whether the analysis is progressing
	 * (it gives up itself once Ghidra goes silent). So this timeout measures only how long the
	 * bridge has been unreachable -- never how long an analysis takes, which is legitimately an hour
	 * for a large library and must not be cut short from here.
	 *
	 * <p>That subsumes the queued case: time spent waiting in the queue cannot expire the deadline,
	 * because the bridge keeps answering throughout.
	 */
	public void onStatus(String status, long now) {
		deadline = now + timeoutMs;
	}

	public boolean isExpired(long now) {
		return now >= deadline;
	}

	public long timeoutMs() {
		return timeoutMs;
	}
}
