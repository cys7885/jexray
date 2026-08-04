package com.jexray.jadx.nav;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Linear back/forward navigation history (browser style).
 *
 * <p>Cursor points at the current entry. {@link #push} appends after the cursor,
 * discarding any forward entries, then advances the cursor to the new entry.
 * Pure and independent of any UI/JADX type so it is unit-testable.
 */
public class NavigationHistory<T> {

	private final List<T> entries = new ArrayList<>();
	private int cursor = -1;

	/** Add a new entry, dropping any forward history, and make it current. */
	public void push(T entry) {
		// drop forward entries
		while (entries.size() > cursor + 1) {
			entries.remove(entries.size() - 1);
		}
		entries.add(entry);
		cursor = entries.size() - 1;
	}

	/**
	 * Visit a symbol, keeping the history free of duplicates across the WHOLE stack
	 * (both back and forward). If an entry with the same key already exists anywhere, the
	 * cursor moves to it and its content is refreshed in place — no new entry, no reordering,
	 * no forward truncation. Otherwise the entry is appended and becomes current.
	 *
	 * <p>This is stronger than a mere adjacent-duplicate check: {@code A,B,A,C,A,B,C} collapses
	 * to a stable unique list {@code [A,B,C]} with the cursor moving among existing positions.
	 *
	 * @return true if a new entry was appended, false if an existing one was revisited
	 */
	public boolean visit(T entry, Function<? super T, ?> keyFn) {
		Object key = keyFn.apply(entry);
		for (int i = 0; i < entries.size(); i++) {
			if (Objects.equals(keyFn.apply(entries.get(i)), key)) {
				entries.set(i, entry); // refresh content (e.g. a now-known Java ref)
				cursor = i;
				return false;
			}
		}
		entries.add(entry);
		cursor = entries.size() - 1;
		return true;
	}

	public boolean canBack() {
		return cursor > 0;
	}

	public boolean canForward() {
		return cursor >= 0 && cursor < entries.size() - 1;
	}

	/** Move cursor back one and return the now-current entry. */
	public T back() {
		if (!canBack()) {
			throw new IllegalStateException("no back history");
		}
		cursor--;
		return entries.get(cursor);
	}

	/** Move cursor forward one and return the now-current entry. */
	public T forward() {
		if (!canForward()) {
			throw new IllegalStateException("no forward history");
		}
		cursor++;
		return entries.get(cursor);
	}

	/** The current entry, or null if history is empty. */
	public T current() {
		return cursor < 0 ? null : entries.get(cursor);
	}

	/** All entries in navigation order (oldest first), as an unmodifiable snapshot. */
	public List<T> entries() {
		return Collections.unmodifiableList(new ArrayList<>(entries));
	}

	/** Jump the cursor to an absolute index and return that entry. */
	public T jumpTo(int index) {
		if (index < 0 || index >= entries.size()) {
			throw new IndexOutOfBoundsException("history index " + index + " of " + entries.size());
		}
		cursor = index;
		return entries.get(cursor);
	}

	public boolean isEmpty() {
		return entries.isEmpty();
	}

	public int size() {
		return entries.size();
	}

	public int cursor() {
		return cursor;
	}

	public void clear() {
		entries.clear();
		cursor = -1;
	}
}
