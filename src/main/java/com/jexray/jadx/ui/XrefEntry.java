package com.jexray.jadx.ui;

/** One caller in an {@link XrefsView}: the calling function's name and its call-site address. */
public record XrefEntry(String name, String address) {
}
