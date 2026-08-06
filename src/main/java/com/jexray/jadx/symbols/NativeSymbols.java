package com.jexray.jadx.symbols;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Pure-Java reader of a native library's <em>defined</em> symbol names, straight from the
 * ELF/Mach-O symbol tables — no Ghidra, fast enough to scan many candidate .so files up front to
 * decide which one actually defines a given JNI function.
 *
 * <p>"Defined" means bound to a section, not necessarily externally visible: the ELF path unions
 * {@code .dynsym} with {@code .symtab}, so an unstripped build also yields local and static
 * functions. The Mach-O path is restricted to external symbols. Shipped Android libraries are
 * normally stripped, so in practice the ELF result is the dynamic exports.
 *
 * <p>Reads the ELF dynamic symbol table ({@code .dynsym}) — which survives stripping and is
 * where exported JNI functions live — and the Mach-O symbol table (LC_SYMTAB). Only symbols
 * that are both defined (in a section, not an undefined import) and named are returned.
 * Handles ELF32/64 both byte orders, thin Mach-O 32/64 both byte orders, and fat Mach-O
 * (first slice). Anything unrecognised yields an empty set (never throws for bad input).
 */
public final class NativeSymbols {

	private NativeSymbols() {
	}

	// ELF
	private static final int SHT_SYMTAB = 2;
	private static final int SHT_DYNSYM = 11;

	// ELF symbol types (st_info & 0xf)
	private static final int STT_NOTYPE = 0;
	private static final int STT_FUNC = 2;
	private static final int STT_GNU_IFUNC = 10;

	/** Section holds executable instructions (SHF_EXECINSTR). */
	private static final long SHF_EXECINSTR = 0x4;

	/**
	 * Whether a symbol names something worth opening. {@code STT_FUNC} and {@code STT_GNU_IFUNC}
	 * qualify outright.
	 *
	 * <p>{@code STT_NOTYPE} is admitted only when it sits in an executable section. It has to be
	 * admitted at all because hand-written assembly routinely omits the {@code .type} directive,
	 * and dropping it would lose JNI entry points {@link #defines} has to find -- but untyped
	 * symbols are also how toolchains label read-only data, and build tooling routinely stamps
	 * such labels into {@code .rodata}. Without the section test those appear as functions that no
	 * decompiler can then produce.
	 */
	private static boolean namesCode(int type, boolean inExecSection) {
		if (type == STT_FUNC || type == STT_GNU_IFUNC) {
			return true;
		}
		return type == STT_NOTYPE && inExecSection;
	}

	/**
	 * Whether {@code shndx} refers to a real, executable section. Reserved indices (SHN_ABS,
	 * SHN_COMMON, anything past the table) name no section and so hold no code.
	 */
	private static boolean isExecSection(ByteBuffer sh, int shentsize, int shnum, boolean is64,
			int shndx) {
		if (shndx <= 0 || shndx >= shnum) {
			return false;
		}
		int base = shndx * shentsize;
		long flags = is64 ? sh.getLong(base + 8) : sh.getInt(base + 8) & 0xFFFFFFFFL;
		return (flags & SHF_EXECINSTR) != 0;
	}

	/**
	 * ARM/AArch64 mapping symbols: {@code $d} (data), {@code $a}/{@code $t}/{@code $x} (code),
	 * optionally suffixed ({@code $d.0}). They mark code/data boundaries for disassemblers and are
	 * {@code STT_NOTYPE}, so the type check above lets them through -- they have to go by name.
	 */
	private static boolean isMappingSymbol(String name) {
		if (name.length() < 2 || name.charAt(0) != '$') {
			return false;
		}
		char kind = name.charAt(1);
		if (kind != 'd' && kind != 'a' && kind != 't' && kind != 'x') {
			return false;
		}
		return name.length() == 2 || name.charAt(2) == '.';
	}
	// Mach-O
	private static final int MH_MAGIC = 0xFEEDFACE;
	private static final int MH_MAGIC_64 = 0xFEEDFACF;
	private static final int MH_CIGAM = 0xCEFAEDFE;
	private static final int MH_CIGAM_64 = 0xCFFAEDFE;
	private static final int FAT_MAGIC = 0xCAFEBABE;
	private static final int FAT_CIGAM = 0xBEBAFECA;
	private static final int LC_SYMTAB = 0x2;
	private static final int N_STAB = 0xe0;
	private static final int N_TYPE = 0x0e;
	private static final int N_EXT = 0x01;
	private static final int N_SECT = 0xe;

	/**
	 * Whether the given exported-symbol set defines {@code symbol}, tolerating a single
	 * leading-underscore difference (Mach-O prefixes exported names with '_', ELF does not),
	 * so an ELF-style {@code Java_..._add} query also matches a Mach-O {@code _Java_..._add}.
	 */
	public static boolean defines(Set<String> exports, String symbol) {
		if (exports == null || symbol == null || symbol.isEmpty()) {
			return false;
		}
		if (exports.contains(symbol)) {
			return true;
		}
		if (exports.contains("_" + symbol)) {
			return true;
		}
		return symbol.startsWith("_") && exports.contains(symbol.substring(1));
	}

	/** Defined exported symbol names, or an empty set if the file can't be parsed. */
	public static Set<String> exportedSymbols(java.io.File file) {
		Set<String> out = new LinkedHashSet<>();
		if (file == null || !file.isFile()) {
			return out;
		}
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			byte[] magic = read(raf, 0, 4);
			if (magic == null) {
				return out;
			}
			int b0 = magic[0] & 0xFF, b1 = magic[1] & 0xFF, b2 = magic[2] & 0xFF, b3 = magic[3] & 0xFF;
			if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) {
				parseElf(raf, out, false, false);
			} else {
				int be = ((b0 & 0xFF) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFF);
				if (be == FAT_MAGIC || be == FAT_CIGAM) {
					parseFat(raf, be == FAT_MAGIC, out);
				} else {
					parseMachOAt(raf, 0, out);
				}
			}
		} catch (Exception ignored) {
			// never throw for malformed input
		}
		return out;
	}

	/**
	 * Symbols the library calls out to but does not define -- whatever it links against at
	 * runtime. The inverse of {@link #exportedSymbols}, and deliberately a separate query: folding
	 * imports into the exported set would make {@link #defines} claim a library defines a symbol
	 * it merely calls, and native-method resolution would then bind to the wrong {@code .so}.
	 *
	 * <p>ELF only. Mach-O undefined symbols are not collected -- the panel that consumes this is
	 * about Android libraries, and reporting an empty list is honest where reporting a partial one
	 * would not be.
	 */
	public static Set<String> importedSymbols(java.io.File file) {
		Set<String> out = new LinkedHashSet<>();
		if (file == null || !file.isFile()) {
			return out;
		}
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			byte[] magic = read(raf, 0, 4);
			if (magic == null || magic[0] != 0x7F || magic[1] != 0x45 || magic[2] != 0x4C
					|| magic[3] != 0x46) {
				return out;
			}
			parseElf(raf, out, true, false);
		} catch (Exception ignored) {
			// never throw for malformed input
		}
		return out;
	}

	/**
	 * Symbols this library publishes in its dynamic symbol table -- the surface another library or
	 * a {@code dlsym} call can reach. A strict subset of {@link #exportedSymbols}, which also
	 * unions {@code .symtab} and so includes purely internal functions an unstripped build happens
	 * to name.
	 *
	 * <p>ELF only, for the same reason {@link #importedSymbols} is.
	 */
	public static Set<String> dynamicExports(java.io.File file) {
		Set<String> out = new LinkedHashSet<>();
		if (file == null || !file.isFile()) {
			return out;
		}
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			byte[] magic = read(raf, 0, 4);
			if (magic == null || magic[0] != 0x7F || magic[1] != 0x45 || magic[2] != 0x4C
					|| magic[3] != 0x46) {
				return out;
			}
			parseElf(raf, out, false, true);
		} catch (Exception ignored) {
			// never throw for malformed input
		}
		return out;
	}

	// ---- ELF ----

	private static void parseElf(RandomAccessFile raf, Set<String> out, boolean undefinedOnly,
			boolean dynsymOnly) throws IOException {
		byte[] ident = read(raf, 0, 16);
		if (ident == null) {
			return;
		}
		boolean is64 = ident[4] == 2;
		boolean le = ident[5] == 1;
		ByteOrder order = le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

		long shoff;
		int shentsize, shnum;
		if (is64) {
			byte[] h = read(raf, 0, 64);
			if (h == null) {
				return;
			}
			ByteBuffer bb = ByteBuffer.wrap(h).order(order);
			shoff = bb.getLong(0x28);
			shentsize = bb.getShort(0x3A) & 0xFFFF;
			shnum = bb.getShort(0x3C) & 0xFFFF;
		} else {
			byte[] h = read(raf, 0, 52);
			if (h == null) {
				return;
			}
			ByteBuffer bb = ByteBuffer.wrap(h).order(order);
			shoff = bb.getInt(0x20) & 0xFFFFFFFFL;
			shentsize = bb.getShort(0x2E) & 0xFFFF;
			shnum = bb.getShort(0x30) & 0xFFFF;
		}
		if (shoff <= 0 || shnum <= 0 || shentsize <= 0 || shnum > 65535) {
			return;
		}

		byte[] shdrs = read(raf, shoff, shentsize * shnum);
		if (shdrs == null) {
			return;
		}
		ByteBuffer sh = ByteBuffer.wrap(shdrs).order(order);

		// Read BOTH the dynamic symbol table (.dynsym) and the static one (.symtab) when
		// present, unioning their defined names. Real Android .so almost always ship .dynsym;
		// an unstripped build may also carry .symtab with local/static functions the exported
		// scan alone would miss. (Ghidra's own FUN_xxxx names exist in neither table.)
		for (int i = 0; i < shnum; i++) {
			int type = sh.getInt(i * shentsize + 4);
			boolean wanted = dynsymOnly ? type == SHT_DYNSYM : (type == SHT_DYNSYM || type == SHT_SYMTAB);
			if (wanted) {
				readElfSymtab(raf, sh, i, shentsize, shnum, is64, order, out, undefinedOnly);
			}
		}
	}

	private static void readElfSymtab(RandomAccessFile raf, ByteBuffer sh, int symIdx, int shentsize,
			int shnum, boolean is64, ByteOrder order, Set<String> out, boolean undefinedOnly)
			throws IOException {
		long symOff, symSize, entSize;
		int strIdx;
		if (is64) {
			int base = symIdx * shentsize;
			symOff = sh.getLong(base + 0x18);
			symSize = sh.getLong(base + 0x20);
			strIdx = sh.getInt(base + 0x28);
			entSize = sh.getLong(base + 0x38);
		} else {
			int base = symIdx * shentsize;
			symOff = sh.getInt(base + 0x10) & 0xFFFFFFFFL;
			symSize = sh.getInt(base + 0x14) & 0xFFFFFFFFL;
			strIdx = sh.getInt(base + 0x18);
			entSize = sh.getInt(base + 0x24) & 0xFFFFFFFFL;
		}
		if (entSize <= 0 || symSize <= 0 || strIdx < 0 || strIdx >= shnum) {
			return;
		}

		long strOff, strSize;
		if (is64) {
			int base = strIdx * shentsize;
			strOff = sh.getLong(base + 0x18);
			strSize = sh.getLong(base + 0x20);
		} else {
			int base = strIdx * shentsize;
			strOff = sh.getInt(base + 0x10) & 0xFFFFFFFFL;
			strSize = sh.getInt(base + 0x14) & 0xFFFFFFFFL;
		}

		byte[] symtab = read(raf, symOff, (int) Math.min(symSize, Integer.MAX_VALUE));
		byte[] strtab = read(raf, strOff, (int) Math.min(strSize, Integer.MAX_VALUE));
		if (symtab == null || strtab == null) {
			return;
		}
		ByteBuffer st = ByteBuffer.wrap(symtab).order(order);
		int count = (int) (symSize / entSize);
		for (int i = 0; i < count; i++) {
			int off = (int) (i * entSize);
			int nameOff;
			int shndx;
			int info;
			if (is64) {
				nameOff = st.getInt(off);              // st_name
				info = st.get(off + 4) & 0xFF;         // st_info
				shndx = st.getShort(off + 6) & 0xFFFF; // st_shndx
			} else {
				nameOff = st.getInt(off);               // st_name
				info = st.get(off + 12) & 0xFF;         // st_info
				shndx = st.getShort(off + 14) & 0xFFFF; // st_shndx
			}
			boolean undefined = shndx == 0; // SHN_UNDEF -> linked in from elsewhere
			if (undefined != undefinedOnly) {
				continue;
			}
			// An undefined symbol has no section to inspect, so the executable-section test that
			// keeps data labels out of the defined set cannot apply -- an import is known by the
			// fact that something here calls it.
			if (!namesCode(info & 0xF, undefined || isExecSection(sh, shentsize, shnum, is64, shndx))) {
				continue; // data, sections, file names -- not something you can open
			}
			String name = cString(strtab, nameOff);
			if (name != null && !name.isEmpty() && !isMappingSymbol(name)) {
				out.add(name);
			}
		}
	}

	// ---- Mach-O ----

	private static void parseFat(RandomAccessFile raf, boolean bigEndian, Set<String> out) throws IOException {
		byte[] fh = read(raf, 0, 8);
		if (fh == null) {
			return;
		}
		ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
		ByteBuffer bb = ByteBuffer.wrap(fh).order(order);
		int nfat = bb.getInt(4);
		if (nfat <= 0 || nfat > 64) {
			return;
		}
		byte[] arch = read(raf, 8, 20); // first fat_arch (cputype,cpusubtype,offset,size,align)
		if (arch == null) {
			return;
		}
		long offset = ByteBuffer.wrap(arch).order(order).getInt(8) & 0xFFFFFFFFL;
		parseMachOAt(raf, offset, out);
	}

	private static void parseMachOAt(RandomAccessFile raf, long base, Set<String> out) throws IOException {
		byte[] m = read(raf, base, 4);
		if (m == null) {
			return;
		}
		int raw = ((m[0] & 0xFF) << 24) | ((m[1] & 0xFF) << 16) | ((m[2] & 0xFF) << 8) | (m[3] & 0xFF);
		boolean is64;
		boolean le;
		if (raw == MH_MAGIC_64) { is64 = true; le = false; }
		else if (raw == MH_CIGAM_64) { is64 = true; le = true; }
		else if (raw == MH_MAGIC) { is64 = false; le = false; }
		else if (raw == MH_CIGAM) { is64 = false; le = true; }
		else { return; }
		ByteOrder order = le ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

		int headerSize = is64 ? 32 : 28;
		byte[] hdr = read(raf, base, headerSize);
		if (hdr == null) {
			return;
		}
		ByteBuffer hb = ByteBuffer.wrap(hdr).order(order);
		int ncmds = hb.getInt(16);
		int sizeofcmds = hb.getInt(20);
		if (ncmds <= 0 || sizeofcmds <= 0 || sizeofcmds > 64 * 1024 * 1024) {
			return;
		}

		byte[] cmds = read(raf, base + headerSize, sizeofcmds);
		if (cmds == null) {
			return;
		}
		ByteBuffer cb = ByteBuffer.wrap(cmds).order(order);
		int pos = 0;
		for (int i = 0; i < ncmds && pos + 8 <= cmds.length; i++) {
			int cmd = cb.getInt(pos);
			int cmdsize = cb.getInt(pos + 4);
			if (cmdsize < 8) {
				break;
			}
			if (cmd == LC_SYMTAB && pos + 24 <= cmds.length) {
				long symoff = cb.getInt(pos + 8) & 0xFFFFFFFFL;
				int nsyms = cb.getInt(pos + 12);
				long stroff = cb.getInt(pos + 16) & 0xFFFFFFFFL;
				int strsize = cb.getInt(pos + 20);
				readMachSymbols(raf, base, symoff, nsyms, stroff, strsize, is64, order, out);
			}
			pos += cmdsize;
		}
	}

	private static void readMachSymbols(RandomAccessFile raf, long base, long symoff, int nsyms,
			long stroff, int strsize, boolean is64, ByteOrder order, Set<String> out) throws IOException {
		if (nsyms <= 0 || nsyms > 5_000_000 || strsize <= 0) {
			return;
		}
		int entSize = is64 ? 16 : 12;
		byte[] symtab = read(raf, base + symoff, entSize * nsyms);
		byte[] strtab = read(raf, base + stroff, strsize);
		if (symtab == null || strtab == null) {
			return;
		}
		ByteBuffer sb = ByteBuffer.wrap(symtab).order(order);
		for (int i = 0; i < nsyms; i++) {
			int off = i * entSize;
			int nStrx = sb.getInt(off);
			int nType = sb.get(off + 4) & 0xFF;
			if ((nType & N_STAB) != 0) {
				continue; // debug symbol
			}
			boolean external = (nType & N_EXT) != 0;
			boolean defined = (nType & N_TYPE) == N_SECT;
			if (external && defined) {
				String name = cString(strtab, nStrx);
				if (name != null && !name.isEmpty()) {
					out.add(name);
				}
			}
		}
	}

	// ---- helpers ----

	private static byte[] read(RandomAccessFile raf, long offset, int len) throws IOException {
		if (len <= 0 || offset < 0 || offset >= raf.length()) {
			return null;
		}
		int safeLen = (int) Math.min(len, raf.length() - offset);
		byte[] buf = new byte[safeLen];
		raf.seek(offset);
		raf.readFully(buf);
		return buf;
	}

	private static String cString(byte[] tab, int off) {
		if (off < 0 || off >= tab.length) {
			return null;
		}
		int end = off;
		while (end < tab.length && tab[end] != 0) {
			end++;
		}
		return new String(tab, off, end - off, java.nio.charset.StandardCharsets.UTF_8);
	}
}
