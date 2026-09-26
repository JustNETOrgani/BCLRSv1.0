package bclrspaper;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Java re-implementation of Solidity's abi.encode(...) for exactly the
 * argument-type combinations RingSignatureService needs to interoperate
 * with BscfRSscheme.sol's abi.encode-based hash preimages (encodeUserList,
 * deriveHEv, deriveC, deriveChainChallenge, deriveHAsPrime).
 *
 * Only supports the specific static/dynamic type combinations actually
 * used here (uint256, bytes, string, string[]) - not a general-purpose
 * ABI library.
 */
public final class AbiEncoder {
    private AbiEncoder() {}

    // -------------------------------------------------------------------
    // Tagged argument types for the top-level abi.encode(...) argument list
    // -------------------------------------------------------------------
    public abstract static class Arg {
        abstract boolean isDynamic();
    }

    public static final class Uint256Arg extends Arg {
        final BigInteger value;
        public Uint256Arg(BigInteger value) { this.value = value; }
        boolean isDynamic() { return false; }
    }

    public static final class BytesArg extends Arg {
        final byte[] value;
        public BytesArg(byte[] value) { this.value = value; }
        boolean isDynamic() { return true; }
    }

    public static final class StringArg extends Arg {
        final String value;
        public StringArg(String value) { this.value = value; }
        boolean isDynamic() { return true; }
    }

    public static final class StringArrayArg extends Arg {
        final String[] value;
        public StringArrayArg(String[] value) { this.value = value; }
        boolean isDynamic() { return true; }
    }

    // Convenience factory methods, so call sites read like the Solidity
    // abi.encode(...) argument list they mirror.
    public static Uint256Arg u(BigInteger v) { return new Uint256Arg(v); }
    public static Uint256Arg u(long v) { return new Uint256Arg(BigInteger.valueOf(v)); }
    public static BytesArg b(byte[] v) { return new BytesArg(v); }
    public static StringArg s(String v) { return new StringArg(v); }
    public static StringArrayArg sArr(String[] v) { return new StringArrayArg(v); }

    // -------------------------------------------------------------------
    // Low-level encoding primitives
    // -------------------------------------------------------------------

    /** Right-pads with zero bytes to the next multiple of 32, matching
     * Solidity's ABI padding rule for dynamic byte data. */
    private static byte[] pad32(byte[] data) {
        int rem = data.length % 32;
        if (rem == 0) {
            return data;
        }
        byte[] padded = new byte[data.length + (32 - rem)];
        System.arraycopy(data, 0, padded, 0, data.length);
        return padded; // remaining bytes already zero by Java array default
    }

    /** Encodes a non-negative BigInteger as a 32-byte big-endian word. */
    private static byte[] encodeUint256(BigInteger v) {
        byte[] raw = v.toByteArray(); // may have a leading 0x00 sign byte, or be shorter than 32
        byte[] out = new byte[32];
        // Copy the significant bytes into the low-order end of the 32-byte word.
        int srcStart = Math.max(0, raw.length - 32);
        int copyLen = raw.length - srcStart;
        System.arraycopy(raw, srcStart, out, 32 - copyLen, copyLen);
        return out;
    }

    /** [32-byte length][data right-padded to a 32-byte multiple]. */
    private static byte[] encodeDynamicBytes(byte[] data) {
        byte[] lenWord = encodeUint256(BigInteger.valueOf(data.length));
        byte[] padded = pad32(data);
        byte[] out = new byte[lenWord.length + padded.length];
        System.arraycopy(lenWord, 0, out, 0, lenWord.length);
        System.arraycopy(padded, 0, out, lenWord.length, padded.length);
        return out;
    }

    private static byte[] encodeDynamicString(String str) {
        return encodeDynamicBytes(str.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encoding of a bare string[] value's own content (used as the tail
     * content for encodeUserList's single top-level argument). Structure:
     *   [32-byte array length]
     *   [n head slots: offset of each element's own encoding, relative to
     *    right after the length word]
     *   [n element encodings, each itself [len][data-padded]]
     */
    private static byte[] encodeStringArrayContent(String[] arr) throws java.io.IOException {
        int n = arr.length;
        byte[][] elementEncodings = new byte[n][];
        for (int i = 0; i < n; i++) {
            elementEncodings[i] = encodeDynamicString(arr[i]);
        }
        long headSize = 32L * n;
        long running = headSize;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(encodeUint256(BigInteger.valueOf(n)));
        for (byte[] enc : elementEncodings) {
            out.write(encodeUint256(BigInteger.valueOf(running)));
            running += enc.length;
        }
        for (byte[] enc : elementEncodings) {
            out.write(enc);
        }
        return out.toByteArray();
    }

    private static byte[] encodeDynamicContent(Arg arg) throws java.io.IOException {
        if (arg instanceof BytesArg) {
            return encodeDynamicBytes(((BytesArg) arg).value);
        }
        if (arg instanceof StringArg) {
            return encodeDynamicString(((StringArg) arg).value);
        }
        if (arg instanceof StringArrayArg) {
            return encodeStringArrayContent(((StringArrayArg) arg).value);
        }
        throw new IllegalArgumentException("not a dynamic arg: " + arg.getClass());
    }

    // -------------------------------------------------------------------
    // General abi.encode(...) for a top-level argument list
    // -------------------------------------------------------------------

    /**
     * General Solidity abi.encode(...) for an ordered list of top-level
     * arguments, each either static (Uint256Arg) or dynamic (BytesArg /
     * StringArg / StringArrayArg). Implements the standard head/tail ABI
     * encoding: every argument gets one 32-byte head slot (the value
     * itself if static, or a byte-offset into the tail if dynamic);
     * dynamic arguments' actual content is appended to the tail, in
     * argument order, after all head slots.
     */
    public static byte[] encode(List<Arg> args) throws java.io.IOException {
        int n = args.size();
        long headSize = 32L * n;
        byte[][] headParts = new byte[n][];
        List<byte[]> tailParts = new ArrayList<>();
        long runningTailOffset = headSize;

        for (int i = 0; i < n; i++) {
            Arg arg = args.get(i);
            if (arg instanceof Uint256Arg) {
                headParts[i] = encodeUint256(((Uint256Arg) arg).value);
            } else {
                byte[] content = encodeDynamicContent(arg);
                headParts[i] = encodeUint256(BigInteger.valueOf(runningTailOffset));
                tailParts.add(content);
                runningTailOffset += content.length;
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : headParts) {
            out.write(part);
        }
        for (byte[] part : tailParts) {
            out.write(part);
        }
        return out.toByteArray();
    }

    /** Varargs convenience wrapper around {@link #encode(List)}. */
    public static byte[] encode(Arg... args) throws java.io.IOException {
        List<Arg> list = new ArrayList<>();
        for (Arg a : args) {
            list.add(a);
        }
        return encode(list);
    }
}
