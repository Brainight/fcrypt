package com.brainache.fcrypt.utils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * Note: Java saves data in Big Endian...
 *
 * @author Brainight
 */
public class ByteGod {

    public enum Endianes {
        BIG,
        LITTLE
    }

    public static int bytesToIntBE(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24
                | (bytes[1] & 0xFF) << 16
                | (bytes[2] & 0xFF) << 8
                | (bytes[3] & 0xFF) << 0);
    }

    public static byte[] intToBytesBE(final int num) {
        return new byte[]{
            (byte) ((num >> 24) & 0xFF),
            (byte) ((num >> 16) & 0xFF),
            (byte) ((num >> 8) & 0xFF),
            (byte) ((num >> 0) & 0xFF)
        };
    }

    public static byte[] intTo3BytesBE(final int num) {
        return new byte[]{
            (byte) ((num >> 16) & 0XFF),
            (byte) ((num >> 8) & 0xFF),
            (byte) ((num >> 0) & 0xFF)
        };
    }

    public static byte[] unsignedShortToBytesBE(final char num) {
        return new byte[]{
            (byte) ((num >> 8) & 0xFF),
            (byte) ((num >> 0) & 0xFF)
        };
    }

    public static byte[] charArrayToByteArrayBE(char[] array) {
        byte[] b = new byte[array.length * 2];
        for (int i = 0, j = 0; i < array.length; j += 2, i++) {
            b[j] = (byte) ((array[i] >> 8) & 0XFF);
            b[j + 1] = (byte) (array[i] & 0XFF);
        }
        return b;
    }

    public static byte[] charArrayToByteArrayBE255(char[] array) {
        byte[] data = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            data[i] = (byte) array[i];
        }
        return data;
    }

    public static char[] byteArrayToCharArrayBE(byte[] array) {
        if ((array.length & 0x01) == 1) {
            return new char[]{(char) array[0]};
        }

        char[] c = new char[array.length / 2];
        for (int i = 0, j = 0; i < array.length / 2; i++, j += 2) {
            c[i] = (char) (array[j] + array[j + 1]);
        }
        return c;
    }

    public static char[] byteArrayToCharArrayBE255(byte[] array) {

        char[] c = new char[array.length];
        for (int i = 0; i < array.length; i++) {
            c[i] = (char) (array[i]);
        }
        return c;
    }

    public static byte[] getSecureRandomBytes(int length) {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return bytes;
    }

    public static void getSecureRandomBytes(byte[] buffer) {
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(buffer);

    }

    public static String getNumberInMB(int num) {
        StringBuilder sb = new StringBuilder();
        int v = num / 1024;
        int r = num % 1024;

        sb.append(v + "GB | ");
        v = r % 1024;
        r = v % 1024;
        sb.append(v + "MB | ");
        v = r % 1024;
        r = v % 1024;
        sb.append(v + "KB |");
        v = r % 1024;
        r = v % 1024;
        sb.append(v + "B");

        return sb.toString();
    }

    public static ByteBuffer[] getByteBuffersForSize(long size) {
        List<ByteBuffer> buffers = new ArrayList<>();
        do {
            if (size > Integer.MAX_VALUE) {
                buffers.add(ByteBuffer.allocate(Integer.MAX_VALUE));
                size -= Integer.MAX_VALUE;
            } else {
                buffers.add(ByteBuffer.allocate((int) size));
                size = 0;
            }
        } while (size > 0);
        return (ByteBuffer[]) buffers.toArray();
    }

    public static void zeroOut(byte[] array) {
        Arrays.fill(array, 0, array.length, (byte) 0x00);
    }

    public static void zeroOut(char[] array) {
        Arrays.fill(array, 0, array.length, (char) 0x00);
    }

    // ###############   E N C O D I N G    H A N D L I N G   ##################
    // ### HEX 
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    private static final String HEX_STR = "0123456789ABCDEF";

    /**
     * Returns UTF-8 String.
     *
     * @param bytes
     * @return
     */
    public static String toHexString(byte[] bytes) {
        byte[] hexChars = toHex(bytes);
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public static byte[] toHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int i = 0, k = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[k++] = HEX_ARRAY[v >>> 4];
            hexChars[k++] = HEX_ARRAY[v & 0x0F];
        }
        return hexChars;
    }

    public static byte[] fromHex(String hexString) {

        char[] hexChar = hexString.toCharArray();
        byte[] result = new byte[hexChar.length >>> 1];
        for (int i = 0, k = 0; i < hexChar.length >>> 1; i++, k += 2) {
            result[i] = (byte) ((HEX_STR.indexOf(hexChar[k]) << 4) + (HEX_STR.indexOf(hexChar[k + 1]) & 0x0F));
        }

        return result;
    }

    // #### BASE64 (UTF-8)
    public static final byte PADDING_BYTE = "=".getBytes(StandardCharsets.UTF_8)[0];
    public static final String B64_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    public static final byte[] B64_ARRAY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes(StandardCharsets.UTF_8);

    public static byte[] encodeB64(byte[] bytes, boolean padded) {

        if (bytes == null || bytes.length == 0) {
            return new byte[0];
        }
        float fl = bytes.length * 1.3333f;
        int length = ((int) fl) + ((fl == (int) fl) ? 0 : 1);

        int forLength = (length / 4) + ((length & 3) == 0 ? 0 : 1);
//      float ffL = length / 4;
//      int forLength = ((int)ffL) + ((ffL == (int)ffL) ? 0 : 1);

        int lengthCheck = length - 1;

        if (padded) {
            int rem = (length & 0b11);
            length += (rem == 3 || rem == 1) ? 1 : rem;
        }

        byte[] b64result = new byte[length];
        for (int i = 0, bc = 0, k = 0, v = 0, hv = 0; i < forLength; i++) {

            v = bytes[k++] & 0xFF;

            b64result[bc++] = B64_ARRAY[v >>> 2];

            hv = (v & 0b11) << 4;
            if (bc < lengthCheck) {
                v = bytes[k++] & 0xFF;
                b64result[bc++] = B64_ARRAY[hv | v >>> 4];
            } else {
                b64result[bc++] = B64_ARRAY[hv];
                if (padded) {
                    b64result[bc++] = PADDING_BYTE;
                    b64result[bc] = PADDING_BYTE;
                }
                break;
            }

            hv = (v & 0b1111) << 2;
            if (bc < lengthCheck) {
                v = bytes[k++] & 0xFF;
                b64result[bc++] = B64_ARRAY[hv | v >>> 6];
            } else {
                b64result[bc++] = B64_ARRAY[hv];
                if (padded) {
                    b64result[bc] = PADDING_BYTE;
                }
                break;
            }

            b64result[bc++] = B64_ARRAY[v & 0b111111];
        }

        return b64result;
    }

    public static byte[] decodeB64(String b64) {
        return decodeB64(b64.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decodeB64(char[] b64) {
        return decodeB64(ByteGod.charArrayToByteArrayBE(b64));
    }

    public static byte[] decodeB64(byte[] b64) {
        if (b64 == null || b64.length < 2) {
            return new byte[]{};
        }

        int b64Length = b64.length;
        int paddingLength = 0;
        if (b64[b64Length - 2] == ((byte) '=') && b64[b64Length - 1] == ((byte) '=')) {
            paddingLength = 2;
        } else if (b64[b64Length - 1] == ((byte) '=')) {
            paddingLength = 1;
        } else {
            paddingLength = 0;
        }

        int noPaddingLength = b64.length - paddingLength;
        int resLength = (int) (noPaddingLength / 1.3333f);
        byte[] data = new byte[resLength];

        int index = 0;
        int b0 = 0;
        int b1 = 0;

        for (int i = 0, k = 0; i < resLength;) {

            if (i >= resLength) {
                break;
            }

            index = getIndex((char) b64[k], B64_STR, k);

            b0 = index << 2;
            index = getIndex((char) b64[++k], B64_STR, k);
            b1 = index >>> 4;
            data[i++] = (byte) (b0 | b1);

            if (i >= resLength) {
                break;
            }

            b0 = (index & 0b1111) << 4;
            index = getIndex((char) b64[++k], B64_STR, k);
            b1 = index >>> 2;
            data[i++] = (byte) (b0 | b1);

            if (i >= resLength) {
                break;
            }

            b0 = (index & 0b11) << 6;
            b1 = getIndex((char) b64[++k], B64_STR, k);
            data[i++] = (byte) (b0 | b1);
            k++;

        }

        return data;
    }

    private static int getIndex(char c, String source, int indexOfChar) {
        int index = -1;
        index = B64_STR.indexOf(c);
        if (index == -1) {
            throw new IllegalArgumentException("Illegal char '" + c + "' encountered at index " + indexOfChar);
        }

        return index;
    }

    public static int getB64LengthForInputLength(int inputLength, boolean padded) {
        float fl = inputLength * 1.3333f;
        int length = ((int) fl) + ((fl == (int) fl) ? 0 : 1);

        if (padded) {
            length += (length & 0b11);
        }

        return length;
    }

    // ##############################################################
}
