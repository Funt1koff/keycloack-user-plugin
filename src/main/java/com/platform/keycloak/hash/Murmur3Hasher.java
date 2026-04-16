package com.platform.keycloak.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

final class Murmur3Hasher {
    private static final long C1 = 0x87c37b91114253d5L;
    private static final long C2 = 0x4cf5ad432745937fL;

    private Murmur3Hasher() {
    }

    static String hashUuid(String input) {
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        long[] hash = murmur3_x64_128(data, 0);
        String hex = String.format("%016x%016x", hash[0], hash[1]);
        return hex.substring(0, 8)
            + "-" + hex.substring(8, 12)
            + "-" + hex.substring(12, 16)
            + "-" + hex.substring(16, 20)
            + "-" + hex.substring(20, 32);
    }

    private static long[] murmur3_x64_128(byte[] data, int seed) {
        long h1 = seed;
        long h2 = seed;
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        while (buffer.remaining() >= 16) {
            long k1 = buffer.getLong();
            long k2 = buffer.getLong();

            k1 *= C1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= C2;
            h1 ^= k1;

            h1 = Long.rotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729L;

            k2 *= C2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= C1;
            h2 ^= k2;

            h2 = Long.rotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5L;
        }

        long k1 = 0L;
        long k2 = 0L;
        int tailStart = buffer.position();
        int remaining = data.length - tailStart;

        switch (remaining) {
            case 15:
                k2 ^= ((long) data[tailStart + 14] & 0xffL) << 48;
            case 14:
                k2 ^= ((long) data[tailStart + 13] & 0xffL) << 40;
            case 13:
                k2 ^= ((long) data[tailStart + 12] & 0xffL) << 32;
            case 12:
                k2 ^= ((long) data[tailStart + 11] & 0xffL) << 24;
            case 11:
                k2 ^= ((long) data[tailStart + 10] & 0xffL) << 16;
            case 10:
                k2 ^= ((long) data[tailStart + 9] & 0xffL) << 8;
            case 9:
                k2 ^= ((long) data[tailStart + 8] & 0xffL);
                k2 *= C2;
                k2 = Long.rotateLeft(k2, 33);
                k2 *= C1;
                h2 ^= k2;
            case 8:
                k1 ^= ((long) data[tailStart + 7] & 0xffL) << 56;
            case 7:
                k1 ^= ((long) data[tailStart + 6] & 0xffL) << 48;
            case 6:
                k1 ^= ((long) data[tailStart + 5] & 0xffL) << 40;
            case 5:
                k1 ^= ((long) data[tailStart + 4] & 0xffL) << 32;
            case 4:
                k1 ^= ((long) data[tailStart + 3] & 0xffL) << 24;
            case 3:
                k1 ^= ((long) data[tailStart + 2] & 0xffL) << 16;
            case 2:
                k1 ^= ((long) data[tailStart + 1] & 0xffL) << 8;
            case 1:
                k1 ^= ((long) data[tailStart] & 0xffL);
                k1 *= C1;
                k1 = Long.rotateLeft(k1, 31);
                k1 *= C2;
                h1 ^= k1;
            default:
                break;
        }

        h1 ^= data.length;
        h2 ^= data.length;

        h1 += h2;
        h2 += h1;

        h1 = fmix64(h1);
        h2 = fmix64(h2);

        h1 += h2;
        h2 += h1;

        return new long[] {h1, h2};
    }

    private static long fmix64(long k) {
        k ^= k >>> 33;
        k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33;
        k *= 0xc4ceb9fe1a85ec53L;
        k ^= k >>> 33;
        return k;
    }
}
