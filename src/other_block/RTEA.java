package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class RTEA {

    private static final int DELTA = 0x9E3779B9;
    private static final int ROUNDS = 32;

    private final int[] key; // 128-bit = 4 ints

    public RTEA(int[] key) {
        if (key.length != 4) {
            throw new IllegalArgumentException("Key must be 128-bit (4 ints)");
        }
        this.key = key;
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] data) {

        int len = ((data.length + 7) / 8) * 8;
        byte[] padded = Arrays.copyOf(data, len);

        if (data.length < padded.length) {
            padded[data.length] = 1; // simple padding
        }

        for (int i = 0; i < padded.length; i += 8) {
            int v0 = bytesToInt(padded, i);
            int v1 = bytesToInt(padded, i + 4);

            int sum = 0;

            for (int r = 0; r < ROUNDS; r++) {
                v0 += (((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3]);
                sum += DELTA;
                v1 += (((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3]);
            }

            intToBytes(v0, padded, i);
            intToBytes(v1, padded, i + 4);
        }

        return padded;
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] data) {

        for (int i = 0; i < data.length; i += 8) {
            int v0 = bytesToInt(data, i);
            int v1 = bytesToInt(data, i + 4);

            int sum = DELTA * ROUNDS;

            for (int r = 0; r < ROUNDS; r++) {
                v1 -= (((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3]);
                sum -= DELTA;
                v0 -= (((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3]);
            }

            intToBytes(v0, data, i);
            intToBytes(v1, data, i + 4);
        }

        // remove padding
        int end = data.length;
        while (end > 0 && data[end - 1] == 0)
            end--;
        if (end > 0 && data[end - 1] == 1)
            end--;

        return Arrays.copyOf(data, end);
    }

    // ================= HELPERS =================
    private int bytesToInt(byte[] b, int offset) {
        return ByteBuffer.wrap(b, offset, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();
    }

    private void intToBytes(int v, byte[] b, int offset) {
        ByteBuffer.wrap(b, offset, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(v);
    }

    // ================= DEMO =================
    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        RTEA rte = new RTEA(key);

        String text = "HELLO RTEA";
        byte[] data = text.getBytes();

        byte[] enc = rte.encrypt(data);
        byte[] dec = rte.decrypt(enc);

        System.out.println("Original:  " + text);
        System.out.println("Encrypted: " + Arrays.toString(enc));
        System.out.println("Decrypted: " + new String(dec));
    }
}