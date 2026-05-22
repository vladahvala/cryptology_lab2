package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class LOKI97 {

    private static final int ROUNDS = 16;

    private final int[] key; // 128-bit key (4 ints)

    public LOKI97(int[] key) {
        if (key.length != 4) {
            throw new IllegalArgumentException("Key must be 128-bit (4 ints)");
        }
        this.key = key;
    }

    // ================= ROUND FUNCTION =================
    private int F(int x, int k) {
        x ^= k;
        x = Integer.rotateLeft(x, 11);
        x = (x * 0x9E3779B1);
        return x ^ (x >>> 16);
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] block) {

        int[] v = toInts(block);
        int L = v[0], R = v[1];

        for (int i = 0; i < ROUNDS; i++) {

            int temp = R;

            R = L ^ F(R, key[i % 4]);
            L = temp;

        }

        return toBytes(new int[] { L, R });
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] block) {

        int[] v = toInts(block);
        int L = v[0], R = v[1];

        for (int i = ROUNDS - 1; i >= 0; i--) {

            int temp = L;

            L = R ^ F(L, key[i % 4]);
            R = temp;

        }

        return toBytes(new int[] { L, R });
    }

    // ================= HELPERS =================
    private int[] toInts(byte[] b) {
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        return new int[] {
                bb.getInt(),
                bb.getInt()
        };
    }

    private byte[] toBytes(int[] v) {
        ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        bb.putInt(v[0]).putInt(v[1]);
        return bb.array();
    }

    // ================= DEMO =================
    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        LOKI97 loki = new LOKI97(key);

        String text = "LOKI97!!"; // 8 bytes
        byte[] data = Arrays.copyOf(text.getBytes(), 8);

        byte[] enc = loki.encrypt(data);
        byte[] dec = loki.decrypt(enc);

        System.out.println("Original:  " + text);
        System.out.println("Encrypted: " + Arrays.toString(enc));
        System.out.println("Decrypted: " + new String(dec));
    }
}