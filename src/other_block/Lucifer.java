package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Lucifer {

    private static final int ROUNDS = 16;

    // 128-bit key = 4 integers
    private final int[] key;

    public Lucifer(int[] key) {

        if (key.length != 4) {
            throw new IllegalArgumentException("Key must contain 4 integers");
        }

        this.key = key;
    }

    // ================= F FUNCTION =================
    private int F(int half, int roundKey) {

        int x = half ^ roundKey;

        x = Integer.rotateLeft(x, 3);

        x = (x + 0x9E3779B9);

        x ^= (x >>> 16);

        return x;
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] data) {

        int len = ((data.length + 7) / 8) * 8;

        byte[] padded = Arrays.copyOf(data, len);

        if (data.length < padded.length) {
            padded[data.length] = 1;
        }

        for (int i = 0; i < padded.length; i += 8) {

            int left = bytesToInt(padded, i);

            int right = bytesToInt(padded, i + 4);

            for (int r = 0; r < ROUNDS; r++) {

                int temp = right;

                right = left ^ F(right, key[r % 4]);

                left = temp;
            }

            intToBytes(left, padded, i);

            intToBytes(right, padded, i + 4);
        }

        return padded;
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] data) {

        byte[] result = Arrays.copyOf(data, data.length);

        for (int i = 0; i < result.length; i += 8) {

            int left = bytesToInt(result, i);

            int right = bytesToInt(result, i + 4);

            for (int r = ROUNDS - 1; r >= 0; r--) {

                int temp = left;

                left = right ^ F(left, key[r % 4]);

                right = temp;
            }

            intToBytes(left, result, i);

            intToBytes(right, result, i + 4);
        }

        // remove padding
        int end = result.length;

        while (end > 0 && result[end - 1] == 0) {
            end--;
        }

        if (end > 0 && result[end - 1] == 1) {
            end--;
        }

        return Arrays.copyOf(result, end);
    }

    // ================= HELPERS =================
    private int bytesToInt(byte[] b, int offset) {

        return ByteBuffer.wrap(b, offset, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();
    }

    private void intToBytes(int value, byte[] b, int offset) {

        ByteBuffer.wrap(b, offset, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(value);
    }

    // ================= DEMO =================
    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        Lucifer lucifer = new Lucifer(key);

        String text = "HELLO LUCIFER";

        byte[] encrypted = lucifer.encrypt(text.getBytes());

        byte[] decrypted = lucifer.decrypt(encrypted);

        System.out.println("Original:  " + text);

        System.out.println("Encrypted: " +
                Arrays.toString(encrypted));

        System.out.println("Decrypted: " +
                new String(decrypted));
    }
}