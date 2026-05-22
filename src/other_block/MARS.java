package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;

public class MARS {

    private static final int ROUNDS = 8;

    private final int[] key; // 4 × 32-bit слова

    public MARS(int[] key) {
        if (key.length != 4) {
            throw new IllegalArgumentException("Key must be 128-bit (4 ints)");
        }
        this.key = key;
    }

    // -------- basic round function (імітація S-box + mixing) --------
    private int F(int x, int k) {
        return Integer.rotateLeft(x + k, 7) ^ (x >>> 3);
    }

    // -------- encrypt 64-bit block --------
    private void encryptBlock(int[] v) {
        int a = v[0], b = v[1], c = v[2], d = v[3];

        for (int i = 0; i < ROUNDS; i++) {

            int ka = key[i % 4];

            // forward mixing (як у теорії Feistel-like MARS)
            a += F(b, ka);
            c ^= F(d, ka);
            b += F(c, ka);
            d ^= F(a, ka);

            // rotation (як описано в теорії)
            int tmp = a;
            a = b;
            b = c;
            c = d;
            d = tmp;
        }

        // final whitening
        v[0] = a ^ key[0];
        v[1] = b + key[1];
        v[2] = c + key[2];
        v[3] = d ^ key[3];
    }

    // -------- decrypt --------
    private void decryptBlock(int[] v) {
        int a = v[0] ^ key[0];
        int b = v[1] - key[1];
        int c = v[2] - key[2];
        int d = v[3] ^ key[3];

        for (int i = ROUNDS - 1; i >= 0; i--) {

            int ka = key[i % 4];

            // reverse rotation
            int tmp = d;
            d = c;
            c = b;
            b = a;
            a = tmp;

            d ^= F(a, ka);
            b -= F(c, ka);
            c ^= F(d, ka);
            a -= F(b, ka);
        }

        v[0] = a;
        v[1] = b;
        v[2] = c;
        v[3] = d;
    }

    // -------- utils --------
    private int[] bytesToInts(byte[] data, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(data, offset, 16)
                .order(ByteOrder.BIG_ENDIAN);

        return new int[] {
                bb.getInt(),
                bb.getInt(),
                bb.getInt(),
                bb.getInt()
        };
    }

    private void intsToBytes(int[] in, byte[] data, int offset) {
        ByteBuffer bb = ByteBuffer.allocate(16)
                .order(ByteOrder.BIG_ENDIAN);

        bb.putInt(in[0]).putInt(in[1]).putInt(in[2]).putInt(in[3]);

        System.arraycopy(bb.array(), 0, data, offset, 16);
    }

    // -------- public API --------
    public byte[] encrypt(byte[] data) {

        int len = ((data.length + 15) / 16) * 16;
        byte[] padded = Arrays.copyOf(data, len);

        if (data.length < padded.length) {
            padded[data.length] = 1; // padding 0x01
        }

        int[] block = new int[4];

        for (int i = 0; i < padded.length; i += 16) {
            block = bytesToInts(padded, i);
            encryptBlock(block);
            intsToBytes(block, padded, i);
        }

        return padded;
    }

    public byte[] decrypt(byte[] data) {

        int[] block = new int[4];

        for (int i = 0; i < data.length; i += 16) {
            block = bytesToInts(data, i);
            decryptBlock(block);
            intsToBytes(block, data, i);
        }

        int end = data.length;
        while (end > 0 && data[end - 1] == 0)
            end--;
        if (end > 0 && data[end - 1] == 1)
            end--;

        return Arrays.copyOf(data, end);
    }

    // -------- demo --------
    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        MARS mars = new MARS(key);

        String text = "Hello MARS crypto!";
        byte[] data = text.getBytes();

        byte[] enc = mars.encrypt(data);
        byte[] dec = mars.decrypt(enc);

        System.out.println("Original: " + text);
        System.out.println("Encrypted (Base64): " +
                Base64.getEncoder().encodeToString(enc));
        System.out.println("Decrypted: " + new String(dec));
    }
}