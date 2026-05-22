package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class XTEA {

    private static final int DELTA = 0x9E3779B9;
    private static final int ROUNDS = 32;

    private final int[] key;

    public XTEA(int[] key) {
        if (key.length != 4) {
            throw new IllegalArgumentException("Key must be 128-bit (4 ints)");
        }
        this.key = key;
    }

    private void encipher(int[] v) {
        int v0 = v[0], v1 = v[1];
        int sum = 0;

        for (int i = 0; i < ROUNDS; i++) {
            v0 += (((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += DELTA;
            v1 += (((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3]);
        }

        v[0] = v0;
        v[1] = v1;
    }

    private void decipher(int[] v) {
        int v0 = v[0], v1 = v[1];
        int sum = DELTA * ROUNDS;

        for (int i = 0; i < ROUNDS; i++) {
            v1 -= (((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3]);
            sum -= DELTA;
            v0 -= (((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3]);
        }

        v[0] = v0;
        v[1] = v1;
    }

    private void blockToInts(byte[] b, int offset, int[] out) {
        ByteBuffer bb = ByteBuffer.wrap(b, offset, 8).order(ByteOrder.BIG_ENDIAN);
        out[0] = bb.getInt();
        out[1] = bb.getInt();
    }

    private void intsToBlock(int[] in, byte[] b, int offset) {
        ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        bb.putInt(in[0]).putInt(in[1]);
        System.arraycopy(bb.array(), 0, b, offset, 8);
    }

    public byte[] encrypt(byte[] data) {
        int len = ((data.length + 7) / 8) * 8;
        byte[] padded = Arrays.copyOf(data, len);

        if (data.length < padded.length) {
            padded[data.length] = 1;
        }

        int[] block = new int[2];

        for (int i = 0; i < padded.length; i += 8) {
            blockToInts(padded, i, block);
            encipher(block);
            intsToBlock(block, padded, i);
        }

        return padded;
    }

    public byte[] decrypt(byte[] data) {
        int[] block = new int[2];

        for (int i = 0; i < data.length; i += 8) {
            blockToInts(data, i, block);
            decipher(block);
            intsToBlock(block, data, i);
        }

        // remove padding (0x01 and trailing zeros)
        int end = data.length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        if (end > 0 && data[end - 1] == 1) {
            end--;
        }

        return Arrays.copyOf(data, end);
    }

    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        XTEA xtea = new XTEA(key);

        String text = "HelloXTEA!1234";
        byte[] data = text.getBytes();

        byte[] enc = xtea.encrypt(data);
        byte[] dec = xtea.decrypt(enc);

        System.out.println("Original: " + text);
        System.out.println("Encrypted: " + Arrays.toString(enc));
        System.out.println("Decrypted: " + new String(dec));
    }
}