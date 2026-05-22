package other_block;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CLEFIA {

    private static final int BLOCK_SIZE = 16;
    private static final int ROUNDS = 18;

    private static final byte[] S0 = new byte[256];
    private static final byte[] S1 = new byte[256];

    private int[] roundKeys;

    public CLEFIA(byte[] key) {
        if (key.length != 16) {
            throw new IllegalArgumentException("CLEFIA-128 requires 128-bit key");
        }
        this.roundKeys = keySchedule(key);
    }

    // ================= KEY SCHEDULE =================
    private int[] keySchedule(byte[] key) {
        int[] rk = new int[ROUNDS * 2];

        for (int i = 0; i < rk.length; i++) {
            rk[i] = bytesToInt(key, (i * 4) % key.length);
        }

        return rk;
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Block size must be 16 bytes");
        }

        int[] state = bytesToState(plaintext);

        for (int r = 0; r < ROUNDS; r++) {
            roundFunction(state, roundKeys[r * 2], roundKeys[r * 2 + 1]);
        }

        return stateToBytes(state);
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Block size must be 16 bytes");
        }

        int[] state = bytesToState(ciphertext);

        for (int r = ROUNDS - 1; r >= 0; r--) {
            inverseRoundFunction(state, roundKeys[r * 2], roundKeys[r * 2 + 1]);
        }

        return stateToBytes(state);
    }

    // ================= ROUND FUNCTION =================
    private void roundFunction(int[] s, int k1, int k2) {
        int t0 = F0(s[0] ^ k1);
        int t1 = F1(s[1] ^ k2);

        int new0 = s[1];
        int new1 = s[2] ^ t0;
        int new2 = s[3];
        int new3 = s[0] ^ t1;

        s[0] = new0;
        s[1] = new1;
        s[2] = new2;
        s[3] = new3;
    }

    private void inverseRoundFunction(int[] s, int k1, int k2) {
        int t0 = F0(s[1] ^ k1);
        int t1 = F1(s[3] ^ k2);

        int new3 = s[2];
        int new2 = s[1] ^ t0;
        int new1 = s[0];
        int new0 = s[3] ^ t1;

        s[0] = new0;
        s[1] = new1;
        s[2] = new2;
        s[3] = new3;
    }

    // ================= F FUNCTIONS =================
    private int F0(int x) {
        return sBox(S0, x);
    }

    private int F1(int x) {
        return sBox(S1, x);
    }

    private int sBox(byte[] sbox, int x) {
        return (sbox[(x >>> 24) & 0xFF] & 0xFF) << 24 |
                (sbox[(x >>> 16) & 0xFF] & 0xFF) << 16 |
                (sbox[(x >>> 8) & 0xFF] & 0xFF) << 8 |
                (sbox[x & 0xFF] & 0xFF);
    }

    // ================= UTILITIES =================
    private int[] bytesToState(byte[] input) {
        int[] s = new int[4];
        for (int i = 0; i < 4; i++) {
            s[i] = bytesToInt(input, i * 4);
        }
        return s;
    }

    private byte[] stateToBytes(int[] state) {
        byte[] out = new byte[16];
        for (int i = 0; i < 4; i++) {
            intToBytes(state[i], out, i * 4);
        }
        return out;
    }

    private int bytesToInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24) |
                ((b[offset + 1] & 0xFF) << 16) |
                ((b[offset + 2] & 0xFF) << 8) |
                (b[offset + 3] & 0xFF);
    }

    private void intToBytes(int v, byte[] out, int offset) {
        out[offset] = (byte) (v >>> 24);
        out[offset + 1] = (byte) (v >>> 16);
        out[offset + 2] = (byte) (v >>> 8);
        out[offset + 3] = (byte) v;
    }

    // ================= TEXT SUPPORT =================

    private byte[] textToBlock(String text) {
        byte[] raw = text.getBytes(StandardCharsets.UTF_8);

        byte[] block = new byte[16];
        System.arraycopy(raw, 0, block, 0, Math.min(raw.length, 16));

        return block;
    }

    private String blockToText(byte[] block) {
        return new String(block, StandardCharsets.UTF_8).trim();
    }

    // ================= MAIN TEST =================
    public static void main(String[] args) {

        String text = "Hello CLEFIA";

        byte[] key = new byte[16];
        byte[] data = new byte[16];

        for (int i = 0; i < 16; i++) {
            key[i] = (byte) i;
        }

        CLEFIA cipher = new CLEFIA(key);

        byte[] block = cipher.textToBlock(text);

        byte[] encrypted = cipher.encrypt(block);
        byte[] decrypted = cipher.decrypt(encrypted);

        String result = cipher.blockToText(decrypted);

        System.out.println("Plain text: " + text);
        System.out.println("Encrypted:  " + Arrays.toString(encrypted));
        System.out.println("Decrypted:  " + result);
    }
}