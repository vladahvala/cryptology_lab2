package aes;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Rijndael {

    // ===== S-box (скорочена частина AES таблиці можна вставити повну у звіті)
    // =====
    private static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
            // (для лабораторної зазвичай достатньо показати принцип або повну таблицю)
    };

    private static final int BLOCK_SIZE = 16; // 128-bit
    private static final int ROUNDS = 10;

    // ===== SubBytes =====
    private static void subBytes(int[] state) {
        for (int i = 0; i < 16; i++) {
            state[i] = SBOX[state[i] & 0x0F];
        }
    }

    // ===== ShiftRows =====
    private static void shiftRows(int[] s) {
        int[] t = Arrays.copyOf(s, 16);

        s[0] = t[0];
        s[1] = t[5];
        s[2] = t[10];
        s[3] = t[15];

        s[4] = t[4];
        s[5] = t[9];
        s[6] = t[14];
        s[7] = t[3];

        s[8] = t[8];
        s[9] = t[13];
        s[10] = t[2];
        s[11] = t[7];

        s[12] = t[12];
        s[13] = t[1];
        s[14] = t[6];
        s[15] = t[11];
    }

    // ===== MixColumns (спрощена версія XOR-змішування) =====
    private static void mixColumns(int[] s) {
        for (int i = 0; i < 16; i += 4) {
            int a = s[i];
            int b = s[i + 1];
            int c = s[i + 2];
            int d = s[i + 3];

            s[i] = a ^ b;
            s[i + 1] = b ^ c;
            s[i + 2] = c ^ d;
            s[i + 3] = d ^ a;
        }
    }

    // ===== AddRoundKey =====
    private static void addRoundKey(int[] state, int[] key) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= key[i];
        }
    }

    // ===== простий key expansion (для лаби достатньо дублювання) =====
    private static int[][] expandKey(byte[] key) {
        int[][] roundKeys = new int[11][16];

        for (int r = 0; r < 11; r++) {
            for (int i = 0; i < 16; i++) {
                roundKeys[r][i] = key[i % key.length] & 0xFF;
            }
        }
        return roundKeys;
    }

    // ===== AES-like encryption =====
    public static byte[] encrypt(byte[] input, byte[] key) {

        int[] state = new int[16];

        for (int i = 0; i < 16; i++) {
            if (i < input.length) {
                state[i] = input[i] & 0xFF;
            } else {
                state[i] = 0; // padding
            }
        }

        int[][] roundKeys = expandKey(key);

        // Initial round
        addRoundKey(state, roundKeys[0]);

        // 9 rounds
        for (int i = 1; i < ROUNDS; i++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[i]);
        }

        // Final round
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);

        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) state[i];
        }

        return out;
    }

    // ===== test =====
    public static void main(String[] args) {

        String text = "HelloAES1234567"; // 16 bytes
        String key = "MySecretKey1234";

        byte[] result = encrypt(
                text.getBytes(StandardCharsets.UTF_8),
                key.getBytes(StandardCharsets.UTF_8));

        System.out.print("Ciphertext: ");
        for (byte b : result) {
            System.out.printf("%02x", b);
        }
    }
}