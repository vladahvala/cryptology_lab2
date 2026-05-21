package rc;

public class RC5 {

    private static final int ROUNDS = 12;
    private int[] S = new int[26];

    // ===== KEY EXPANSION =====
    public void keyExpansion(String keyHex) {

        int P = 0xB7E15163;
        int Q = 0x9E3779B9;

        S[0] = P;
        for (int i = 1; i < 26; i++) {
            S[i] = S[i - 1] + Q;
        }

        int[] L = new int[4];

        for (int i = 0; i < 4; i++) {
            String part = keyHex.substring(i * 8, (i + 1) * 8);
            L[i] = (int) Long.parseUnsignedLong(part, 16);
        }

        int A = 0, B = 0;
        int i = 0, j = 0;

        for (int k = 0; k < 78; k++) {

            A = S[i] = Integer.rotateLeft(S[i] + A + B, 3);
            B = L[j] = Integer.rotateLeft(L[j] + A + B, (A + B) % 32);

            i = (i + 1) % 26;
            j = (j + 1) % 4;
        }
    }

    // ===== ENCRYPT =====
    public long encrypt(long block, String keyHex) {

        keyExpansion(keyHex);

        int A = (int) (block >>> 32);
        int B = (int) block;

        A += S[0];
        B += S[1];

        for (int i = 1; i <= ROUNDS; i++) {

            A ^= B;
            A = Integer.rotateLeft(A, B % 32);
            A += S[2 * i];

            B ^= A;
            B = Integer.rotateLeft(B, A % 32);
            B += S[2 * i + 1];
        }

        return (((long) A) << 32) | (B & 0xFFFFFFFFL);
    }

    // ===== DECRYPT =====
    public long decrypt(long block, String keyHex) {

        keyExpansion(keyHex);

        int A = (int) (block >>> 32);
        int B = (int) block;

        for (int i = ROUNDS; i >= 1; i--) {

            B -= S[2 * i + 1];
            B = Integer.rotateRight(B, A % 32);
            B ^= A;

            A -= S[2 * i];
            A = Integer.rotateRight(A, B % 32);
            A ^= B;
        }

        B -= S[1];
        A -= S[0];

        return (((long) A) << 32) | (B & 0xFFFFFFFFL);
    }

    // ===== MAIN (ВЖЕ ЗАДАНІ ДАНІ) =====
    public static void main(String[] args) {

        RC5 rc5 = new RC5();

        // 32 hex chars key (128-bit)
        String key = "00112233445566778899aabbccddeeff";

        // 64-bit plaintext (hex)
        long input = 0x0123456789ABCDEFL;

        long enc = rc5.encrypt(input, key);
        long dec = rc5.decrypt(enc, key);

        System.out.println("Key: " + key);
        System.out.println("Input (plaintext): " + Long.toHexString(input));

        System.out.println("\nEncrypted: " + Long.toHexString(enc));
        System.out.println("Decrypted: " + Long.toHexString(dec));
    }
}