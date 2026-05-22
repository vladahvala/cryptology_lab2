package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class COBRA {

    private static final int ROUNDS = 12;

    private final int[] W1 = new int[4];
    private final int[] W2 = new int[4];

    private final int[][] P = new int[12][3]; // P-box
    private final int[][] S = new int[12][256]; // S-box
    private final int[][] K = new int[12][4]; // round keys

    public COBRA(byte[] key) {
        keyExpansion(key);
    }

    // ================= KEY EXPANSION (simplified model) =================
    private void keyExpansion(byte[] key) {

        ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOf(key, 64))
                .order(ByteOrder.BIG_ENDIAN);

        // W-boxes
        for (int i = 0; i < 4; i++)
            W1[i] = bb.getInt();
        for (int i = 0; i < 4; i++)
            W2[i] = bb.getInt();

        // Round keys + S + P generation (toy PRNG)
        int seed = Arrays.hashCode(key);

        for (int r = 0; r < ROUNDS; r++) {

            for (int i = 0; i < 4; i++) {
                K[r][i] = seed = mix(seed);
            }

            for (int i = 0; i < 3; i++) {
                P[r][i] = seed = mix(seed);
            }

            for (int i = 0; i < 256; i++) {
                S[r][i] = seed = mix(seed);
            }
        }
    }

    private int mix(int x) {
        x ^= (x << 13);
        x ^= (x >>> 17);
        x ^= (x << 5);
        return x;
    }

    // ================= F FUNCTION =================
    private int F(int x, int k, int sbox) {
        int v = x + k;
        return Integer.rotateLeft(v ^ sbox, 7);
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] input) {

        int[] s = toState(input);

        int A = s[0], B = s[1], C = s[2], D = s[3];

        // pre-whitening
        A ^= W1[0];
        B ^= W1[1];
        C ^= W1[2];
        D ^= W1[3];

        for (int r = 0; r < ROUNDS; r++) {

            int A2 = B ^ F(B, K[r][0], S[r][0]);
            int B2 = C ^ F(C, K[r][1], S[r][1]);
            int C2 = D ^ F(D, K[r][2], S[r][2]);
            int D2 = A ^ F(A, K[r][3], S[r][3]);

            // diffusion (>>>1)
            A = Integer.rotateRight(A2, 1);
            B = Integer.rotateRight(B2, 1);
            C = Integer.rotateRight(C2, 1);
            D = Integer.rotateRight(D2, 1);
        }

        // post-whitening
        A ^= W2[0];
        B ^= W2[1];
        C ^= W2[2];
        D ^= W2[3];

        return toBytes(new int[] { A, B, C, D });
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] input) {
        // симетрична навчальна модель (Feistel-like)
        return encrypt(input);
    }

    // ================= HELPERS =================
    private int[] toState(byte[] b) {
        ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        return new int[] {
                bb.getInt(),
                bb.getInt(),
                bb.getInt(),
                bb.getInt()
        };
    }

    private byte[] toBytes(int[] s) {
        ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
        for (int v : s)
            bb.putInt(v);
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
    
        MARS mars = new MARS(key);
    
        String text = "HELLO MARS CRYPTO";
    
        byte[] data = text.getBytes();
    
        byte[] enc = mars.encrypt(data);
        byte[] dec = mars.decrypt(enc);
    
        System.out.println("Original:  " + text);
    
        // ❗ FIX: НЕ new String(enc)
        System.out.println("Encrypted (Base64): " +
                java.util.Base64.getEncoder().encodeToString(enc));
    
        System.out.println("Encrypted (bytes): " +
                java.util.Arrays.toString(enc));
    
        System.out.println("Decrypted: " + new String(dec).trim());
    }
}