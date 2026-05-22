package other_block;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;

public class Cartman {

    private static final int ROUNDS = 12;

    // 128-bit key
    private final int[] key;

    public Cartman(int[] key) {

        if (key.length != 4) {
            throw new IllegalArgumentException("Key must contain 4 integers");
        }

        this.key = key;
    }

    // ================= F FUNCTION =================
    private int F(int x, int k) {

        x ^= k;

        x = Integer.rotateLeft(x, 5);

        x += 0x9E3779B9;

        x ^= (x >>> 16);

        return x;
    }

    // ================= ENCRYPT BLOCK =================
    private void encryptBlock(int[] s) {

        int A = s[0];
        int B = s[1];
        int C = s[2];
        int D = s[3];

        // pre-whitening
        A ^= key[0];
        B ^= key[1];
        C ^= key[2];
        D ^= key[3];

        for (int r = 0; r < ROUNDS; r++) {

            int Dn = A;

            int Cn = Integer.rotateRight(
                    D ^ F(Dn, key[(r + 0) % 4]), 1);

            int Bn = Integer.rotateRight(
                    C ^ F(Cn, key[(r + 1) % 4]), 1);

            int An = Integer.rotateRight(
                    B ^ F(Bn, key[(r + 2) % 4]), 1);

            A = An;
            B = Bn;
            C = Cn;
            D = Dn;
        }

        // post-whitening
        s[0] = A ^ key[0];
        s[1] = B ^ key[1];
        s[2] = C ^ key[2];
        s[3] = D ^ key[3];
    }

    // ================= DECRYPT BLOCK =================
    private void decryptBlock(int[] s) {

        int A = s[0] ^ key[0];
        int B = s[1] ^ key[1];
        int C = s[2] ^ key[2];
        int D = s[3] ^ key[3];

        for (int r = ROUNDS - 1; r >= 0; r--) {

            int An = D;

            int Btemp = Integer.rotateLeft(A, 1);
            int Bn = Btemp ^ F(B, key[(r + 2) % 4]);

            int Ctemp = Integer.rotateLeft(B, 1);
            int Cn = Ctemp ^ F(C, key[(r + 1) % 4]);

            int Dtemp = Integer.rotateLeft(C, 1);
            int Dn = Dtemp ^ F(D, key[(r + 0) % 4]);

            A = An;
            B = Bn;
            C = Cn;
            D = Dn;
        }

        s[0] = A ^ key[0];
        s[1] = B ^ key[1];
        s[2] = C ^ key[2];
        s[3] = D ^ key[3];
    }

    // ================= ENCRYPT =================
    public byte[] encrypt(byte[] data) {

        int len = ((data.length + 15) / 16) * 16;

        byte[] padded = Arrays.copyOf(data, len);

        if (data.length < padded.length) {
            padded[data.length] = 1;
        }

        for (int i = 0; i < padded.length; i += 16) {

            int[] block = bytesToInts(padded, i);

            encryptBlock(block);

            intsToBytes(block, padded, i);
        }

        return padded;
    }

    // ================= DECRYPT =================
    public byte[] decrypt(byte[] data) {

        byte[] result = Arrays.copyOf(data, data.length);

        for (int i = 0; i < result.length; i += 16) {

            int[] block = bytesToInts(result, i);

            decryptBlock(block);

            intsToBytes(block, result, i);
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
    private int[] bytesToInts(byte[] b, int offset) {

        ByteBuffer bb = ByteBuffer.wrap(b, offset, 16)
                .order(ByteOrder.BIG_ENDIAN);

        return new int[] {
                bb.getInt(),
                bb.getInt(),
                bb.getInt(),
                bb.getInt()
        };
    }

    private void intsToBytes(int[] in, byte[] out, int offset) {

        ByteBuffer bb = ByteBuffer.allocate(16)
                .order(ByteOrder.BIG_ENDIAN);

        for (int v : in) {
            bb.putInt(v);
        }

        System.arraycopy(bb.array(), 0, out, offset, 16);
    }

    // ================= DEMO =================
    public static void main(String[] args) {

        int[] key = {
                0x11111111,
                0x22222222,
                0x33333333,
                0x44444444
        };

        Cartman cipher = new Cartman(key);

        String text = "HELLO CARTMAN";

        byte[] encrypted = cipher.encrypt(text.getBytes());

        byte[] decrypted = cipher.decrypt(encrypted);

        System.out.println("Original:  " + text);

        System.out.println("Encrypted (Base64): " +
                Base64.getEncoder().encodeToString(encrypted));

        System.out.println("Decrypted: " +
                new String(decrypted));
    }
}