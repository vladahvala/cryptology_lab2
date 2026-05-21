package rc;

import java.util.Arrays;

public class RC6 {

    private static final int W = 32;
    private static final int R = 20;

    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;

    private int[] S = new int[2 * R + 4];

    // ================= ROTATE =================
    private int rotl(int x, int y) {
        return (x << (y & 31)) | (x >>> (32 - (y & 31)));
    }

    private int rotr(int x, int y) {
        return (x >>> (y & 31)) | (x << (32 - (y & 31)));
    }

    // ================= KEY SCHEDULE =================
    private void keySchedule(byte[] key) {

        int c = Math.max(1, key.length / 4);
        int[] L = new int[c];

        for (int i = 0; i < key.length; i++) {
            L[i / 4] = (L[i / 4] << 8) + (key[i] & 0xFF);
        }

        S[0] = P32;
        for (int i = 1; i < S.length; i++) {
            S[i] = S[i - 1] + Q32;
        }

        int A = 0, B = 0;
        int i = 0, j = 0;

        int v = 3 * Math.max(c, S.length);

        for (int k = 0; k < v; k++) {
            A = S[i] = rotl(S[i] + A + B, 3);
            B = L[j] = rotl(L[j] + A + B, (A + B));
            i = (i + 1) % S.length;
            j = (j + 1) % c;
        }
    }

    // ================= ENCRYPT BLOCK =================
    private byte[] encryptBlock(byte[] block) {

        int A = toInt(block, 0);
        int B = toInt(block, 4);
        int C = toInt(block, 8);
        int D = toInt(block, 12);

        B += S[0];
        D += S[1];

        for (int i = 1; i <= R; i++) {

            int t = rotl(B * (2 * B + 1), 5);
            int u = rotl(D * (2 * D + 1), 5);

            A = rotl(A ^ t, u) + S[2 * i];
            C = rotl(C ^ u, t) + S[2 * i + 1];

            int tmp = A;
            A = B;
            B = C;
            C = D;
            D = tmp;
        }

        A += S[2 * R + 2];
        C += S[2 * R + 3];

        return toBytes(A, B, C, D);
    }

    // ================= DECRYPT BLOCK =================
    private byte[] decryptBlock(byte[] block) {

        int A = toInt(block, 0);
        int B = toInt(block, 4);
        int C = toInt(block, 8);
        int D = toInt(block, 12);

        C -= S[2 * R + 3];
        A -= S[2 * R + 2];

        for (int i = R; i >= 1; i--) {

            int tmp = D;
            D = C;
            C = B;
            B = A;
            A = tmp;

            int t = rotl(B * (2 * B + 1), 5);
            int u = rotl(D * (2 * D + 1), 5);

            C = rotr(C - S[2 * i + 1], t) ^ u;
            A = rotr(A - S[2 * i], u) ^ t;
        }

        D -= S[1];
        B -= S[0];

        return toBytes(A, B, C, D);
    }

    // ================= PUBLIC ENCRYPT =================
    public byte[] encrypt(byte[] data, byte[] key) {

        keySchedule(key);

        byte[] padded = pad(data);
        byte[] out = new byte[padded.length];

        for (int i = 0; i < padded.length; i += 16) {
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);
            byte[] enc = encryptBlock(block);
            System.arraycopy(enc, 0, out, i, 16);
        }

        return out;
    }

    // ================= PUBLIC DECRYPT =================
    public byte[] decrypt(byte[] data, byte[] key) {

        keySchedule(key);

        byte[] out = new byte[data.length];

        for (int i = 0; i < data.length; i += 16) {
            byte[] block = Arrays.copyOfRange(data, i, i + 16);
            byte[] dec = decryptBlock(block);
            System.arraycopy(dec, 0, out, i, 16);
        }

        return unpad(out);
    }

    // ================= HELPERS =================
    private int toInt(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    private byte[] toBytes(int a, int b, int c, int d) {
        return new byte[] {
                (byte) a, (byte) (a >> 8), (byte) (a >> 16), (byte) (a >> 24),
                (byte) b, (byte) (b >> 8), (byte) (b >> 16), (byte) (b >> 24),
                (byte) c, (byte) (c >> 8), (byte) (c >> 16), (byte) (c >> 24),
                (byte) d, (byte) (d >> 8), (byte) (d >> 16), (byte) (d >> 24)
        };
    }

    private byte[] pad(byte[] data) {
        int len = ((data.length / 16) + 1) * 16;
        byte[] out = Arrays.copyOf(data, len);
        Arrays.fill(out, data.length, len, (byte) (len - data.length));
        return out;
    }

    private byte[] unpad(byte[] data) {
        int pad = data[data.length - 1] & 0xFF;
        return Arrays.copyOf(data, data.length - pad);
    }

    // ================= TEST =================
    public static void main(String[] args) {

        RC6 rc6 = new RC6();

        String text = "Hello RC6 World!";
        String key = "1234567890ABCDEF1234567890ABCDEF";

        byte[] enc = rc6.encrypt(text.getBytes(), key.getBytes());
        byte[] dec = rc6.decrypt(enc, key.getBytes());

        System.out.println("Encrypted: " + Arrays.toString(enc));
        System.out.println("Decrypted: " + new String(dec));
    }
}