package rc;

import java.nio.charset.StandardCharsets;

public class RC4 {

    private final byte[] S = new byte[256];
    private int i = 0, j = 0;

    // ===== KSA =====
    public RC4(byte[] key) {

        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }

        int j = 0;

        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + (key[i % key.length] & 0xFF)) & 0xFF;

            byte tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;
        }
    }

    // ===== PRGA =====
    public byte[] process(byte[] data) {

        byte[] output = new byte[data.length];

        for (int k = 0; k < data.length; k++) {

            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;

            byte tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;

            int t = (S[i] + S[j]) & 0xFF;
            byte keyStream = S[t];

            output[k] = (byte) (data[k] ^ keyStream);
        }

        return output;
    }

    // ===== decrypt =====
    public byte[] decrypt(byte[] data) {
        return process(data);
    }

    // ===== hex helper =====
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ===== TEST =====
    public static void main(String[] args) {

        String text = "Hello, World!";
        String key = "SecretKey";

        RC4 rc4 = new RC4(key.getBytes(StandardCharsets.UTF_8));

        byte[] encrypted = rc4.process(text.getBytes(StandardCharsets.UTF_8));

        // IMPORTANT: новий об'єкт для decrypt (інакше стан S зіпсований)
        RC4 rc4Decrypt = new RC4(key.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = rc4Decrypt.process(encrypted);

        System.out.println("Encrypted (hex): " + toHex(encrypted));
        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
    }
}