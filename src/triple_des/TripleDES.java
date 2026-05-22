package triple_des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TripleDES {

    // ===== create DES key =====
    private static SecretKey key(String k) throws Exception {
        byte[] kb = Arrays.copyOf(k.getBytes(StandardCharsets.UTF_8), 8);
        DESKeySpec spec = new DESKeySpec(kb);
        return SecretKeyFactory.getInstance("DES").generateSecret(spec);
    }

    // ===== DES encrypt (NO padding) =====
    private static byte[] desEncrypt(byte[] data, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    // ===== DES decrypt (NO padding) =====
    private static byte[] desDecrypt(byte[] data, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(data);
    }

    // ===== manual padding =====
    private static byte[] pad(byte[] data) {
        int blockSize = 8;
        int paddedLen = ((data.length + blockSize - 1) / blockSize) * blockSize;
        byte[] padded = Arrays.copyOf(data, paddedLen);

        // PKCS-like padding (simple)
        int padValue = paddedLen - data.length;
        for (int i = data.length; i < paddedLen; i++) {
            padded[i] = (byte) padValue;
        }

        return padded;
    }

    // ===== remove padding =====
    private static byte[] unpad(byte[] data) {
        int padValue = data[data.length - 1] & 0xFF;
        return Arrays.copyOf(data, data.length - padValue);
    }

    // ===== ENCRYPT (EDE) =====
    public static byte[] encrypt(String text, String k1, String k2, String k3) throws Exception {

        byte[] data = pad(text.getBytes(StandardCharsets.UTF_8));

        byte[] step1 = desEncrypt(data, key(k1));
        byte[] step2 = desDecrypt(step1, key(k2));
        return desEncrypt(step2, key(k3));
    }

    // ===== DECRYPT (DED) =====
    public static String decrypt(byte[] data, String k1, String k2, String k3) throws Exception {

        byte[] step1 = desDecrypt(data, key(k3));
        byte[] step2 = desEncrypt(step1, key(k2));
        byte[] step3 = desDecrypt(step2, key(k1));

        return new String(unpad(step3), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        String text = "Hello, 3DES!";

        byte[] enc = encrypt(text, "key11111", "key22222", "key33333");
        String dec = decrypt(enc, "key11111", "key22222", "key33333");

        System.out.println("Input: " + text);

        System.out.print("Encrypted: ");
        for (byte b : enc)
            System.out.printf("%02x", b);

        System.out.println("\nDecrypted: " + dec);
    }
}