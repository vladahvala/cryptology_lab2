package triple_des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TripleDES {

    private static SecretKey key(String k) throws Exception {
        byte[] kb = Arrays.copyOf(k.getBytes(StandardCharsets.UTF_8), 8);
        DESKeySpec spec = new DESKeySpec(kb);
        return SecretKeyFactory.getInstance("DES").generateSecret(spec);
    }

    private static byte[] desEncrypt(byte[] data, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    private static byte[] desDecrypt(byte[] data, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(data);
    }

    public static byte[] encrypt(String text, String k1, String k2, String k3) throws Exception {

        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        int blockSize = 8;
        int paddedLen = ((data.length + 7) / 8) * 8;
        data = Arrays.copyOf(data, paddedLen); // manual padding

        byte[] step1 = desEncrypt(data, key(k1));
        byte[] step2 = desDecrypt(step1, key(k2));
        return desEncrypt(step2, key(k3));
    }

    public static String decrypt(byte[] data, String k1, String k2, String k3) throws Exception {

        byte[] step1 = desDecrypt(data, key(k3));
        byte[] step2 = desEncrypt(step1, key(k2));
        byte[] step3 = desDecrypt(step2, key(k1));

        return new String(step3, StandardCharsets.UTF_8).trim();
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