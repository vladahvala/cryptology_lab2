package des;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DES_CBC {

    public static void main(String[] args) throws Exception {

        // ===== Input data =====
        byte[] input = "Hello DES CBC!".getBytes(StandardCharsets.UTF_8);

        // ===== Key (8 bytes for DES) =====
        byte[] keyBytes = new byte[] {
                0x01, 0x23, 0x45, 0x67,
                (byte) 0x89, (byte) 0xab,
                (byte) 0xcd, (byte) 0xef
        };

        // ===== IV (8 bytes for DES CBC) =====
        byte[] ivBytes = new byte[] {
                0x07, 0x06, 0x05, 0x04,
                0x03, 0x02, 0x01, 0x00
        };

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // ===== Cipher CBC =====
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        // ===== ENCRYPT =====
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encrypted = cipher.doFinal(input);

        System.out.println("Input: " + new String(input, StandardCharsets.UTF_8));
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));

        // ===== DECRYPT =====
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
    }
}