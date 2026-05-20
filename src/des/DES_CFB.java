package des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DES_CFB {

    public static void main(String[] args) throws Exception {

        // =========================
        // 1. Вхідні дані
        // =========================
        String plaintext = "Hello DES CFB!";
        System.out.println("Input: " + plaintext);

        // =========================
        // 2. Генерація ключа (DES)
        // =========================
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        SecretKey key = keyGen.generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Key (Base64): " + encodedKey);

        // =========================
        // 3. IV (ініціалізаційний вектор)
        // =========================
        byte[] ivBytes = new byte[] { 11, 22, 33, 44, 99, 88, 77, 66 };
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // =========================
        // 4. CFB Cipher
        // =========================
        Cipher cipher = Cipher.getInstance("DES/CFB/PKCS5Padding");

        // =========================
        // 5. ШИФРУВАННЯ
        // =========================
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        String encText = Base64.getEncoder().encodeToString(encrypted);
        System.out.println("Encrypted: " + encText);

        // =========================
        // 6. РОЗШИФРУВАННЯ
        // =========================
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decrypted = cipher.doFinal(encrypted);

        String decText = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + decText);
    }
}