package other_block;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class CAST128 {

    public static void main(String[] args) {

        try {

            // Реєстрація Bouncy Castle
            Security.addProvider(new BouncyCastleProvider());

            // Вхідні дані
            String plaintext = "Hello World!";

            // 128-bit key = 16 bytes
            byte[] keyBytes = "1234567890ABCDEF".getBytes();

            // Створення ключа
            SecretKey secretKey = new SecretKeySpec(keyBytes, "CAST5");

            // Створення шифра
            Cipher cipher = Cipher.getInstance("CAST5/ECB/PKCS5Padding", "BC");

            // ================= ENCRYPT =================
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);

            // ================= DECRYPT =================
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedBytes = cipher.doFinal(
                    Base64.getDecoder().decode(encryptedText));

            String decryptedText = new String(decryptedBytes);

            // ================= OUTPUT =================
            System.out.println("Original text: " + plaintext);

            System.out.println("Encrypted text: " + encryptedText);

            System.out.println("Decrypted text: " + decryptedText);

        } catch (Exception e) {

            System.out.println("Encryption error");

            e.printStackTrace();
        }
    }
}