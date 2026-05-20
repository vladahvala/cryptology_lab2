package des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DES_OFB {

    private SecretKey secretKey;
    private Cipher cipher;
    private IvParameterSpec iv;

    public DES_OFB(String key, byte[] ivBytes) throws Exception {

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");

        secretKey = factory.generateSecret(desKeySpec);

        cipher = Cipher.getInstance("DES/OFB/PKCS5Padding");

        iv = new IvParameterSpec(ivBytes);
    }

    // =========================
    // ENCRYPT
    // =========================
    public String encrypt(String text) throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    // =========================
    // DECRYPT
    // =========================
    public String decrypt(String cipherText) throws Exception {

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] decoded = Base64.getDecoder().decode(cipherText);

        byte[] decrypted = cipher.doFinal(decoded);

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // =========================
    // TEST
    // =========================
    public static void main(String[] args) throws Exception {

        String text = "Hello DES OFB!";
        String key = "secretkey";

        byte[] iv = new byte[] {
                0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08
        };

        DES_OFB des = new DES_OFB(key, iv);

        String encrypted = des.encrypt(text);
        String decrypted = des.decrypt(encrypted);

        System.out.println("Input: " + text);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}