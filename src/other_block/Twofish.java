package other_block;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class Twofish {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 🔥 256-bit key = 32 bytes
    private static byte[] fixKey(String key) {
        byte[] k = new byte[32]; // 256 bit
        byte[] input = key.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < k.length; i++) {
            k[i] = (i < input.length) ? input[i] : 0;
        }
        return k;
    }

    public static String encrypt(String data, String key) throws Exception {

        SecretKeySpec secretKey = new SecretKeySpec(fixKey(key), "Twofish");

        Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String data, String key) throws Exception {

        SecretKeySpec secretKey = new SecretKeySpec(fixKey(key), "Twofish");

        Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decoded = Base64.getDecoder().decode(data);

        return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {

        String key = "1234567890ABCDEF1234567890ABCDEF"; // 32 chars (≈256-bit)
        String text = "Hello Twofish";

        String enc = encrypt(text, key);
        String dec = decrypt(enc, key);

        System.out.println("Encrypted: " + enc);
        System.out.println("Decrypted: " + dec);
    }
}