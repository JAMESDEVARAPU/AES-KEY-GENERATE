import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Scanner;
import java.util.Base64;

public class AESExample {
    // Method to generate AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // For AES-128
        return keyGenerator.generateKey();
    }

    // Method to encrypt plaintext
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to decrypt ciphertext
    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            
            // Get plaintext from user
            System.out.print("Enter the plaintext: ");
            String plaintext = scanner.nextLine();
            
            // Generate AES key
            SecretKey secretKey = generateAESKey();
            System.out.println("Generated AES Key (in base64): " + 
                Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            
            // Encrypt the plaintext
            String encryptedText = encrypt(plaintext, secretKey);
            System.out.println("Encrypted Text: " + encryptedText);
            
            // Decrypt the ciphertext
            String decryptedText = decrypt(encryptedText, secretKey);
            System.out.println("Decrypted Text: " + decryptedText);
            
            scanner.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}