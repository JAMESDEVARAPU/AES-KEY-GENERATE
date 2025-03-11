import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.util.Base64;
import java.util.Scanner;

public class FolderSecurity {
    private static final String PASSWORD_FILE = "password.enc";
    private static SecretKey secretKey;

    // Method to generate AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    // Encrypt password
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt password
    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    // Store the encrypted password in a file
    public static void saveEncryptedPassword(String encryptedPassword) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(PASSWORD_FILE))) {
            writer.write(encryptedPassword);
        }
    }

    // Read the encrypted password from the file
    public static String readEncryptedPassword() throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(PASSWORD_FILE))) {
            return reader.readLine();
        }
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            secretKey = generateAESKey();

            System.out.println("1. Set Folder Password");
            System.out.println("2. Access Folder");
            System.out.print("Choose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine();  // Consume newline

            if (choice == 1) {
                // Set password
                System.out.print("Enter a new password: ");
                String password = scanner.nextLine();
                String encryptedPassword = encrypt(password, secretKey);
                saveEncryptedPassword(encryptedPassword);
                System.out.println("Password set successfully!");
            } else if (choice == 2) {
                // Verify password
                System.out.print("Enter the password to access folder: ");
                String inputPassword = scanner.nextLine();
                String encryptedPassword = readEncryptedPassword();
                String decryptedPassword = decrypt(encryptedPassword, secretKey);

                if (inputPassword.equals(decryptedPassword)) {
                    System.out.println("Access Granted!");
                    // Simulate opening folder (In real cases, use OS commands)
                } else {
                    System.out.println("Access Denied!");
                }
            } else {
                System.out.println("Invalid option.");
            }

            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
