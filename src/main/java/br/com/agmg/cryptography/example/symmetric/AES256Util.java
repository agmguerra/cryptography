package br.com.agmg.cryptography.example.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

/**
 * 
 * This class cryptograph and decryptograph a String using
 * AES algorithm
 *
 */
public class AES256Util {

    private static final String ALGORITHM = "AES";
    private static final String KEY_FILE = "secret.key";

    // Gera uma chave AES de 256 bits e a salva em um arquivo
    public static void generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // Tamanho da chave: 256 bits
        SecretKey secretKey = keyGen.generateKey();

        // Salva a chave em um arquivo
        try (FileOutputStream fos = new FileOutputStream(KEY_FILE)) {
            fos.write(secretKey.getEncoded());
        }
    }

    // Carrega a chave do arquivo
    private static Key loadKey() throws Exception {
        File keyFile = new File(KEY_FILE);
        if (!keyFile.exists()) {
            throw new IllegalStateException("Chave não encontrada. Gere a chave primeiro.");
        }

        try (FileInputStream fis = new FileInputStream(keyFile)) {
            byte[] keyBytes = new byte[(int) keyFile.length()];
            fis.read(keyBytes);
            return new SecretKeySpec(keyBytes, ALGORITHM);
        }
    }

    // Criptografa um texto
    public static String encrypt(String text) throws Exception {
        Key key = loadKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Descriptografa um texto
    public static String decrypt(String encryptedText) throws Exception {
        Key key = loadKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Gera a chave (execute apenas uma vez ou quando necessário)
        generateKey();

        // Texto original
        String originalText = "Olá, mundo!";
        System.out.println("Texto original: " + originalText);

        // Criptografa o texto
        String encryptedText = encrypt(originalText);
        System.out.println("Texto criptografado: " + encryptedText);

        // Descriptografa o texto
        String decryptedText = decrypt(encryptedText);
        System.out.println("Texto descriptografado: " + decryptedText);
    }
}
