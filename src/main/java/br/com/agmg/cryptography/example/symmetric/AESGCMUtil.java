package br.com.agmg.cryptography.example.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESGCMUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // Tamanho do tag de autenticação em bits
    private static final int GCM_IV_LENGTH = 12;   // Tamanho do IV em bytes (recomendado para GCM)

    // Gera uma chave AES de 256 bits
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // Tamanho da chave: 256 bits
        return keyGen.generateKey();
    }

    // Criptografa o texto usando GCM
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        // Gera um IV aleatório
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Configura o cipher para criptografia
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // Criptografa o texto
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Combina o IV e o texto cifrado em um único array
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        // Retorna o resultado codificado em Base64
        return Base64.getEncoder().encodeToString(combined);
    }

    // Descriptografa o texto usando GCM
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        // Decodifica o texto cifrado de Base64
        byte[] combined = Base64.getDecoder().decode(encryptedText);

        // Separa o IV do texto cifrado
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedBytes = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);

        // Configura o cipher para descriptografia
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        // Descriptografa o texto
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        // Gera uma chave AES de 256 bits
        SecretKey key = generateKey();

        // Texto original
        String originalText = "Olá, mundo!";
        System.out.println("Texto original: " + originalText);

        // Criptografa o texto
        String encryptedText = encrypt(originalText, key);
        System.out.println("Texto criptografado: " + encryptedText);

        // Descriptografa o texto
        String decryptedText = decrypt(encryptedText, key);
        System.out.println("Texto descriptografado: " + decryptedText);
    }
}
