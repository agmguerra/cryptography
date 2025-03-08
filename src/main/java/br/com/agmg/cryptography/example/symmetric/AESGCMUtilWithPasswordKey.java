package br.com.agmg.cryptography.example.symmetric;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESGCMUtilWithPasswordKey {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // Tamanho do tag de autenticação em bits
    private static final int GCM_IV_LENGTH = 12;   // Tamanho do IV em bytes (recomendado para GCM)
    private static final int ITERATIONS = 65536;   // Número de iterações para PBKDF2
    private static final int KEY_LENGTH = 256;     // Tamanho da chave em bits

    // Gera uma chave a partir de uma senha usando PBKDF2
    public static SecretKey generateKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), ITERATIONS, KEY_LENGTH);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        return secretKey;
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
        // Senha e salt (devem ser os mesmos em ambos os servidores)
        String password = "SenhaSuperSecreta123!";
        String salt = "SaltFixoParaSeguranca";

        // Gera a chave a partir da senha e do salt
        SecretKey key = generateKeyFromPassword(password, salt);

        // Texto original
        String originalText = "Olá, mundo!";
        System.out.println("Texto original: " + originalText);

        // Criptografa o texto (pode ser feito em um servidor)
        String encryptedText = encrypt(originalText, key);
        System.out.println("Texto criptografado: " + encryptedText);

        // Descriptografa o texto (pode ser feito em outro servidor)
        String decryptedText = decrypt(encryptedText, key);
        System.out.println("Texto descriptografado: " + decryptedText);
    }
}
