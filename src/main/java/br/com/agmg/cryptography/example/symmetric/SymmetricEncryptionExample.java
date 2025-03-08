package br.com.agmg.cryptography.example.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Texto original
        String originalText = "Olá, mundo!";
        System.out.println("Texto original: " + originalText);

        // Gerar uma chave AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Tamanho da chave: 128 bits
        SecretKey secretKey = keyGen.generateKey();

        // Converter a chave para uma representação em bytes
        byte[] keyBytes = secretKey.getEncoded();

        // Criar uma chave a partir dos bytes
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        // Criptografar o texto
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(originalText.getBytes());
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Texto criptografado: " + encryptedText);

        // Descriptografar o texto
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        String decryptedText = new String(decryptedBytes);
        System.out.println("Texto descriptografado: " + decryptedText);
    }
}
