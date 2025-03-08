package br.com.agmg.cryptography.example.asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public class RSAWithPaddingExample {

    public static void main(String[] args) throws Exception {
        String originalText = "Hello, World!";

        // Gerar par de chaves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamanho da chave: 2048 bits
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Criptografar com PKCS1Padding
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedBytes = encryptCipher.doFinal(originalText.getBytes());

        // Descriptografar com PKCS1Padding
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);

        String decryptedText = new String(decryptedBytes);
        System.out.println("Texto Descriptografado: " + decryptedText);
    }
}