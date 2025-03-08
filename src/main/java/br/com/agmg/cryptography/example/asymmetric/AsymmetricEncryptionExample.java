package br.com.agmg.cryptography.example.asymmetric;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class AsymmetricEncryptionExample {
	
    // Criptografa o texto com a chave pública
    public static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Descriptografa o texto com a chave privada
    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }
    
    // Gera um par de chaves RSA
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Tamanho da chave: 2048 bits
        return keyGen.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        // Gera um par de chaves RSA
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Texto original
        String originalText = "Olá, mundo!";
        System.out.println("Texto original: " + originalText);

        // Criptografa o texto com a chave pública
        String encryptedText = encrypt(originalText, publicKey);
        System.out.println("Texto criptografado: " + encryptedText);

        // Decriptografa o texto com a chave privada
        String decryptedText = decrypt(encryptedText, privateKey);
        System.out.println("Texto descriptografado: " + decryptedText);
    }

}