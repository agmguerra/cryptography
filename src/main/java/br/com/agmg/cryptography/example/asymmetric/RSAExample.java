package br.com.agmg.cryptography.example.asymmetric;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAExample {
	
    public static KeyPair generateKeyPair(String password) throws Exception {
        // Usar a senha como seed para um SecureRandom
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(password.getBytes());

        // Gerar par de chaves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom); // Tamanho da chave: 2048 bits
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String strToEncrypt, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String strToDecrypt, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
        return new String(decryptedBytes);
    }	

    public static void main(String[] args) throws Exception {
        String password = "mySecretPassword";
        String originalText = "Hello, World!";

        // Gerar par de chaves RSA a partir da senha
        KeyPair keyPair = generateKeyPair(password);

        // Criptografar o texto com a chave pública
        String encryptedText = encrypt(originalText, keyPair.getPublic());
        System.out.println("Texto Criptografado: " + encryptedText);

        // Descriptografar o texto com a chave privada
        String decryptedText = decrypt(encryptedText, keyPair.getPrivate());
        System.out.println("Texto Descriptografado: " + decryptedText);
    }

}
