package br.com.agmg.cryptography.example.asymmetric;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricFileEncryption {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int KEY_SIZE = 2048; // Tamanho da chave RSA (2048 bits é seguro e eficiente)

    /**
     * Gera um par de chaves RSA (pública e privada).
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Criptografa um arquivo usando a chave pública.
     */
    public static void encryptFile(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
        // Ler o conteúdo do arquivo
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));

        // Criptografar o conteúdo
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(fileContent);

        // Salvar o conteúdo criptografado no arquivo de saída
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(encryptedBytes);
        }
    }

    /**
     * Descriptografa um arquivo usando a chave privada.
     */
    public static void decryptFile(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
        // Ler o conteúdo criptografado do arquivo
        byte[] encryptedContent = Files.readAllBytes(Paths.get(inputFile));

        // Descriptografar o conteúdo
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedContent);

        // Salvar o conteúdo descriptografado no arquivo de saída
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(decryptedBytes);
        }
    }

    /**
     * Salva uma chave (pública ou privada) em um arquivo.
     */
    public static void saveKeyToFile(String fileName, Key key) throws IOException {
        byte[] keyBytes = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyBytes);
        }
    }

    /**
     * Carrega uma chave pública de um arquivo.
     */
    public static PublicKey loadPublicKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Carrega uma chave privada de um arquivo.
     */
    public static PrivateKey loadPrivateKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    public static void main(String[] args) {
        try {
            // Gerar par de chaves
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Salvar as chaves em arquivos (opcional)
            saveKeyToFile("public.key", publicKey);
            saveKeyToFile("private.key", privateKey);

            // Arquivo de entrada e saída
            String inputFile = "texto.txt"; // Arquivo de texto original
            String encryptedFile = "texto_criptografado.enc"; // Arquivo criptografado
            String decryptedFile = "texto_descriptografado.txt"; // Arquivo descriptografado

            // Criptografar o arquivo
            encryptFile(inputFile, encryptedFile, publicKey);
            System.out.println("Arquivo criptografado com sucesso: " + encryptedFile);

            // Descriptografar o arquivo
            decryptFile(encryptedFile, decryptedFile, privateKey);
            System.out.println("Arquivo descriptografado com sucesso: " + decryptedFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
