package br.com.agmg.cryptography.example.asymmetric;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HybridFileEncryption {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final int RSA_KEY_SIZE = 2048; // Tamanho da chave RSA
    private static final int AES_KEY_SIZE = 128; // Tamanho da chave AES (128 bits)

    /**
     * Gera um par de chaves RSA (pública e privada).
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Gera uma chave AES.
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    /**
     * Criptografa um arquivo usando AES e criptografa a chave AES com RSA.
     */
    public static void encryptFile(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
        // Gerar uma chave AES
        SecretKey aesKey = generateAESKey();

        // Criptografar o arquivo com AES
        Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));
        byte[] encryptedFileContent = aesCipher.doFinal(fileContent);

        // Criptografar a chave AES com RSA
        Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Salvar a chave AES criptografada e o conteúdo criptografado no arquivo de saída
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             DataOutputStream dos = new DataOutputStream(fos)) {
            // Escrever o tamanho da chave AES criptografada
            dos.writeInt(encryptedAESKey.length);
            // Escrever a chave AES criptografada
            dos.write(encryptedAESKey);
            // Escrever o conteúdo criptografado
            dos.write(encryptedFileContent);
        }
    }

    /**
     * Descriptografa um arquivo usando AES e descriptografa a chave AES com RSA.
     */
    public static void decryptFile(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             DataInputStream dis = new DataInputStream(fis)) {
            // Ler o tamanho da chave AES criptografada
            int encryptedAESKeyLength = dis.readInt();
            // Ler a chave AES criptografada
            byte[] encryptedAESKey = new byte[encryptedAESKeyLength];
            dis.readFully(encryptedAESKey);
            // Ler o conteúdo criptografado
            byte[] encryptedFileContent = dis.readAllBytes();

            // Descriptografar a chave AES com RSA
            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedAESKeyBytes = rsaCipher.doFinal(encryptedAESKey);
            SecretKey aesKey = new SecretKeySpec(decryptedAESKeyBytes, AES_ALGORITHM);

            // Descriptografar o conteúdo com AES
            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedFileContent = aesCipher.doFinal(encryptedFileContent);

            // Salvar o conteúdo descriptografado no arquivo de saída
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedFileContent);
            }
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
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Carrega uma chave privada de um arquivo.
     */
    public static PrivateKey loadPrivateKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    public static void main(String[] args) {
        try {
            // Gerar par de chaves RSA
            KeyPair keyPair = generateRSAKeyPair();
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
