package br.com.agmg.cryptography.example.symmetric;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PBKDF2Example {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Senha do usuário
        String password = "SenhaSuperSecreta123!";

        // Gera um salt aleatório
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // Salt de 16 bytes
        random.nextBytes(salt);

        // Configurações do PBKDF2
        int iterations = 65536; // Número de iterações
        int keyLength = 256;    // Tamanho da chave em bits

        // Gera a chave usando PBKDF2
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        byte[] key = factory.generateSecret(spec).getEncoded();

        // Exibe o salt e a chave gerada
        System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
        System.out.println("Chave: " + Base64.getEncoder().encodeToString(key));
    }
}
