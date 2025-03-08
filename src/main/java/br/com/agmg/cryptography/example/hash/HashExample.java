package br.com.agmg.cryptography.example.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class HashExample {
    public static void main(String[] args) {
        String entrada = "Olá, mundo!";

        try {
            // Cria uma instância do algoritmo SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Converte a entrada para bytes e calcula o hash
            byte[] hashBytes = digest.digest(entrada.getBytes(StandardCharsets.UTF_8));

            // Converte o array de bytes para uma representação hexadecimal
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            System.out.println("Entrada: " + entrada);
            System.out.println("Hash SHA-256: " + hexString.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
