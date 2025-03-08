package br.com.agmg.cryptography.example.hash;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public class GeradorHashSHA3 {
    public static String gerarHashSHA3(String entrada) {
        SHA3.DigestSHA3 digest = new SHA3.DigestSHA3(256); // SHA3-256
        byte[] hashBytes = digest.digest(entrada.getBytes(StandardCharsets.UTF_8));
        return Hex.toHexString(hashBytes);
    }

    public static void main(String[] args) {
        String entrada = "SenhaSuperSecreta123";
        String hash = gerarHashSHA3(entrada);

        System.out.println("Entrada: " + entrada);
        System.out.println("Hash SHA3-256: " + hash);
    }
}
