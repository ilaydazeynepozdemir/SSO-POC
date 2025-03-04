package com.poc.openid.server;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class RSAKeyPairGenerator {


    public static KeyPair generateRSAKeyPair() throws Exception {
        // RSA anahtar çifti oluştur
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // 2048 bit uzunluğunda bir anahtar
        return keyPairGenerator.generateKeyPair(); // Anahtar çiftini döndür
    }

    public static RSAPrivateKey loadPrivateKey(String filename) throws Exception {
        FileInputStream keyInputStream = new FileInputStream(filename);
        byte[] keyBytes = new byte[keyInputStream.available()];
        keyInputStream.read(keyBytes);
        keyInputStream.close();

        // PEM formatındaki private key'in başındaki "-----BEGIN PRIVATE KEY-----" ve
        // sonundaki "-----END PRIVATE KEY-----" satırlarını temizle
        String keyString = new String(keyBytes);
        keyString = keyString.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        // Base64 decode
        byte[] decodedKey = Base64.getDecoder().decode(keyString);

        // Anahtarı oluştur
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

}
