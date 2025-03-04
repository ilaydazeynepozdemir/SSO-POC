package com.poc.openid.server;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

public class JwtGenerator {

   /* public static Jwt generateJwt(RSAPrivateKey privateKey) {
        // JwtEncoder kullanarak token oluştur
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(privateKey);
        
        // JWT içeriğini oluştur
        JwtEncoderParameters parameters = JwtEncoderParameters.from(
            JwtClaimSets.builder()
                .claim("sub", "user1") // Sub claim'i, yani kullanıcı kimliği
                .claim("name", "John Doe") // Diğer kullanıcı bilgileri
                .build());
        
        // JWT'yi oluştur ve döndür
        return jwtEncoder.encode(parameters);
    }

    public static void main(String[] args) throws Exception {
        // Dinamik olarak RSA anahtar çifti oluştur
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // JWT'yi oluştur
        Jwt jwt = generateJwt(privateKey);

        // JWT'yi yazdır
        System.out.println("Generated JWT: " + jwt.getTokenValue());
    }*/
}
