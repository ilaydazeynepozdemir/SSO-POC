package com.poc.openid.server;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class JwtConfig {
    
    
    // Bu private key'i bir .pem dosyasından ya da güvenli bir kaynaktan alabilirsiniz.
    @Bean
    public JwtEncoder jwtEncoder() throws Exception {
        // RS256 algoritması için bir key ayarlıyoruz
        KeyPair keyPair = RSAKeyPairGenerator.generateRSAKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();// Yani buraya sizin özel anahtarınız gelecek;
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();// Yani buraya sizin özel anahtarınız gelecek;

        // RSAPrivateKey'i JWK'ye dönüştür
        JWK jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        // JWKSource oluşturun
        JWKSource<SecurityContext> jwkSource = new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                List<JWK> res = new ArrayList<>();
                res.add(jwk);
                return res;
            }
        };

        // NimbusJwtEncoder, JWKSource ile çalışır
        return new NimbusJwtEncoder(jwkSource);
    }


    @Bean
    public JwtGenerator tokenGenerator() throws Exception {
        return new JwtGenerator(jwtEncoder());
    }
}
