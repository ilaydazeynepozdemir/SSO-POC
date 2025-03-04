package com.poc.openid.server;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .oauth2Login()
                .and()
                .oauth2Login(oauth2Login -> oauth2Login.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.baseUri(
                                "/oauth2/authorize")))
                .authorizeRequests()
                .antMatchers("/oauth2/authorize", "/oauth2/token").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll();
    }



    @Bean
    public OAuth2AuthorizationServerConfiguration authorizationServerConfiguration() {
        return new OAuth2AuthorizationServerConfiguration();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("client1")
                .clientId("my-client-id")
                .clientSecret("{noop}my-secret") // {noop} düz metin için
                .scope("openid")
                .scope("profile")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/my-client")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }


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
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        // JWT token'ına özel claimler eklemek için
        return (context) -> {
            context.getClaims().claim("custom-claim", "custom-value");
        };
    }

}
