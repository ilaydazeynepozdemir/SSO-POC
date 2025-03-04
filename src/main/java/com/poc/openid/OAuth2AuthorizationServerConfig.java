package com.poc.openid;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;


@Configuration
public class OAuth2AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId("client1")
                .clientId("my-client-id")
                .clientSecret("{noop}my-secret") // {noop} means no encoding, plaintext
                .scope("read")
                .scope("write")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }


    @Bean
    public HttpSecurity configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/oauth2/authorize", "/oauth2/token", "/oauth2/authorization").permitAll()
                .anyRequest().authenticated()
            .and()
                .formLogin().permitAll();
        return http;
    }


}
