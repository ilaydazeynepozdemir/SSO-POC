package com.baeldung;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/token").authenticated() // Token endpoint'ine yetkilendirme eklendi
                        .requestMatchers("/oauth2/redirect-to-google").permitAll()
                        .anyRequest().permitAll()
                )
                .oauth2Login(Customizer.withDefaults()) // OAuth2 login'i aktif et
                .oauth2Client(Customizer.withDefaults()); // OAuth2 Client'i aktif et

        return http.build();
    }

}
