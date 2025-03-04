package com.poc.openid.server;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
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
}
