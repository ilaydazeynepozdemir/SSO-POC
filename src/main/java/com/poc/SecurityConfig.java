package com.poc;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .saml2Login();
        
        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        // SSO Circle IdP metadata URL'sini kullanıyoruz
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
            .fromMetadataLocation("https://idp.ssocircle.com/sso/meta/idp.xml") // SSO Circle Metadata URL
            .registrationId("sso-circle-idp")
            .assertionConsumerServiceLocation("http://localhost:8080/saml/acs")  // SP'nin Assertion Consumer Service (ACS) URL'si
            .build();
        
        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }
}
