package com.baeldung;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Configuration
@EnableRedisHttpSession
public class AuthServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        http.apply(authServerConfigurer);
        authServerConfigurer.oidc(Customizer.withDefaults());

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/oauth2/token", "/userinfo").authenticated() // Token ve UserInfo endpoint'i için authentication gerekli
                        .requestMatchers("/oauth2/authorize").authenticated()
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization ->
                                authorization.authorizationRequestRepository(new HttpSessionOAuth2AuthorizationRequestRepository())
                        )
                        .defaultSuccessUrl("http://localhost:8080/login/oauth2/code/sso-dashboard-client", true) // ** Yetkilendirme kodunu istemciye geri gönder**
                )
                .sessionManagement(session -> session
                        .sessionFixation().none()  // **Oturumun değiştirilmesini engelle**
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // **Session kullanımını zorunlu yap**
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt) // 🔥 Bearer Token doğrulama eklenmeli!
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("http://localhost:8080/login/oauth2/code/sso-dashboard-client", true) // ** Doğru yönlendirme**
                );

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(PasswordEncoder passwordEncoder) {
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("sso-dashboard-client")
                .clientId("sso-dashboard-client")
        .clientSecret(passwordEncoder.encode("secret"))
                //.clientSecret("{noop}secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/oauth2/login/oauth2/code/sso-dashboard-client")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .tokenUri("http://localhost:9000/oauth2/token")
                .userInfoUri("http://localhost:9000/userinfo")
                .jwkSetUri("http://localhost:9000/oauth2/jwks")
                .clientName("SSO Dashboard Client")
                .build();

        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // Önce kayıtlı client var mı kontrol et
        Optional<RegisteredClient> existingClient = Optional.ofNullable(
                registeredClientRepository.findByClientId("sso-dashboard-client")
        );

        if (existingClient.isEmpty()) { // Eğer yoksa kaydet
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("sso-dashboard-client")
                    .clientSecret(passwordEncoder.encode("secret"))
                    //.clientSecret("{noop}secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:8080/login/oauth2/code/sso-dashboard-client")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("email")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();

            registeredClientRepository.save(client); // Client’ı kaydet
        }

        return registeredClientRepository;
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = KeyPairGeneratorUtils.generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        return (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(rsaKey));
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                Authentication authentication = context.getPrincipal();
                context.getClaims().claim(IdTokenClaimNames.SUB, authentication.getName());
                context.getClaims().claim("email", authentication.getName());
                context.getClaims().claim("name", authentication.getName());
                context.getClaims().claim("email_verified", true); // Zorla email_verified = true
                List<String> audience = new ArrayList<>();
                audience.add("sso-dashboard-client");
                context.getClaims().audience(audience);
            }


        };
    }


    @Bean
    UserDetailsService users() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.builder()
                .username("ilaydazeynepozdemir@gmail.com")
                .password("admin")
                .passwordEncoder(encoder::encode)
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:8080", "http://localhost:9000")
                        .allowCredentials(true);
            }
        };
    }

}
