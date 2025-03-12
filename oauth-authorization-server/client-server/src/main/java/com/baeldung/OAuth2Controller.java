package com.baeldung;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping
public class OAuth2Controller {
    private final OAuth2TokenService tokenService;

    public OAuth2Controller(OAuth2TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/oauth2/redirect-to-google")
    public ResponseEntity<?> redirectToGoogle() {
        String googleAuthUrl = "https://accounts.google.com/o/oauth2/auth" +
                "?client_id=sso-dashboard-client" +
                "&redirect_uri=http://localhost:8080/oauth2/callback" +// Callback URL
                "&response_type=code" +
                "&scope=openid%20email%20profile%20" +
                "&prompt=none"; // Kullanıcıdan tekrar login isteme

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleAuthUrl)).build();
    }

    @GetMapping("/login/oauth2/code/sso-dashboard-client")
    public ResponseEntity<?> callback(
            @RegisteredOAuth2AuthorizedClient("sso-dashboard") OAuth2AuthorizedClient authorizedClient,
            @RequestParam("code") String code, @RequestParam("state") String state) {
        // Google'dan ID Token al
        String idToken = tokenService.getIdToken(code);

        // Google ID Token'ı Workload Identity Pool'a çevir
        String googleToken = exchangeTokenForGoogle(idToken);

        // Google Cloud Console'a yönlendir
        String googleUrl = "https://console.cloud.google.com/?authuser=0&access_token=" + googleToken;

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleUrl)).build();
    }

    @GetMapping("/oauth2/callback")
    public ResponseEntity<?> googleCallback(@RequestParam("code") String code) {
        // Google'dan ID Token al
        String idToken = tokenService.getIdToken(code);

        // Google ID Token'ı Workload Identity Pool'a çevir
        String googleToken = exchangeTokenForGoogle(idToken);

        // Google Cloud Console'a yönlendir
        String googleUrl = "https://console.cloud.google.com/?authuser=0&access_token=" + googleToken;

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleUrl)).build();
    }


    /*@GetMapping("/oauth2/redirect-to-google")
    public ResponseEntity<?> redirectToGoogle(@RequestParam("code") String authorizationCode) {
        //String accessToken = tokenService.getAccessToken(authorizationCode);
        String idToken = tokenService.getIdToken(authorizationCode);

        String googleToken = exchangeTokenForGoogle(idToken); // Google Token'a çevir

        String googleUrl = "https://console.cloud.google.com/?authuser=0&access_token=" + googleToken;

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleUrl)).build();
    }*/

    @GetMapping("/oauth2/google-logout")
    public ResponseEntity<Void> googleLogoutRedirect() {
        String googleLogoutUrl = "https://accounts.google.com/logout" +
                "?continue=https://accounts.google.com/o/oauth2/auth" +
                "?client_id=sso-dashboard-client" +
                "&redirect_uri=" + "http://localhost:8080/login/oauth2/code/sso-dashboard-client" +
                "&response_type=code" +
                "&scope=email%20profile%20openid";

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(googleLogoutUrl))
                .build();
    }


    private String exchangeTokenForGoogle(String token) {
        RestTemplate restTemplate = new RestTemplate();

        Map<String, Object> request = Map.of(
                "audience", "//iam.googleapis.com/projects/1050151621152/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
                "grantType", "urn:ietf:params:oauth:grant-type:token-exchange",
                "requestedTokenType", "urn:ietf:params:oauth:token-type:access_token",
                "subjectTokenType", "urn:ietf:params:oauth:token-type:id_token",
                "subjectToken", token,
                "scope", "https://www.googleapis.com/auth/cloud-platform"
        );


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(request, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://sts.googleapis.com/v1/token",
                HttpMethod.POST,
                entity,
                Map.class
        );

        return response.getBody().get("access_token").toString();
    }



    /*@GetMapping("/oauth2/callback")
    public ResponseEntity<?> handleOAuth2Callback(@RequestParam("code") String authorizationCode) {
        String accessToken = tokenService.getAccessToken(authorizationCode);
        return ResponseEntity.ok(Map.of("access_token", accessToken));
    }*/
}
