package com.baeldung;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
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
    public ResponseEntity<?> redirectToGoogle(@RequestParam("code") String code) {
        String idToken;
        try {
            idToken = tokenService.getIdToken(code);
        } catch (Exception e) {
            System.out.println(e);
            // Kullanıcı Google'dan çıkış yapmış, IDP'ye (localhost:8080/login) yönlendir.
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("http://localhost:8080/login"))
                    .build();
        }

        String googleToken;
        try {
            googleToken = exchangeTokenForGoogle(idToken);
        } catch (Exception e) {
            System.out.println(e);
            // Google’dan alınan token geçersizse, kullanıcıyı IDP’ye yönlendir
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("http://localhost:8080/login"))
                    .build();
        }

        // Google’a giriş yapmadan yönlendir
        String googleUrl = "https://console.cloud.google.com/?authuser=0&prompt=none&access_token=" + googleToken;

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleUrl)).build();
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
    public ResponseEntity<?> googleCallback( @RegisteredOAuth2AuthorizedClient("sso-dashboard") OAuth2AuthorizedClient authorizedClient , @RequestParam("code") String code) {
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



    @GetMapping("/callbackTest")
    public ResponseEntity<String> callback(@RequestParam Map<String, String> params) {
        return ResponseEntity.ok("Callback Params: " + params.toString());
    }
}
