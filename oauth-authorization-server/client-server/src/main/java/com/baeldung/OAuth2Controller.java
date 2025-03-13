package com.baeldung;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping
public class OAuth2Controller {
    private final OAuth2TokenService tokenService;

    public OAuth2Controller(OAuth2TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/oauth2/redirect-to-google")
    public ResponseEntity<?> redirectToGoogle(OAuth2AuthenticationToken authentication, @RequestParam("code") String code) {
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        String idToken = oidcUser.getIdToken().getTokenValue();
        /*try {
            idToken = tokenService.getIdToken(code);
        } catch (Exception e) {
            System.out.println(e);
            // Kullanıcı Google'dan çıkış yapmış, IDP'ye (localhost:8080/login) yönlendir.
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("http://localhost:8080/login"))
                    .build();
        }*/

        String googleAccessToken;
        String googleIdToken;
        try {
            googleAccessToken = exchangeTokenForGoogle(idToken);
            googleIdToken = generateGoogleIdToken(googleAccessToken);
        } catch (Exception e) {
            System.out.println(e);
            // Google’dan alınan token geçersizse, kullanıcıyı IDP’ye yönlendir
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("http://localhost:8080/login"))
                    .build();
        }

        try {
            String encodedIdToken = URLEncoder.encode(googleIdToken, StandardCharsets.UTF_8.toString());  // ✅ URL Encoding yap
            String clientId = "1050151621152-udj2p6nqfgbp3hj33nkeae1tsjetat2k.apps.googleusercontent.com";
            String nonce = "random_nonce_value" + UUID.randomUUID().toString(); // ✅ Her istekte değiştir
            String googleUrl = "https://accounts.google.com/o/oauth2/auth"
                    + "?client_id=" + clientId
                    + "&redirect_uri=https://console.cloud.google.com"
                    + "&response_type=id_token"
                    + "&scope=openid%20email%20profile"
                    + "&nonce=" + nonce
                    + "&id_token=" + encodedIdToken;  // ✅ ID Token’ı URL içine ekle

            return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(googleUrl)).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        // Google’a giriş yapmadan yönlendir
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

    private String generateGoogleIdToken(String accessToken) {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);  // ✅ Google’dan aldığın access_token’ı burada kullan

        Map<String, Object> request = Map.of(
                "audience", "https://console.cloud.google.com",  // ✅ Google Cloud Console erişimi için
                "includeEmail", true
        );

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(request, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/selfservice@selfservice-1729170560028.iam.gserviceaccount.com:generateIdToken",
                HttpMethod.POST,
                entity,
                Map.class
        );

        System.out.println("Google ID Token Response: " + response.getBody());

        return response.getBody().get("token").toString();
    }


    private String exchangeTokenForGoogleIdToken(String token) {
        RestTemplate restTemplate = new RestTemplate();

        Map<String, Object> request = Map.of(
                "audience", "//iam.googleapis.com/projects/1050151621152/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
                "grantType", "urn:ietf:params:oauth:grant-type:token-exchange",
                "requestedTokenType", "urn:ietf:params:oauth:token-type:id_token",  // ✅ ID Token istemelisin
                "subjectTokenType", "urn:ietf:params:oauth:token-type:jwt",
                "subjectToken", token
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

        Map<String, Object> responseBody = response.getBody();
        System.out.println("Google ID Token Response: " + responseBody);

        return responseBody.get("id_token").toString();
    }


    private String exchangeTokenForGoogle(String token) {
        RestTemplate restTemplate = new RestTemplate();

        Map<String, Object> request = Map.of(
                "audience", "//iam.googleapis.com/projects/1050151621152/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
                "aud", "//iam.googleapis.com/projects/1050151621152/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
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

    private String getIdTokenFromGoogle(String accessToken) {
        System.out.println("ACCESS TOKEN " + accessToken);
        RestTemplate restTemplate = new RestTemplate();

        String url = "https://oauth2.googleapis.com/tokeninfo?access_token=" + accessToken;

        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                Map.class
        );

        return response.getBody().get("id_token").toString();
    }




    @GetMapping("/callbackTest")
    public ResponseEntity<String> callback(@RequestParam Map<String, String> params) {
        return ResponseEntity.ok("Callback Params: " + params.toString());
    }
}
